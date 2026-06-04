"""Subdomain discovery via Certificate Transparency + passive DNS + always-on bruteforce.

Direct sources queried concurrently for a fast first response:
  1. crt.sh          - Sectigo CT log aggregator, largest free dataset
  2. certspotter     - SSLMate CT mirror, complementary coverage
  3. hackertarget    - passive DNS hostsearch (rate-limited free tier, 50/day per IP)
  4. rapiddns        - free keyless passive DNS (replaced network-blocked OTX)
  5. VirusTotal v3   - subdomains endpoint (500/day free per API key)
  6. DNS bruteforce  - 773-word curated wordlist, ALWAYS runs (no third-party limit)

Plus an optional subfinder background-enrichment pass aggregating 25+ more passive
sources for comprehensive coverage (no-ops cleanly if the binary is absent).

VT (and a dormant OTX source) only fire when their keys are configured via env
vars VT_API_KEY / OTX_API_KEY; otherwise they no-op cleanly.

Bruteforce now ALWAYS runs alongside the other sources (not just on full CT
failure). Reasons:
  - Catches resolvable subs that aren't in CT logs (private infra, recent adds)
  - Pure DNS resolution from the VPS = zero third-party rate limit
  - Backstop when CT sources are partially or fully rate-limited

Warnings logic: only surface warnings when coverage is genuinely low
(default: fewer than 20 subdomains total found). Otherwise the warnings
field is suppressed even if individual sources failed — because partial
failure with strong coverage isn't useful information to the API consumer.

Response shape (backward-compatible):
  count, returned, subdomains   <- unchanged
  sources_used                  <- list of source result strings (always present)
  warnings                      <- only present when total coverage is low
"""
import asyncio
import logging
import os
import re
from typing import Optional

import httpx

log = logging.getLogger("domain-intel.subdomains")

# Per-source timeouts.
#
# These are httpx.Timeout objects with a SHORT connect timeout and a generous
# read timeout, on purpose. The split matters a lot here:
#   - A host that's unreachable/blocked from this VPS (OTX has been returning
#     connection-level failures, crt.sh goes fully down for stretches) fails on
#     *connect*. With a single float timeout, connect == read, so a dead host
#     burned the whole window (6-7s) and — because we asyncio.gather all sources
#     and wait for the slowest — that dead host gated EVERY cold response.
#   - A host that's alive but slow (crt.sh routinely takes 8-15s under load) only
#     needs a generous *read* budget; its connect succeeds quickly.
# So: connect fails fast (CONNECT_TIMEOUT), read stays patient per-source.
CONNECT_TIMEOUT = 2.5

def _timeout(read: float) -> httpx.Timeout:
    return httpx.Timeout(read, connect=CONNECT_TIMEOUT, write=read, pool=read)

CRT_TIMEOUT          = _timeout(9.0)   # richest source but slowest when alive — kept long so background enrich can capture it
CERTSPOTTER_TIMEOUT  = _timeout(6.0)
HACKERTARGET_TIMEOUT = _timeout(4.0)
OTX_TIMEOUT          = _timeout(2.5)   # reliably unreachable from this VPS right now; fail fast so it doesn't drag
VT_TIMEOUT           = _timeout(6.0)
RAPIDDNS_TIMEOUT     = _timeout(7.0)   # free keyless passive-DNS (HTML); reliable from this VPS, replaces dead OTX

# subfinder: external MIT binary that aggregates 20+ passive sources with proper
# CT-log handling. Slow (~15-60s) so it ALWAYS lands in the background-enrich path —
# the cold response stays fast on our direct sources, and the cached/second lookup
# becomes comprehensive (matches/beats subfinder-alone since we MERGE).
SUBFINDER_BIN       = os.environ.get("SUBFINDER_BIN", "/usr/local/bin/subfinder")
SUBFINDER_MAXTIME   = os.environ.get("SUBFINDER_MAXTIME", "1")   # minutes (subfinder -max-time)
SUBFINDER_SRC_TO    = os.environ.get("SUBFINDER_SRC_TIMEOUT", "15")  # per-source seconds
SUBFINDER_HARD_KILL = 90        # asyncio safety kill (s)
SUBFINDER_PARSE_CAP = 20000     # bound memory on huge domains (github returns 41k+)
DNS_BRUTE_TIMEOUT    = 1.0   # per name; NXDOMAIN comes back fast
DNS_BRUTE_CONCURRENCY = 100  # proven value; raising it under event-loop contention is counterproductive

# dns-brute is the always-on coverage FLOOR (local resolution, no third-party
# limit) — it must always make the snapshot, not get deferred to background
# like the flaky HTTP upstreams. If it's still running at SOFT_DEADLINE (can
# happen under concurrent load), we give it this much extra grace to land in
# the first-lookup response rather than the cache-only enrichment.
BRUTE_FLOOR_GRACE = 2.5

# Above this soft deadline, the reliable fast sources (certspotter ~0.6s, VT
# ~0.6s, DNS bruteforce ~1.3s) have all returned; we stop blocking the caller
# and let any slow straggler (crt.sh, which hangs 8-15s when degraded) finish
# in the background, writing its fuller result into the cache so the NEXT
# lookup of this domain is complete. "First lookup good, second lookup perfect"
# — the standard way to hide upstream flakiness. 3.0s leaves comfortable
# headroom over the slowest reliable source (dns-brute ~1.3s).
SOFT_DEADLINE = 3.0

# Synchronous "complete" mode (the API ?wait=1 flag). Block up to this long for the
# slow sources (crt.sh, subfinder) to finish, returning a fuller result in one call
# instead of the fast snapshot. Anything still pending after this still enriches in
# the background. Opt-in only — the default path stays fast.
WAIT_DEADLINE = float(os.environ.get("SUBDOMAINS_WAIT_DEADLINE", "20.0"))

# Warnings only appear when coverage is below this count
LOW_COVERAGE_THRESHOLD = 20

# --- Output quality: liveness tiering + shared-infra pool collapse ---
# Liveness pass (runs in the background): resolve discovered hosts NOW and split
# them into "live" (resolving) vs "historical" (seen in CT/passive, maybe dead).
LIVENESS_BUDGET      = int(os.environ.get("SUBDOMAINS_LIVENESS_BUDGET", "5000"))  # max hosts resolved per lookup
LIVENESS_CONCURRENCY = 150
LIVE_CAP             = int(os.environ.get("SUBDOMAINS_LIVE_CAP", "2000"))          # max live hosts returned
# Collapse high-cardinality shared-infrastructure pools (e.g. *.ns.cloudflare.com).
POOL_MIN  = 40   # a deep sub-zone with >= this many descendants is treated as a pool
POOL_KEEP = 3    # keep this many representative members visible

OTX_KEY = os.environ.get("OTX_API_KEY", "").strip()
VT_KEY  = os.environ.get("VT_API_KEY", "").strip()


# ~500 curated common subdomains — covers the patterns most real infra uses.
# Order roughly by frequency: web/mail first, then admin/api/dev tooling,
# then provider/cloud-specific, then long-tail. Bruteforce stops at NXDOMAIN
# so unused entries cost ~one async timeout each, capped by concurrency.
_BRUTE_WORDLIST = [
    # Core web
    "www", "www2", "www3", "web", "web1", "web2", "m", "mobile", "app", "apps",
    "static", "assets", "cdn", "cdn1", "cdn2", "media", "img", "images", "files",
    "downloads", "download", "dl", "uploads", "upload", "video", "videos", "stream",
    # Mail / messaging
    "mail", "mail2", "smtp", "smtp1", "smtp2", "pop", "pop3", "imap", "imap2",
    "webmail", "email", "exchange", "owa", "mx", "mx1", "mx2", "mx3", "relay",
    "autodiscover", "autoconfig", "mta", "mta1", "mta2", "outbound", "inbound",
    "spam", "antispam", "newsletter", "marketing", "campaign", "campaigns",
    # DNS / infrastructure
    "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "dns", "dns1", "dns2", "dns3",
    "resolver", "nameserver", "whois", "rdap",
    # Admin / management
    "admin", "administrator", "adm", "manage", "manager", "console", "control",
    "panel", "cp", "cpanel", "whm", "plesk", "directadmin", "webadmin", "siteadmin",
    "dashboard", "control-panel", "controlpanel", "backend", "backoffice", "intranet",
    # API / dev
    "api", "api1", "api2", "api3", "apiv1", "apiv2", "api-v1", "api-v2",
    "rest", "graphql", "gql", "ws", "wss", "websocket", "rpc", "grpc",
    "developer", "developers", "dev", "dev1", "dev2", "developer-api", "api-dev",
    "sandbox", "sandbox1", "playground", "demo", "demo1", "demo2", "trial",
    "test", "test1", "test2", "test3", "testing", "qa", "uat", "staging",
    "stage", "stg", "preprod", "pre-prod", "preview", "beta", "alpha", "experimental",
    # Auth / identity
    "auth", "oauth", "sso", "login", "logout", "signin", "signout", "signup",
    "register", "account", "accounts", "id", "identity", "idp", "saml", "openid",
    "passport", "credentials", "verify", "verification", "2fa", "mfa", "otp",
    # User / profile
    "user", "users", "profile", "profiles", "my", "me", "home", "settings",
    "preferences", "notifications", "messages", "inbox",
    # Commerce / billing
    "shop", "store", "buy", "checkout", "cart", "order", "orders", "pay",
    "payment", "payments", "billing", "invoice", "invoices", "subscriptions",
    "subscribe", "pricing", "plans", "upgrade", "wallet", "balance",
    # Support / help
    "support", "help", "helpdesk", "service", "services", "contact", "feedback",
    "docs", "doc", "documentation", "wiki", "knowledgebase", "kb", "faq",
    "tickets", "ticket", "status", "statuspage", "uptime", "health",
    # Content / pages
    "blog", "blogs", "news", "press", "media", "events", "community", "forum",
    "forums", "board", "discussion", "discussions", "answers", "questions",
    "search", "find", "directory", "listing", "listings", "explore", "discover",
    # File / data
    "data", "stats", "statistics", "analytics", "metrics", "reports", "report",
    "logs", "log", "monitor", "monitoring", "graph", "graphs", "chart", "charts",
    "ftp", "sftp", "ftps", "tftp", "rsync", "nfs", "smb", "samba",
    "git", "gitlab", "gitea", "gogs", "svn", "cvs", "hg", "bzr",
    "repo", "repos", "registry", "docker-registry", "container-registry",
    "artifacts", "artifact", "nexus", "jfrog", "harbor", "quay",
    # CI/CD
    "ci", "cicd", "build", "builds", "jenkins", "drone", "concourse", "travis",
    "circle", "circleci", "actions", "pipeline", "pipelines", "deploy", "deployment",
    "release", "releases", "publish",
    # Monitoring / observability
    "grafana", "prometheus", "alert", "alerts", "alertmanager", "kibana", "elastic",
    "elasticsearch", "logstash", "splunk", "datadog", "newrelic", "sentry",
    "rollbar", "bugsnag", "honeybadger", "pagerduty", "statuspage",
    # Database
    "db", "db1", "db2", "database", "databases", "mysql", "postgres", "postgresql",
    "mongo", "mongodb", "redis", "memcached", "cassandra", "couchdb", "elastic",
    "rds", "warehouse", "datalake", "datawarehouse", "olap", "oltp",
    # Cloud / infra
    "aws", "azure", "gcp", "cloud", "k8s", "kubernetes", "kube", "helm",
    "rancher", "openshift", "eks", "gke", "aks", "ecs", "fargate",
    "vm", "vm1", "vm2", "node", "node1", "node2", "node3", "host", "host1",
    "server", "server1", "server2", "srv", "srv1", "srv2",
    "lb", "loadbalancer", "load-balancer", "haproxy", "nginx", "traefik", "envoy",
    "proxy", "reverse-proxy", "fwd", "forward", "gateway", "gw", "edge",
    "router", "switch", "firewall", "vpn", "openvpn", "wireguard", "ipsec",
    "vpn1", "vpn2", "remote", "rdp", "ssh", "ssh1", "ssh2", "bastion", "jump",
    "jumpbox", "jumphost", "tunnel", "ngrok",
    # Geographic / regional
    "us", "us-east", "us-west", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu", "eu-west", "eu-west-1", "eu-central", "eu-central-1", "eu-north",
    "ap", "ap-south", "ap-southeast", "ap-northeast", "asia", "asia-pacific",
    "uk", "us-prod", "uk-prod", "eu-prod", "americas", "emea", "apac",
    "east", "west", "north", "south", "central", "global",
    # Environment
    "prod", "production", "live", "main", "master",
    "internal", "intranet", "private", "secure", "vault", "secret", "secrets",
    "corp", "corporate", "office", "hq", "headquarters", "lan", "wan",
    # CMS / web stacks
    "wp", "wordpress", "drupal", "joomla", "ghost", "magento", "shopify",
    "blog", "cms", "site", "sites", "publish", "publisher", "editor",
    # Specific common services
    "jira", "confluence", "bitbucket", "trello", "asana", "monday", "linear",
    "slack", "teams", "discord", "zoom", "meet", "calendar", "schedule",
    "hubspot", "salesforce", "sf", "marketo", "intercom", "drift", "zendesk",
    "freshdesk", "helpscout", "kayako", "olark", "tawk", "crisp",
    "okta", "auth0", "onelogin", "duo", "lastpass", "1password", "bitwarden",
    "looker", "tableau", "powerbi", "metabase", "redash", "superset", "mode",
    "segment", "amplitude", "mixpanel", "heap", "fullstory", "logrocket",
    "stripe", "paypal", "square", "braintree", "razorpay", "paddle", "chargebee",
    "twilio", "sendgrid", "mailgun", "mandrill", "postmark", "ses", "mailchimp",
    "klaviyo", "convertkit", "activecampaign", "drip", "constant-contact",
    # SaaS subdomain patterns (tenant-style won't match but flagship subs will)
    "secure", "secure1", "secure2", "ssl", "tls", "encrypted", "private",
    "client", "clients", "partner", "partners", "vendor", "vendors", "supplier",
    "enterprise", "business", "team", "teams", "workspace", "workspaces",
    "tenant", "tenants", "org", "orgs", "organization", "organizations",
    "company", "companies", "site", "sites", "portal", "portals",
    # Static / asset CDN patterns
    "s1", "s2", "s3", "s4", "s5", "static1", "static2", "static3",
    "i1", "i2", "i3", "img1", "img2", "img3", "image1", "image2",
    "a1", "a2", "a3", "asset1", "asset2", "asset3", "assets1", "assets2",
    "media1", "media2", "video1", "video2", "stream1", "stream2",
    "fonts", "font", "css", "js", "javascript", "scripts", "lib", "libs", "vendor",
    # Misc / legacy
    "old", "new", "legacy", "deprecated", "v1", "v2", "v3", "v4", "v5",
    "alpha", "beta", "gamma", "rc", "rc1", "rc2", "snapshot", "nightly",
    "tmp", "temp", "temporary", "draft", "drafts", "wip", "todo",
    "backup", "backups", "bak", "archive", "archives", "history",
    "internal-tools", "tools", "tooling", "utility", "utilities", "util", "utils",
    "labs", "lab", "research", "rnd", "r-and-d", "innovation",
    "go", "redirect", "redir", "link", "links", "short", "shortlink",
    # Education / community
    "learn", "learning", "education", "edu", "school", "academy", "training",
    "courses", "course", "tutorial", "tutorials", "lessons", "guide", "guides",
    # Other commonly-found
    "www-staging", "www-dev", "www-test", "www-uat", "www-qa",
    "auth-dev", "auth-staging", "auth-prod",
    "api-dev", "api-staging", "api-prod", "api-internal", "api-public",
    "internal-api", "private-api", "public-api",
    "app-dev", "app-staging", "app-prod",
    "static-cdn", "static-assets", "static-files",
    # Cloud-native / modern infra (added 2026-05-31)
    "argo", "argocd", "flux", "istio", "consul", "nomad", "vault-prod",
    "terraform", "atlantis", "spinnaker", "tekton", "keycloak", "authentik",
    "minio", "ceph", "longhorn", "rook", "velero", "thanos", "loki", "tempo",
    "victoriametrics", "cortex", "mimir", "opentelemetry", "otel", "jaeger", "zipkin",
    "vector", "fluentd", "fluentbit", "telegraf", "influx", "influxdb", "timescale",
    "clickhouse", "trino", "presto", "spark", "flink", "airflow", "dagster", "prefect",
    "dbt", "kafka", "pulsar", "rabbitmq", "nats", "temporal", "celery",
    "feature", "features", "flags", "flagsmith", "unleash", "launchdarkly",
    "webhook", "webhooks", "callback", "callbacks", "events", "eventbus", "queue",
    "cdn-edge", "edge1", "edge2", "origin", "origin1", "origin2", "ingress", "egress",
    # AI / ML era (added 2026-05-31)
    "ml", "ai", "mlflow", "kubeflow", "triton", "inference", "models", "model",
    "embeddings", "vector-db", "rag", "llm", "gpu", "notebook", "notebooks", "jupyter",
]


# A syntactically valid hostname: dot-separated labels of [a-z0-9-], no leading or
# trailing hyphen per label. Drops passive-DNS junk — underscore service records
# (_dmarc.*, *._domainkey.*), poisoned/garbage entries — that aren't real web hosts.
_VALID_HOST_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
# Labels that mark email-authentication DNS records (not web hosts).
_EMAIL_AUTH_LABELS = {"dkim", "domainkey", "dmarc"}


def _add(out: set, candidate: str, domain: str) -> None:
    """Validate and add a candidate hostname to the result set."""
    if not candidate:
        return
    n = candidate.strip().lower().rstrip(".")
    if not n or n.startswith("*"):
        return
    if n != domain and not n.endswith("." + domain):
        return
    if not _VALID_HOST_RE.match(n):
        return
    # Drop email-authentication DNS records (DKIM/DMARC key hosts) — not web hosts;
    # the dedicated email-security endpoint surfaces those instead.
    if _EMAIL_AUTH_LABELS.intersection(n.split(".")):
        return
    out.add(n)


async def _src_crtsh(client: httpx.AsyncClient, domain: str, out: set) -> str:
    """Query crt.sh certificate transparency log."""
    try:
        r = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=CRT_TIMEOUT,
            headers={"User-Agent": "domain-intel/0.3"},
        )
        if r.status_code != 200:
            return f"crt.sh status {r.status_code}"
        try:
            entries = r.json()
        except Exception:
            return "crt.sh non-json response"
        if not isinstance(entries, list):
            return "crt.sh unexpected shape"
        before = len(out)
        for e in entries:
            name = e.get("name_value") or ""
            for n in name.splitlines():
                _add(out, n, domain)
            _add(out, e.get("common_name") or "", domain)
        return f"crt.sh ok +{len(out) - before}"
    except Exception as exc:
        return f"crt.sh {type(exc).__name__}: {exc}"


async def _src_certspotter(client: httpx.AsyncClient, domain: str, out: set) -> str:
    """Query certspotter (SSLMate) CT mirror - no auth required for basic use."""
    try:
        r = await client.get(
            "https://api.certspotter.com/v1/issuances",
            params={
                "domain": domain,
                "include_subdomains": "true",
                "expand": "dns_names",
            },
            timeout=CERTSPOTTER_TIMEOUT,
            headers={"User-Agent": "domain-intel/0.3"},
        )
        if r.status_code == 429:
            return "certspotter rate-limited"
        if r.status_code != 200:
            return f"certspotter status {r.status_code}"
        try:
            entries = r.json()
        except Exception:
            return "certspotter non-json"
        if not isinstance(entries, list):
            return "certspotter unexpected shape"
        before = len(out)
        for e in entries:
            for n in (e.get("dns_names") or []):
                _add(out, n, domain)
        return f"certspotter ok +{len(out) - before}"
    except Exception as exc:
        return f"certspotter {type(exc).__name__}: {exc}"


async def _src_hackertarget(client: httpx.AsyncClient, domain: str, out: set) -> str:
    """Query hackertarget hostsearch (passive DNS, free tier — 50/day/IP)."""
    try:
        r = await client.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain},
            timeout=HACKERTARGET_TIMEOUT,
            headers={"User-Agent": "domain-intel/0.3"},
        )
        if r.status_code != 200:
            return f"hackertarget status {r.status_code}"
        text = r.text or ""
        low = text.lower()
        if "error" in low or "api count" in low or "upgrade" in low:
            return f"hackertarget limited: {text[:80]}"
        before = len(out)
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip()
            _add(out, host, domain)
        return f"hackertarget ok +{len(out) - before}"
    except Exception as exc:
        return f"hackertarget {type(exc).__name__}: {exc}"


async def _src_otx(client: httpx.AsyncClient, domain: str, out: set) -> str:
    """Query AlienVault OTX passive DNS. Requires OTX_API_KEY env var."""
    if not OTX_KEY:
        return "otx skipped: no OTX_API_KEY"
    try:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=OTX_TIMEOUT,
            headers={"X-OTX-API-KEY": OTX_KEY, "User-Agent": "domain-intel/0.3"},
        )
        if r.status_code == 429:
            return "otx rate-limited"
        if r.status_code != 200:
            return f"otx status {r.status_code}"
        try:
            data = r.json()
        except Exception:
            return "otx non-json"
        records = data.get("passive_dns") or []
        if not isinstance(records, list):
            return "otx unexpected shape"
        before = len(out)
        for rec in records:
            _add(out, rec.get("hostname") or "", domain)
        return f"otx ok +{len(out) - before}"
    except Exception as exc:
        return f"otx {type(exc).__name__}: {exc}"


async def _src_virustotal(client: httpx.AsyncClient, domain: str, out: set) -> str:
    """Query VirusTotal v3 subdomains endpoint, paginating up to 3 pages (≤120
    results) via the meta.cursor. Free tier is 4 req/min / 500/day, so 3 pages
    per lookup is well within budget at our traffic. Requires VT_API_KEY."""
    if not VT_KEY:
        return "virustotal skipped: no VT_API_KEY"
    before = len(out)
    try:
        cursor = None
        for page in range(3):
            params = {"limit": "40"}
            if cursor:
                params["cursor"] = cursor
            r = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                params=params, timeout=VT_TIMEOUT,
                headers={"x-apikey": VT_KEY, "User-Agent": "domain-intel/0.4"},
            )
            if r.status_code != 200:
                # first page failed = real failure; later page = keep what we got
                if page == 0:
                    return "virustotal rate-limited" if r.status_code == 429 else f"virustotal status {r.status_code}"
                break
            data = r.json()
            for it in (data.get("data") or []):
                _add(out, it.get("id") or "", domain)
            cursor = (data.get("meta") or {}).get("cursor")
            if not cursor:
                break
        return f"virustotal ok +{len(out) - before}"
    except Exception as exc:
        if len(out) > before:
            return f"virustotal ok +{len(out) - before}"
        return f"virustotal {type(exc).__name__}: {exc}"


async def _src_rapiddns(client: httpx.AsyncClient, domain: str, out: set) -> str:
    """Query rapiddns.io — free, keyless passive-DNS (HTML table). Reliable from
    this VPS; added 2026-06-01 to replace AlienVault OTX (which is network-blocked
    from the Hetzner IP range and contributed nothing)."""
    try:
        r = await client.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1",
            timeout=RAPIDDNS_TIMEOUT,
            headers={"User-Agent": "Mozilla/5.0 (compatible; domain-intel/0.4; +https://oti-labs.com)"},
        )
        if r.status_code == 429:
            return "rapiddns rate-limited"
        if r.status_code != 200:
            return f"rapiddns status {r.status_code}"
        before = len(out)
        for m in re.findall(rf"([a-zA-Z0-9_\-.]+\.{re.escape(domain)})\b", r.text):
            _add(out, m, domain)
        return f"rapiddns ok +{len(out) - before}"
    except Exception as exc:
        return f"rapiddns {type(exc).__name__}: {exc}"


async def _src_subfinder(domain: str, out: set) -> str:
    """Run subfinder (external binary) as a comprehensive passive aggregator.
    Subprocess, bounded by -max-time + an asyncio hard-kill. Slow by design — it
    lands in the background-enrich path, making the cached/second lookup complete."""
    if not os.path.exists(SUBFINDER_BIN):
        return "subfinder skipped: not installed"
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            SUBFINDER_BIN, "-d", domain, "-silent", "-duc",
            "-timeout", SUBFINDER_SRC_TO, "-max-time", SUBFINDER_MAXTIME,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=SUBFINDER_HARD_KILL)
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return "subfinder timeout"
        before = len(out)
        added = 0
        for line in stdout.decode(errors="ignore").splitlines():
            name = line.strip().lower()
            if not name:
                continue
            _add(out, name, domain)
            added += 1
            if added >= SUBFINDER_PARSE_CAP:
                break
        return f"subfinder ok +{len(out) - before}"
    except Exception as exc:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        return f"subfinder {type(exc).__name__}: {exc}"


async def _resolve_one(resolver, name: str) -> Optional[str]:
    """Resolve a single hostname; return name on success, None on NXDOMAIN/timeout.

    Queries A then CNAME only — an A query already follows CNAME chains, so this
    pair catches essentially every resolvable subdomain (A-backed hosts AND
    CNAME-to-SaaS records). AAAA is dropped: hosts with ONLY an AAAA record and
    no A or CNAME are vanishingly rare, and dropping it cuts per-name DNS work
    ~33% on the dominant NXDOMAIN case, keeping the always-on floor fast under
    concurrent load."""
    for rtype in ("A", "CNAME"):
        try:
            await resolver.resolve(name, rtype)
            return name
        except Exception:
            continue
    return None


def _make_resolver():
    """A dnspython async resolver spread across 8 anycast public resolvers (the same
    pool the bruteforce uses) so sustained concurrency doesn't get throttled."""
    import dns.asyncresolver
    r = dns.asyncresolver.Resolver()
    r.nameservers = [
        "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
        "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    ]
    r.rotate = True
    r.timeout = DNS_BRUTE_TIMEOUT
    r.lifetime = DNS_BRUTE_TIMEOUT
    return r


async def _resolve_with_ip(resolver, name: str):
    """Return (name, ip) if the host resolves right now, else None. ip is the first
    A address, or the CNAME target for A-less CNAME hosts."""
    try:
        ans = await resolver.resolve(name, "A")
        ips = sorted(str(a) for a in ans)
        if ips:
            return (name, ips[0])
    except Exception:
        pass
    try:
        ans = await resolver.resolve(name, "CNAME")
        if len(ans):
            return (name, str(ans[0].target).rstrip("."))
    except Exception:
        pass
    return None


async def _compute_liveness(domain: str, hosts) -> dict:
    """Resolve up to LIVENESS_BUDGET discovered hosts NOW; return {host: ip} for the
    ones that are genuinely live. Wildcard-aware: if the zone has a catch-all
    wildcard (so every name "resolves"), hits pointing at the wildcard IP are NOT
    counted as distinct live hosts — only names resolving to a different address
    are. This is exactly what separates "live now" from "seen historically"."""
    try:
        import dns.asyncresolver  # noqa: F401
    except ImportError:
        return {}
    import secrets
    resolver = _make_resolver()
    probes = [f"{secrets.token_hex(10)}-livecheck.{domain}" for _ in range(2)]
    probe_res = await asyncio.gather(
        *[_resolve_with_ip(resolver, p) for p in probes], return_exceptions=True
    )
    wildcard_ips = {r[1] for r in probe_res if isinstance(r, tuple) and r[1]}
    targets = sorted(hosts)[:LIVENESS_BUDGET]
    sem = asyncio.Semaphore(LIVENESS_CONCURRENCY)

    async def check(h):
        async with sem:
            return await _resolve_with_ip(resolver, h)

    results = await asyncio.gather(*[check(h) for h in targets], return_exceptions=True)
    live: dict = {}
    for r in results:
        if isinstance(r, tuple) and r[1] and r[1] not in wildcard_ips:
            live[r[0]] = r[1]
    return live


def _collapse_pools(domain: str, hosts) -> tuple:
    """Collapse high-cardinality shared-infrastructure SUBTREES so the list isn't
    front-loaded with infrastructure noise — e.g. Cloudflare's branded nameserver
    namespace (aaron.ns.cloudflare.com AND x.kristina.ns.cloudflare.com, …). For any
    sub-zone deeper than the domain with >= POOL_MIN descendants, the WHOLE subtree
    collapses to a summary + a few representatives. Direct subdomains of the domain
    are never collapsed. Returns (kept_hosts: list, pools: list[{zone,count}])."""
    from collections import Counter
    hosts = list(hosts)
    dlabels = domain.count(".") + 1   # label count of the registered domain
    # Tally descendants for every candidate pool-zone (ancestor zones deeper than the domain).
    zone_count: Counter = Counter()
    for h in hosts:
        labels = h.split(".")
        for i in range(1, len(labels) - dlabels):
            zone_count[".".join(labels[i:])] += 1
    # Choose pool roots shallowest-first, skipping zones already inside a chosen root,
    # so a whole namespace (ns.cloudflare.com) collapses once at the top.
    chosen: list = []
    for zone, cnt in sorted(zone_count.items(), key=lambda kv: (kv[0].count("."), kv[0])):
        if cnt < POOL_MIN:
            continue
        if any(zone == r or zone.endswith("." + r) for r in chosen):
            continue
        chosen.append(zone)
    if not chosen:
        return hosts, []
    drop = set()
    pools = []
    for root in chosen:
        children = sorted(h for h in hosts if h.endswith("." + root))
        if len(children) < POOL_MIN:
            continue
        reps = set(children[:POOL_KEEP])
        drop.update(c for c in children if c not in reps)
        pools.append({"zone": "*." + root, "count": len(children)})
    kept = [h for h in hosts if h not in drop]
    pools.sort(key=lambda p: -p["count"])
    return kept, pools


async def _src_dns_bruteforce(domain: str, out: set) -> str:
    """Always-on DNS bruteforce against curated wordlist via public resolvers."""
    try:
        import dns.asyncresolver
    except ImportError:
        return "dns-brute skipped: dnspython not installed"

    resolver = dns.asyncresolver.Resolver()
    # Spread load across a wide pool of public resolvers. Single resolvers throttle
    # under sustained concurrency; with 6 anycast providers, dnspython round-robins
    # so each sees ~1/6 the query rate — keeps the always-on floor reliable even
    # when one provider rate-limits this VPS's IP.
    resolver.nameservers = [
        "1.1.1.1", "1.0.0.1",            # Cloudflare
        "8.8.8.8", "8.8.4.4",            # Google
        "9.9.9.9", "149.112.112.112",    # Quad9
        "208.67.222.222", "208.67.220.220",  # OpenDNS
    ]
    resolver.rotate = True
    resolver.timeout = DNS_BRUTE_TIMEOUT
    resolver.lifetime = DNS_BRUTE_TIMEOUT

    # Wildcard detection. If a zone has a wildcard record (*.domain), every name
    # we try "resolves", so a wordlist brute would return the entire list as
    # false positives (e.g. reddit.com / shopify.com wildcard to ~750 fake subs).
    # Probe a few random labels that cannot legitimately exist; if they resolve,
    # the zone is a wildcard and brute-force can't distinguish real from fake —
    # so we skip it and rely on the CT/passive sources, which return only REAL
    # certificate/DNS-observed subdomains. Honest data > inflated counts.
    import secrets
    probes = [f"{secrets.token_hex(10)}-wildcardprobe.{domain}" for _ in range(3)]
    probe_hits = await asyncio.gather(
        *[_resolve_one(resolver, p) for p in probes], return_exceptions=True
    )
    if any(isinstance(h, str) and h for h in probe_hits):
        return "dns-brute skipped: wildcard DNS detected (CT/passive sources still apply)"

    names = [f"{word}.{domain}" for word in _BRUTE_WORDLIST]
    sem = asyncio.Semaphore(DNS_BRUTE_CONCURRENCY)

    async def guarded(name):
        async with sem:
            return await _resolve_one(resolver, name)

    results = await asyncio.gather(*[guarded(n) for n in names], return_exceptions=True)
    before = len(out)
    for r in results:
        if isinstance(r, str):
            _add(out, r, domain)
    return f"dns-brute ok +{len(out) - before} (wordlist {len(names)})"


def _clean_source(entry: str) -> str:
    """Normalize a raw per-source status into a clean, uniform label with no
    upstream marketing/error text. Powers the public `sources_used` field and the
    UI source chips. Examples:
        'rapiddns ok +35'                                  -> 'rapiddns: 35 found'
        'crt.sh pending (enriching in background)'         -> 'crt.sh: enriching'
        'hackertarget limited: API count exceeded - ...'   -> 'hackertarget: rate-limited'
        'subfinder skipped: not installed'                 -> 'subfinder: skipped'
        'otx ReadTimeout: ...' / 'crt.sh status 502'       -> 'otx: unavailable'
    """
    parts = str(entry).split(None, 1)
    name = parts[0] if parts else "?"
    rest = (parts[1] if len(parts) > 1 else "").lower()
    m = re.search(r"\+(\d+)", str(entry))
    if rest.startswith("ok"):
        return f"{name}: {m.group(1) if m else '0'} found"
    if "pending" in rest or "enrich" in rest:
        return f"{name}: enriching"
    if "rate" in rest or "limited" in rest or "count exceeded" in rest or " 429" in rest:
        return f"{name}: rate-limited"
    if "skip" in rest or "not installed" in rest or ("no " in rest and "key" in rest):
        return f"{name}: skipped"
    return f"{name}: unavailable"


def sources_enriching(sources_used) -> bool:
    """True if any source in a cleaned `sources_used` list is still enriching."""
    return any("enriching" in str(s) for s in (sources_used or []))


def _assemble(domain: str, found: set, results_by_name: dict,
              pending_names: list, limit: int,
              live_map: Optional[dict] = None, liveness_pending: bool = False) -> dict:
    """Build the response dict from whatever sources have reported so far.

    results_by_name maps source-name -> result string OR Exception (completed).
    pending_names lists sources still running (marked accordingly).
    live_map (optional): host -> resolved IP for hosts confirmed live NOW; when
    present the output is tiered into `live` vs historical. liveness_pending marks
    that the background liveness pass hasn't run yet (keeps consumers polling).
    """
    sources_used: list = []
    failed_msgs: list = []
    for name, res in results_by_name.items():
        if isinstance(res, Exception):
            clean = _clean_source(f"{name} {type(res).__name__}: {res}")
            sources_used.append(clean)
            failed_msgs.append(clean)
        else:
            sources_used.append(_clean_source(res))
            # Source reported failure if "ok" and "skipped" both absent
            if "ok" not in res and "skipped" not in res:
                failed_msgs.append(_clean_source(res))
    for name in pending_names:
        sources_used.append(_clean_source(f"{name} pending"))
    if liveness_pending:
        sources_used.append("liveness: enriching")

    # Hard error only when nothing found, nothing still running, and ~all failed.
    if not found and not pending_names and len(failed_msgs) >= 5:
        return {
            "error": "all subdomain sources failed",
            "domain": domain,
            "sources_used": sources_used,
            "subdomains": [],
            "count": 0,
            "returned": 0,
        }

    # Drop shared-infrastructure pool noise (e.g. *.ns.cloudflare.com).
    clean_hosts, pools = _collapse_pools(domain, found)
    total = len(clean_hosts)

    # Tier into live (resolves now) vs historical when liveness is available, and
    # order live-first so the capped/visible portion leads with the useful hosts.
    if live_map is not None:
        live_hosts = sorted(h for h in clean_hosts if h in live_map)
        hist_hosts = sorted(h for h in clean_hosts if h not in live_map)
        live_count = len(live_hosts)
        ordered = live_hosts + hist_hosts
    else:
        live_hosts = []
        live_count = None
        ordered = sorted(clean_hosts)

    returned = ordered[:limit]
    result = {
        "count":        total,
        "live_count":   live_count,
        "returned":     len(returned),
        "subdomains":   returned,
        "sources_used": sources_used,
    }
    if live_map is not None:
        result["live"] = [{"host": h, "ip": live_map.get(h, "")} for h in live_hosts][:LIVE_CAP]
    if pools:
        result["pools"] = pools
    # Only surface warnings when coverage is genuinely low.
    if total < LOW_COVERAGE_THRESHOLD and failed_msgs:
        result["warnings"] = failed_msgs
    return result


async def _enrich_in_background(domain: str, found: set, results_by_name: dict,
                                task_to_name: dict, pending: set, limit: int,
                                client: httpx.AsyncClient) -> None:
    """Await slow stragglers (e.g. crt.sh), run the liveness pass, then write the
    full tiered result to the subdomains cache so the next lookup of this domain is
    complete. Best-effort: any failure here is non-fatal — the user already got
    their snapshot."""
    try:
        if pending:
            await asyncio.wait(pending)
            for t in pending:
                name = task_to_name.get(t, "?")
                try:
                    results_by_name[name] = t.result()
                except Exception as exc:
                    results_by_name[name] = exc
        # Liveness pass over the full merged set -> live/historical tiers.
        live_map = await _compute_liveness(domain, found)
        full = _assemble(domain, found, results_by_name, [], limit, live_map=live_map)
        if "error" not in full:
            from app.cache import set_cached  # lazy import avoids any import cycle
            await set_cached("subdomains", domain, full)
            log.info("subdomain_enrich_cached domain=%s count=%s live=%s",
                     domain, full.get("count"), full.get("live_count"))
    except Exception as e:
        log.warning("subdomain_enrich_err domain=%s err=%s", domain, e)
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


async def get_subdomains(domain: str, limit: int = 2000, wait: bool = False, wait_liveness: bool = False) -> dict:
    """Discover subdomains for *domain* via concurrent multi-source aggregation.

    Runs the direct sources in parallel: crt.sh, certspotter, hackertarget,
    rapiddns, VirusTotal, and always-on DNS bruteforce, plus an optional
    subfinder background enrichment aggregating 25+ more passive sources for
    comprehensive coverage. Returns as soon as the reliable fast sources have
    reported (SOFT_DEADLINE); any slow-but-alive straggler (typically crt.sh or
    subfinder) keeps running in the background and writes its fuller result into
    the cache, so the next lookup of this domain is complete.

    With wait=True (the API ?wait=1 mode), block up to WAIT_DEADLINE for the slow
    sources to finish and return a fuller result in one call instead of the fast
    snapshot; anything still pending after that still enriches in the background.

    Warnings are suppressed when total coverage is healthy
    (>= LOW_COVERAGE_THRESHOLD), since partial-source-failure isn't actionable
    when the response is otherwise solid.
    """
    domain = domain.strip().lower().rstrip(".")
    if wait_liveness:
        wait = True   # liveness-inline (used by the monitoring cron) implies waiting for sources first
    found: set = set()

    # NOTE: the client is intentionally NOT created with `async with` — a
    # background straggler may still be using it after we return the snapshot,
    # so ownership of aclose() passes to whichever path finishes last.
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=CONNECT_TIMEOUT),
        follow_redirects=True,
    )

    # Named tasks so we can label which sources are still pending at the deadline.
    tasks = {
        "crt.sh":       asyncio.ensure_future(_src_crtsh(client, domain, found)),
        "certspotter":  asyncio.ensure_future(_src_certspotter(client, domain, found)),
        "hackertarget": asyncio.ensure_future(_src_hackertarget(client, domain, found)),
        "rapiddns":     asyncio.ensure_future(_src_rapiddns(client, domain, found)),
        "virustotal":   asyncio.ensure_future(_src_virustotal(client, domain, found)),
        "dns-brute":    asyncio.ensure_future(_src_dns_bruteforce(domain, found)),
        "subfinder":    asyncio.ensure_future(_src_subfinder(domain, found)),
    }
    task_to_name = {t: n for n, t in tasks.items()}

    done, pending = await asyncio.wait(tasks.values(), timeout=(WAIT_DEADLINE if wait else SOFT_DEADLINE))

    # Protect the always-on floor: dns-brute is our coverage guarantee, so if it
    # was just over the soft deadline (concurrent-load contention), give it a
    # short grace window to land in the snapshot instead of deferring it to the
    # background like the flaky HTTP upstreams.
    brute = tasks["dns-brute"]
    if brute in pending:
        grace_done, _ = await asyncio.wait({brute}, timeout=BRUTE_FLOOR_GRACE)
        if brute in grace_done:
            pending = pending - {brute}
            done = done | {brute}

    results_by_name: dict = {}
    for t in done:
        name = task_to_name[t]
        try:
            results_by_name[name] = t.result()
        except Exception as exc:
            results_by_name[name] = exc

    pending_names = [task_to_name[t] for t in pending]

    if wait:
        # Opt-in complete mode: gather any remaining sources inline for full coverage now.
        if pending:
            await asyncio.wait(pending)
            for t in list(pending):
                nm = task_to_name.get(t, "?")
                try:
                    results_by_name[nm] = t.result()
                except Exception as exc:
                    results_by_name[nm] = exc
            pending = set()
        if wait_liveness:
            # Fully synchronous (monitoring cron): run the liveness pass inline and
            # return the complete tiered result — no background task.
            live_map = await _compute_liveness(domain, found)
            await client.aclose()
            return _assemble(domain, found, results_by_name, [], limit, live_map=live_map)
        # Default ?wait=1: sources complete now; liveness tiers fill in the background.
        result = _assemble(domain, found, results_by_name, [], limit, liveness_pending=True)
        asyncio.ensure_future(
            _enrich_in_background(domain, found, results_by_name, task_to_name, set(), limit, client)
        )
        return result

    snapshot = _assemble(domain, found, results_by_name, pending_names, limit, liveness_pending=True)
    # Always enrich in the background — await any pending slow sources AND run the
    # liveness pass — then cache the full tiered result. The page/poll self-heals.
    asyncio.ensure_future(
        _enrich_in_background(domain, found, results_by_name, task_to_name, pending, limit, client)
    )
    return snapshot
