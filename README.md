# Domain Intelligence API

[![Live](https://img.shields.io/badge/API-live-brightgreen)](https://oti-labs.com/domain-intelligence-api)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-listed-2196f3)](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#self-hosting)

> WHOIS/RDAP, DNS, SSL/TLS, subdomains and email security (SPF, DMARC, DKIM) for any domain, in one REST call.

A FastAPI service that runs the five lookups in parallel and returns one JSON object. Built and run in production by [Osiris Technical Institute](https://oti-labs.com).

- **Website and live demo:** <https://oti-labs.com/domain-intelligence-api>
- **Free web report for any domain:** `https://oti-labs.com/report/{domain}`, e.g. <https://oti-labs.com/report/stripe.com>
- **API key and pricing:** [RapidAPI listing](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api)
- **OpenAPI spec:** [`rapidapi/openapi.json`](rapidapi/openapi.json)

---

## Try it (no key needed)

The public demo returns the full aggregate result, limited to 5 requests per IP per day:

```bash
curl -s https://oti-labs.com/demo/example.com | jq
```

## Use it (RapidAPI key)

```bash
curl -s "https://domain-intelligence-api.p.rapidapi.com/lookup/example.com" \
  -H "X-RapidAPI-Host: domain-intelligence-api.p.rapidapi.com" \
  -H "X-RapidAPI-Key: YOUR_RAPIDAPI_KEY"
```

```python
import requests

r = requests.get(
    "https://domain-intelligence-api.p.rapidapi.com/lookup/example.com",
    headers={
        "X-RapidAPI-Host": "domain-intelligence-api.p.rapidapi.com",
        "X-RapidAPI-Key": "YOUR_RAPIDAPI_KEY",
    },
    timeout=30,
)
data = r.json()
print(data["whois"]["registrar"], data["ssl"]["days_until_expiry"], data["subdomains"]["count"])
```

```javascript
// Node 18+ (built-in fetch)
const res = await fetch("https://domain-intelligence-api.p.rapidapi.com/lookup/example.com", {
  headers: {
    "X-RapidAPI-Host": "domain-intelligence-api.p.rapidapi.com",
    "X-RapidAPI-Key": "YOUR_RAPIDAPI_KEY",
  },
});
const data = await res.json();
```

---

## MCP server

AI agents and assistants can use the API as tools through the hosted MCP server at `https://oti-labs.com/mcp` (Streamable HTTP, registry name `com.oti-labs/domain-intelligence`). Send your RapidAPI key in the `X-RapidAPI-Key` header; each tool call counts as one API call on your plan.

```bash
claude mcp add --transport http domain-intelligence https://oti-labs.com/mcp --header "X-RapidAPI-Key: YOUR_KEY"
```

Tools: `domain_lookup`, `whois_lookup`, `dns_records`, `ssl_certificate`, `subdomains`, `email_security`. Setup for Cursor, VS Code, Windsurf and Claude Desktop is in [`mcp/README.md`](mcp/README.md).

---

## Endpoints

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/lookup/{domain}` | All five sections below, fetched in parallel. Supports `?wait=1`. |
| `GET` | `/domain/{domain}/whois` | Registrar, registration/update/expiry dates, nameservers, status codes, registry handle, `_source` |
| `GET` | `/domain/{domain}/dns` | A, AAAA, MX, TXT, NS, CAA and SOA records (CNAME and PTR are not returned) |
| `GET` | `/domain/{domain}/ssl` | Live TLS handshake: issuer, subject, validity dates, `days_until_expiry`, serial number, every SAN, signature algorithm |
| `GET` | `/domain/{domain}/subdomains` | Subdomains from CT logs, passive DNS and DNS brute-force, with live hosts and their IPs separated from historical names. Supports `?wait=1`. |
| `GET` | `/domain/{domain}/email-security` | SPF and DMARC presence and records, plus DKIM keys found by probing 29 common selectors |

Pass the bare hostname as the path parameter (no scheme, no path). Punycode (`xn--`) domains work. An invalid domain returns `400 {"detail": "invalid domain"}`.

`/lookup` returns `domain`, `elapsed_ms`, `cached` (which sections came from cache) and the five sections `dns`, `ssl`, `whois`, `subdomains`, `email_security`. If one section fails, it comes back as an object with an `error` field and the rest of the response is unaffected. Full response schemas and real examples are in the [OpenAPI spec](rapidapi/openapi.json).

---

## How each lookup works

**WHOIS: 4-tier fallback.** The response's `_source` field names the tier that answered.
1. `rdap.org` universal redirect
2. IANA RDAP bootstrap, then the TLD's own RDAP server (bootstrap cached 24 h)
3. Fixed RDAP base URLs for 22 common TLDs, in case the bootstrap is slow
4. Port-43 socket WHOIS with 61 TLD-specific servers (all major gTLDs plus many ccTLDs without RDAP, such as .fr, .nl, .au, .ca, .jp, .ru, .cn, .br, .es, .it and .ch). For an unmapped TLD the client asks `whois.iana.org` and follows its referral.

Registrant contact details are not returned. Some registries (for example .uk and .nl) redact most fields by policy.

**DNS.** The seven record types are resolved in parallel through the server's resolver, each with a 3 s limit. Each type is an array of strings, empty when the domain has none.

**SSL.** A direct TLS handshake on port 443 with a 5 s socket timeout, no third-party scanner. The certificate is returned even if it is expired, self-signed or issued for another name, so you see what is actually deployed. `signature_algorithm` is a name such as `ecdsa-with-SHA384`.

**Subdomains.**
- **Sources, run concurrently:** crt.sh and certspotter (certificate transparency logs); hackertarget, rapiddns and VirusTotal v3 (passive DNS; VirusTotal paginated to about 120 results); DNS brute-force with a 773-name wordlist across 8 public resolvers (Cloudflare, Google, Quad9, OpenDNS), resolving A and CNAME. Each HTTP source has a 2.5 s connect timeout so an unreachable host fails fast.
- **Optional subfinder:** if the [`subfinder`](https://github.com/projectdiscovery/subfinder) binary is installed, it runs as a background source that adds 25+ more passive sources. If it is absent, `sources_used` shows `subfinder: skipped`.
- **Wildcard detection:** three random labels are resolved first. If the zone answers them, brute-force is skipped so a `*.domain` wildcard can't flood the results; the CT and passive-DNS sources still run.
- **Fast by default:** the response comes back after a ~3 s soft deadline. Slow sources keep running in the background and write the fuller result into the cache. `?wait=1` waits for every source (up to about 20 s) instead.
- **Live vs historical:** a background pass resolves every discovered name (wildcard-aware) and adds `live`, a list of `{host, ip}` for names that resolve now (IP or CNAME target), and `live_count`. `subdomains` is ordered live-first. On a domain's first lookup this pass finishes after the response, so `live` appears in the cached result shortly after; until then `sources_used` includes `liveness: enriching`.
- **Noise filtering:** large shared-infrastructure subtrees (for example `*.ns.cloudflare.com`) are collapsed into `pools` with a few representatives kept. DKIM/DMARC records and invalid hostnames are dropped.
- **Output:** up to 2,000 names per response; `count` is always the full total. `sources_used` gives each source's status (`N found`, `enriching`, `rate-limited`, `unavailable`, `skipped`). `warnings` appears only when fewer than 20 names were found and some sources failed.

No tool finds every subdomain; hosts that never appear in public data can't be discovered passively.

**Email security.** SPF from the domain's TXT records, DMARC from `_dmarc.{domain}`, and DKIM by probing 29 selectors used by Google Workspace, Microsoft 365, Mailchimp, SendGrid, Postmark, Mandrill, Klaviyo, Mailgun and generic names. Records are returned raw; SPF and DMARC are not parsed. Custom or hash-based DKIM selectors (for example Amazon SES) can't be discovered this way. BIMI, MTA-STS and blocklist checks are not included.

**Timeouts.** Each section has an overall limit: DNS 5 s, WHOIS 8 s, SSL 8 s, subdomains 10 s, email 6 s. A section that times out returns `{"error": "timeout", ...}`.

## Caching

Successful results are cached in Redis per section. Failed lookups are not cached.

| Section | TTL |
|---------|-----|
| DNS | 5 min |
| WHOIS | 1 hour |
| SSL | 6 hours |
| Subdomains | 24 hours |
| Email security | 1 hour |

## Pricing (RapidAPI)

| Plan | Price | Requests / month | Rate limit | Overage |
|------|-------|------------------|------------|---------|
| **BASIC** | Free | 1,000 (hard limit) | 10 / min | none |
| **PRO** | $9.99/mo | 50,000 | 60 / min | $0.0005 / request |
| **ULTRA** | $39.99/mo | 500,000 | 300 / min | $0.0002 / request |
| **MEGA** | $149.99/mo | 5,000,000 | 1,000 / min | $0.0001 / request |

Every plan includes every endpoint. Cached responses count toward the quota like fresh ones. RapidAPI also applies its own bandwidth fee above 10 GB a month. Subscribe on the [RapidAPI pricing page](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api/pricing).

---

## Self-hosting

```bash
git clone https://github.com/osiris-technical-institute/domain-intelligence-api.git
cd domain-intelligence-api
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Needs Redis; the default is `redis://127.0.0.1:6379/0`. Put Caddy or nginx in front for TLS. The included [`domain-intel.service`](domain-intel.service) is the systemd unit used in production.

| Variable | Purpose |
|----------|---------|
| `REDIS_URL` | Redis connection URL |
| `RAPIDAPI_PROXY_SECRET` | If set, every non-public route requires a matching `X-RapidAPI-Proxy-Secret` header and returns `401` otherwise. Public routes: `/health`, `/metrics`, `/docs`, `/demo/*`, `/demo-preview/*`, `/report/*`, `/reports`, `/sitemap.xml`, `/robots.txt`. |
| `VT_API_KEY` | Enables the VirusTotal subdomain source (skipped if unset) |
| `SUBFINDER_BIN` | Path to the subfinder binary (default `/usr/local/bin/subfinder`; skipped if missing) |
| `SUBDOMAINS_WAIT_DEADLINE` | How long `wait=True` waits for slow subdomain sources (default 20 s) |
| `SUBDOMAINS_LIVENESS_BUDGET`, `SUBDOMAINS_LIVE_CAP` | Max names resolved in the liveness pass (5,000) and max live hosts returned (2,000) |

## Repo layout

```
app/
  main.py             Routes, auth middleware, demo endpoint
  cache.py            Redis cache (per-section TTLs; errors are not cached)
  dns_lookup.py       A, AAAA, MX, TXT, NS, CAA, SOA
  whois_lookup.py     rdap.org -> IANA bootstrap -> 22 RDAP servers -> port-43 WHOIS (61 servers + IANA referral)
  ssl_lookup.py       Live TLS handshake
  subdomains.py       CT logs, passive DNS, VirusTotal, DNS brute-force, optional subfinder, liveness, pools
  email_security.py   SPF, DMARC, DKIM (29 selectors)
  report.py           HTML report pages (/report/{domain}, /reports)
  seed_domains.py     Domains listed in the sitemap and /reports
  templates/          Jinja2 templates for the report pages
  metrics.py          Prometheus metrics (/metrics)
  logging_config.py   JSON logging
  timeouts.py         Per-section timeouts
mcp/
  server.py           MCP server (tools that call the API through RapidAPI)
  server.json         MCP Registry entry
rapidapi/
  openapi.json        OpenAPI 3.1 spec
  terms.md            Terms of use
domain-intel.service  systemd unit
requirements.txt      Python dependencies
```

## Terms of use

[`rapidapi/terms.md`](rapidapi/terms.md)

## License

[MIT](LICENSE). Copyright (c) 2026 Osiris Technical Institute.
