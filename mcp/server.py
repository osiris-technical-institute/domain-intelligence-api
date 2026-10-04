"""Domain Intelligence MCP server (remote, Streamable HTTP).

Hosted at https://oti-labs.com/mcp. Each tool calls the Domain Intelligence API through
RapidAPI with the caller's own RapidAPI key, so every call is an ordinary RapidAPI call:
counted, quota-limited and billed on the caller's plan. Send the key as the
`X-RapidAPI-Key` header (or `Authorization: Bearer <key>`).

Without a key, calls run keyless: 1,000 lookups per IP per calendar month (UTC) at up to 10 a
minute, the same as RapidAPI's free plan. IPv6 clients are counted per /64. Hosted clients that
call from their provider's shared addresses (Claude and ChatGPT connectors, the Smithery gateway)
share one pool per provider: 10,000 a month at up to 120 a minute. All keyless use together stops
at 2,000 calls a day. Keyless calls go straight to the local API (not through RapidAPI) and are counted in
Redis. When they run out, a free RapidAPI key gives 1,000 more.

Run:  uvicorn server:app --host 127.0.0.1 --port 8002 --proxy-headers
Test against a local API instead of RapidAPI: set DI_API_BASE and DI_PROXY_SECRET.
"""
import datetime
import hashlib
import ipaddress
import json
import os
import re
import time
from typing import Any

import httpx
import redis.asyncio as aioredis
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import Icon, ToolAnnotations
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

RAPIDAPI_HOST = "domain-intelligence-api.p.rapidapi.com"
API_BASE = os.environ.get("DI_API_BASE", f"https://{RAPIDAPI_HOST}")
TEST_PROXY_SECRET = os.environ.get("DI_PROXY_SECRET", "")  # test mode only, unset in production
# Keyless use: counted per client IP (Caddy overwrites X-Forwarded-For with the real address),
# served by the local API with the internal proxy secret.
INTERNAL_BASE = os.environ.get("DI_INTERNAL_BASE", "http://127.0.0.1:8001")
INTERNAL_SECRET = os.environ.get("RAPIDAPI_PROXY_SECRET", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
KEY_PREFIX = os.environ.get("MCP_KEYLESS_PREFIX", "mcp:keyless")   # tests use their own prefix
KEYLESS_MONTHLY = int(os.environ.get("MCP_KEYLESS_MONTHLY", "1000"))
KEYLESS_PER_MINUTE = int(os.environ.get("MCP_KEYLESS_PER_MINUTE", "10"))
# Hosted clients call from their provider's shared egress addresses, so each provider gets one
# shared bucket instead of per-IP ones.
PROVIDER_MONTHLY = int(os.environ.get("MCP_PROVIDER_MONTHLY", "10000"))
PROVIDER_PER_MINUTE = int(os.environ.get("MCP_PROVIDER_PER_MINUTE", "120"))
KEYLESS_DAILY_CEILING = int(os.environ.get("MCP_KEYLESS_DAILY_CEILING", "2000"))   # all keyless callers
# Claude connectors: https://platform.claude.com/docs/en/api/ip-addresses (outbound).
ANTHROPIC_RANGES = [ipaddress.ip_network("160.79.104.0/21")]
# ChatGPT connectors: https://openai.com/chatgpt-connectors.json, copied here daily by
# refresh_openai_ranges.py. Without the file, ChatGPT calls are counted per IP.
OPENAI_RANGES_FILE = os.environ.get(
    "MCP_OPENAI_RANGES_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "chatgpt-connectors.json"))
# Smithery's gateway calls from Cloudflare Workers, whose shared edge addresses are also used by
# other Workers. Cloudflare sets Cf-Worker to the calling zone and a Worker can't override it, so
# Cf-Worker: smithery.ai from a Cloudflare address identifies Smithery. https://www.cloudflare.com/ips/
CLOUDFLARE_RANGES = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32")]
SMITHERY_WORKER = "smithery.ai"
PROVIDER_LABEL = {"anthropic": "Claude", "openai": "ChatGPT", "smithery": "Smithery"}
# How a user of each platform gets their own allowance (a RapidAPI key sent as a header).
OWN_KEY_HINT = {
    "anthropic": "send a free RapidAPI key as X-RapidAPI-Key from a client that can set headers (Claude Code, Cursor, VS Code, Windsurf)",
    "openai": "send a free RapidAPI key as X-RapidAPI-Key from a client that can set headers (Claude Code, Cursor, VS Code, Windsurf)",
    "smithery": "add a free RapidAPI key as X-RapidAPI-Key in this server's connection settings on Smithery",
}
VERSION = "1.2.2"
LISTING = ("https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default"
           "/api/domain-intelligence-api")
PRICING = LISTING + "/pricing"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(title=title, read_only_hint=True, idempotent_hint=True, open_world_hint=True)

mcp = MCPServer(
    name="domain-intelligence",
    title="Domain Intelligence",
    version=VERSION,
    website_url="https://oti-labs.com/mcp-server",
    icons=[Icon(src="https://oti-labs.com/favicon-192.png", mimeType="image/png", sizes=["192x192"])],
    instructions=(
        "Domain intelligence for any domain: WHOIS/RDAP registration (age, registrar, expiry), DNS "
        "records, the live SSL certificate, subdomains (live hosts with IPs vs historical names) and "
        "email authentication (SPF, DMARC, DKIM). Use domain_lookup for the full picture in one call, "
        "or a single tool when only one part is needed. Pass bare domains such as example.com. "
        f"Works without a key for {KEYLESS_MONTHLY:,} lookups a month per IP (hosted Claude, ChatGPT and Smithery "
        "connectors share a larger pool per provider). After that, send a "
        "RapidAPI key subscribed to the Domain Intelligence API as the X-RapidAPI-Key header; its "
        f"free plan adds 1,000 requests a month: {PRICING}"
    ),
)

_client: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=10.0))
    return _client


def _clean_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)       # drop a scheme
    d = d.split("/")[0].split("?")[0].split("#")[0]   # drop path, query, fragment
    d = d.split("@")[-1].split(":")[0].rstrip(".")    # drop userinfo and port
    if d.startswith("www.") and d.count(".") > 1:
        d = d[4:]
    if not DOMAIN_RE.match(d):
        raise ToolError(f"'{domain}' is not a valid domain name. Pass a bare domain such as example.com.")
    return d


def _api_key(ctx: Context) -> str:
    headers = ctx.headers or {}
    key = (headers.get("x-rapidapi-key") or "").strip()
    if not key:
        auth = (headers.get("authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()
    if key.startswith("${"):   # an unfilled client placeholder such as ${user_config.rapidapi_key}
        key = ""
    return key


_redis = None


def _rds():
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    return _redis


async def _fetch(ctx: Context, path: str, params: dict | None = None) -> dict[str, Any]:
    """With a key (or in test mode): the API through RapidAPI. Without one: keyless quota."""
    if _api_key(ctx) or TEST_PROXY_SECRET:
        return await _call(ctx, path, params)
    return await _keyless(ctx, path, params)


_openai = {"nets": [], "mtime": None, "checked": None}


def _openai_ranges() -> list:
    """ChatGPT connector ranges from the local file, re-read when it changes (checked once a minute).
    A missing or broken file keeps the last good list."""
    now = time.monotonic()
    if _openai["checked"] is not None and now - _openai["checked"] < 60:
        return _openai["nets"]
    _openai["checked"] = now
    try:
        mtime = os.stat(OPENAI_RANGES_FILE).st_mtime
        if mtime != _openai["mtime"]:
            with open(OPENAI_RANGES_FILE, encoding="utf-8") as f:
                prefixes = json.load(f)["prefixes"]
            _openai["nets"] = [ipaddress.ip_network(p.get("ipv4Prefix") or p["ipv6Prefix"], strict=False)
                               for p in prefixes]
            _openai["mtime"] = mtime
    except Exception:
        pass
    return _openai["nets"]


def _bucket(ip: str, headers=None) -> tuple[str, str | None]:
    """Quota bucket for a client address and the provider it belongs to, if any: a provider's shared
    bucket, the /64 for IPv6, otherwise the IPv4 address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown", None
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if ((headers or {}).get("cf-worker") or "").strip().lower() == SMITHERY_WORKER \
            and any(addr in n for n in CLOUDFLARE_RANGES):
        return "provider:smithery", "smithery"
    if any(addr in n for n in ANTHROPIC_RANGES):
        return "provider:anthropic", "anthropic"
    if any(addr in n for n in _openai_ranges()):
        return "provider:openai", "openai"
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False)), None
    return str(addr), None


async def _keyless(ctx: Context, path: str, params: dict | None) -> dict[str, Any]:
    ip = ((ctx.headers or {}).get("x-forwarded-for") or "").split(",")[0].strip()
    bucket, provider = _bucket(ip, ctx.headers)
    label = PROVIDER_LABEL.get(provider or "", "")
    monthly, per_minute = (PROVIDER_MONTHLY, PROVIDER_PER_MINUTE) if provider else (KEYLESS_MONTHLY, KEYLESS_PER_MINUTE)
    now = datetime.datetime.now(datetime.timezone.utc)
    month_key = f"{KEY_PREFIX}:{bucket}:{now:%Y-%m}"
    day_key = f"{KEY_PREFIX}:calls:{now:%Y-%m-%d}"   # keyless calls served today, also the daily ceiling
    used = None
    counted = False
    try:
        r = _rds()
        minute_key = f"{KEY_PREFIX}:min:{bucket}:{now:%Y%m%d%H%M}"
        pipe = r.pipeline()
        pipe.incr(minute_key); pipe.expire(minute_key, 120)
        if (await pipe.execute())[0] > per_minute:
            if provider:
                raise ToolError(f"Keyless lookups through {label} share a limit of {per_minute} a "
                                "minute. Wait a moment and try again.")
            raise ToolError(f"Keyless use is limited to {per_minute} lookups a minute. Wait a "
                            f"moment, or add a RapidAPI key as X-RapidAPI-Key: {PRICING}")
        pipe = r.pipeline()
        pipe.incr(month_key); pipe.expire(month_key, 40 * 86400)
        used = (await pipe.execute())[0]
        if used > monthly:
            if provider:
                raise ToolError(
                    f"The keyless pool shared by everyone using this server through {label} ({monthly:,} "
                    f"lookups a month) is used up. To keep going, {OWN_KEY_HINT[provider]} (1,000 requests "
                    f"a month, no card): {PRICING}")
            raise ToolError(
                f"The {monthly:,} free keyless lookups for this month are used up. Get a free "
                "RapidAPI key (another 1,000 requests a month, no card) and send it as X-RapidAPI-Key: "
                f"{PRICING}")
        pipe = r.pipeline()
        pipe.incr(day_key); pipe.expire(day_key, 120 * 86400)
        if (await pipe.execute())[0] > KEYLESS_DAILY_CEILING:
            pipe = r.pipeline()
            pipe.decr(day_key); pipe.decr(month_key)   # a refused call doesn't count
            await pipe.execute()
            raise ToolError(
                "Keyless capacity on this server is used up for today; it resets at 00:00 UTC. To keep "
                "going now, add a free RapidAPI key as X-RapidAPI-Key (1,000 requests a month, no card): "
                f"{PRICING}")
        counted = True
        stats = r.pipeline()   # anonymous adoption stats: distinct (hashed) callers and calls by source, per month
        stats.sadd(f"{KEY_PREFIX}:ips:{now:%Y-%m}", hashlib.sha256(bucket.encode()).hexdigest()[:16])
        stats.expire(f"{KEY_PREFIX}:ips:{now:%Y-%m}", 120 * 86400)
        stats.hincrby(f"{KEY_PREFIX}:src:{now:%Y-%m}", provider or "ip", 1)
        stats.expire(f"{KEY_PREFIX}:src:{now:%Y-%m}", 120 * 86400)
        await stats.execute()
    except ToolError:
        raise
    except Exception:
        used = None   # Redis trouble: serve the call rather than fail it
    headers = {"X-RapidAPI-Proxy-Secret": INTERNAL_SECRET, "User-Agent": "oti-labs-domain-intelligence-mcp/keyless"}
    try:
        resp = await _http().get(f"{INTERNAL_BASE}{path}", params=params or None, headers=headers)
    except httpx.HTTPError as e:
        if counted:
            await _refund(month_key, day_key)
        raise ToolError(f"Could not reach the API: {type(e).__name__}. Try again in a moment.")
    if resp.status_code >= 500 or resp.status_code in (401, 403):
        if counted:
            await _refund(month_key, day_key)
        raise ToolError(f"The API returned HTTP {resp.status_code}. Try again in a moment.")
    data = _parse(resp)
    if used is not None:
        left = max(0, monthly - used)
        if provider:
            data["_keyless"] = (f"{left:,} of {monthly:,} lookups left this month in the keyless pool shared by "
                                f"all {label} users. For 1,000 a month of your own, {OWN_KEY_HINT[provider]}: "
                                f"{PRICING}")
        else:
            data["_keyless"] = (f"{left:,} of {monthly:,} free keyless lookups left this month. "
                                f"A free RapidAPI key adds 1,000 more: {PRICING}")
    return data


async def _refund(*keys: str) -> None:
    try:
        pipe = _rds().pipeline()
        for k in keys:
            pipe.decr(k)
        await pipe.execute()
    except Exception:
        pass


def _parse(r: httpx.Response) -> dict[str, Any]:
    if r.status_code == 400:
        raise ToolError("The API rejected the domain as invalid.")
    if r.status_code >= 400:
        raise ToolError(f"The API returned HTTP {r.status_code}. Try again in a moment.")
    try:
        data = r.json()
    except ValueError:
        raise ToolError("The API returned a response that was not JSON.")
    return data if isinstance(data, dict) else {"result": data}


async def _call(ctx: Context, path: str, params: dict | None = None) -> dict[str, Any]:
    key = _api_key(ctx)
    headers = {"X-RapidAPI-Key": key, "X-RapidAPI-Host": RAPIDAPI_HOST,
               "User-Agent": "oti-labs-domain-intelligence-mcp/1.0"}
    if TEST_PROXY_SECRET:
        headers["X-RapidAPI-Proxy-Secret"] = TEST_PROXY_SECRET
    try:
        r = await _http().get(f"{API_BASE}{path}", params=params or None, headers=headers)
    except httpx.TimeoutException:
        raise ToolError("The lookup timed out. Try again; repeat lookups are served from cache.")
    except httpx.HTTPError as e:
        raise ToolError(f"Could not reach the API: {type(e).__name__}.")
    if r.status_code in (401, 403):
        raise ToolError(
            f"RapidAPI rejected the key (HTTP {r.status_code}). Make sure the key is subscribed to the "
            f"Domain Intelligence API; the free plan is 1,000 requests a month: {PRICING}")
    if r.status_code == 429:
        raise ToolError(
            "Quota or rate limit reached (HTTP 429). The free plan allows 1,000 requests a month; "
            f"PRO is $9.99/mo for 50,000 requests: {PRICING}")
    return _parse(r)


def _trim_subdomains(s, limit: int):
    """Keep the first `limit` live hosts and names so a big zone doesn't flood the context."""
    if not isinstance(s, dict):
        return s
    out = dict(s)
    live, names = s.get("live") or [], s.get("subdomains") or []
    out["live"], out["subdomains"] = live[:limit], names[:limit]
    if len(live) > limit or len(names) > limit:
        out["truncated"] = (f"Showing the first {limit} of {len(live)} live hosts and {len(names)} names "
                            "(live first). Raise limit (max 2000) for more.")
    return out


def _trim_sans(s, limit: int = 50):
    if isinstance(s, dict) and isinstance(s.get("sans"), list) and len(s["sans"]) > limit:
        s = dict(s)
        s["sans_count"] = len(s["sans"])
        s["sans"] = s["sans"][:limit]
    return s


def _clamp(limit: int) -> int:
    return max(1, min(int(limit or 100), 2000))


@mcp.tool(title="Full domain lookup", annotations=_read_only("Full domain lookup"), structured_output=True)
async def domain_lookup(domain: str, ctx: Context, wait: bool = False, subdomain_limit: int = 50) -> dict[str, Any]:
    """Full report on a domain in one call: WHOIS/RDAP registration, DNS records, live SSL
    certificate, subdomains (live hosts with IPs first) and email authentication (SPF, DMARC, DKIM).
    Use it to triage a suspicious domain or profile a company's domain. If one section fails it comes
    back as an object with an `error` field and the rest is unaffected. Set wait=true to wait for every
    subdomain source (up to about 20 s) instead of the fast first result."""
    d = _clean_domain(domain)
    data = await _fetch(ctx, f"/lookup/{d}", {"wait": 1} if wait else None)
    data["subdomains"] = _trim_subdomains(data.get("subdomains"), _clamp(subdomain_limit))
    data["ssl"] = _trim_sans(data.get("ssl"))
    return data


@mcp.tool(title="WHOIS / RDAP lookup", annotations=_read_only("WHOIS / RDAP lookup"), structured_output=True)
async def whois_lookup(domain: str, ctx: Context) -> dict[str, Any]:
    """Registration data for a domain: registrar, created, updated and expiry dates, nameservers and
    status. RDAP first (rdap.org, IANA bootstrap, 22 fallback servers), then port-43 WHOIS for 60+
    TLDs. `_source` says which one answered. Use it for domain age, expiry or registrar checks."""
    d = _clean_domain(domain)
    return await _fetch(ctx, f"/domain/{d}/whois")


@mcp.tool(title="DNS records", annotations=_read_only("DNS records"), structured_output=True)
async def dns_records(domain: str, ctx: Context) -> dict[str, Any]:
    """DNS records for a domain: A, AAAA, MX, TXT, NS, CAA and SOA, resolved in parallel."""
    d = _clean_domain(domain)
    return await _fetch(ctx, f"/domain/{d}/dns")


@mcp.tool(title="SSL certificate", annotations=_read_only("SSL certificate"), structured_output=True)
async def ssl_certificate(domain: str, ctx: Context) -> dict[str, Any]:
    """The certificate a domain serves on port 443, from a live TLS handshake: issuer, subject,
    valid_from, valid_to, days_until_expiry, SANs, signature algorithm and serial number."""
    d = _clean_domain(domain)
    return _trim_sans(await _fetch(ctx, f"/domain/{d}/ssl"))


@mcp.tool(title="Subdomains", annotations=_read_only("Subdomains"), structured_output=True)
async def subdomains(domain: str, ctx: Context, wait: bool = False, limit: int = 100) -> dict[str, Any]:
    """Subdomains of a domain from certificate transparency logs, passive DNS and DNS brute force.
    `live` lists hosts that resolve now, each with its IP; `subdomains` lists every name found, live
    first; `pools` summarises large shared-infrastructure zones. The first lookup of a domain is a fast
    snapshot and later ones are fuller; set wait=true to wait for every source (up to about 20 s)."""
    d = _clean_domain(domain)
    data = await _fetch(ctx, f"/domain/{d}/subdomains", {"wait": 1} if wait else None)
    return _trim_subdomains(data, _clamp(limit))


@mcp.tool(title="Email security (SPF, DMARC, DKIM)", annotations=_read_only("Email security (SPF, DMARC, DKIM)"), structured_output=True)
async def email_security(domain: str, ctx: Context) -> dict[str, Any]:
    """Email authentication for a domain: SPF and DMARC records, and DKIM keys found by probing about
    29 common selectors (Google, Microsoft 365, Mailchimp, SendGrid and others). Custom selectors
    may not be found."""
    d = _clean_domain(domain)
    return await _fetch(ctx, f"/domain/{d}/email-security")


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):
    return JSONResponse({"status": "ok", "server": "domain-intelligence-mcp", "version": VERSION})


# Public server with per-call key auth, so DNS-rebinding protection (meant for local servers)
# is off; CORS is open so browser-based MCP clients can connect.
app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version"],
)
