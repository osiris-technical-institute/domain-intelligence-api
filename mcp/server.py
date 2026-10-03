"""Domain Intelligence MCP server (remote, Streamable HTTP).

Hosted at https://oti-labs.com/mcp. Each tool calls the Domain Intelligence API through
RapidAPI with the caller's own RapidAPI key, so every call is an ordinary RapidAPI call:
counted, quota-limited and billed on the caller's plan. Send the key as the
`X-RapidAPI-Key` header (or `Authorization: Bearer <key>`).

Without a key, calls run keyless: 1,000 lookups per IP per calendar month (UTC) at up to 10 a
minute, the same as RapidAPI's free plan. They go straight to the local API (not through
RapidAPI) and are counted in Redis. When they run out, a free RapidAPI key gives 1,000 more.

Run:  uvicorn server:app --host 127.0.0.1 --port 8002 --proxy-headers
Test against a local API instead of RapidAPI: set DI_API_BASE and DI_PROXY_SECRET.
"""
import datetime
import hashlib
import os
import re
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
KEYLESS_MONTHLY = 1000
KEYLESS_PER_MINUTE = 10
LISTING = ("https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default"
           "/api/domain-intelligence-api")
PRICING = LISTING + "/pricing"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
READ_ONLY = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=True)

mcp = MCPServer(
    name="domain-intelligence",
    title="Domain Intelligence",
    version="1.1.0",
    website_url="https://oti-labs.com/mcp-server",
    icons=[Icon(src="https://oti-labs.com/favicon-192.png", mimeType="image/png", sizes=["192x192"])],
    instructions=(
        "Domain intelligence for any domain: WHOIS/RDAP registration (age, registrar, expiry), DNS "
        "records, the live SSL certificate, subdomains (live hosts with IPs vs historical names) and "
        "email authentication (SPF, DMARC, DKIM). Use domain_lookup for the full picture in one call, "
        "or a single tool when only one part is needed. Pass bare domains such as example.com. "
        f"Works without a key for {KEYLESS_MONTHLY:,} lookups a month per IP. After that, send a "
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


async def _keyless(ctx: Context, path: str, params: dict | None) -> dict[str, Any]:
    ip = ((ctx.headers or {}).get("x-forwarded-for") or "").split(",")[0].strip() or "unknown"
    now = datetime.datetime.now(datetime.timezone.utc)
    month_key = f"mcp:keyless:{ip}:{now:%Y-%m}"
    used = None
    try:
        r = _rds()
        minute_key = f"mcp:keyless:min:{ip}:{now:%Y%m%d%H%M}"
        pipe = r.pipeline()
        pipe.incr(minute_key); pipe.expire(minute_key, 120)
        per_min = (await pipe.execute())[0]
        if per_min > KEYLESS_PER_MINUTE:
            raise ToolError(f"Keyless use is limited to {KEYLESS_PER_MINUTE} lookups a minute. Wait a "
                            f"moment, or add a RapidAPI key as X-RapidAPI-Key: {PRICING}")
        pipe = r.pipeline()
        pipe.incr(month_key); pipe.expire(month_key, 40 * 86400)
        used = (await pipe.execute())[0]
        if used > KEYLESS_MONTHLY:
            raise ToolError(
                f"The {KEYLESS_MONTHLY:,} free keyless lookups for this month are used up. Get a free "
                "RapidAPI key (another 1,000 requests a month, no card) and send it as X-RapidAPI-Key: "
                f"{PRICING}")
        stats = r.pipeline()   # anonymous adoption stats: calls per day, distinct (hashed) IPs per month
        stats.incr(f"mcp:keyless:calls:{now:%Y-%m-%d}"); stats.expire(f"mcp:keyless:calls:{now:%Y-%m-%d}", 120 * 86400)
        stats.sadd(f"mcp:keyless:ips:{now:%Y-%m}", hashlib.sha256(ip.encode()).hexdigest()[:16])
        stats.expire(f"mcp:keyless:ips:{now:%Y-%m}", 120 * 86400)
        await stats.execute()
    except ToolError:
        raise
    except Exception:
        used = None   # Redis trouble: serve the call rather than fail it
    headers = {"X-RapidAPI-Proxy-Secret": INTERNAL_SECRET, "User-Agent": "oti-labs-domain-intelligence-mcp/keyless"}
    try:
        resp = await _http().get(f"{INTERNAL_BASE}{path}", params=params or None, headers=headers)
    except httpx.HTTPError as e:
        await _refund(month_key)
        raise ToolError(f"Could not reach the API: {type(e).__name__}. Try again in a moment.")
    if resp.status_code >= 500 or resp.status_code in (401, 403):
        await _refund(month_key)
        raise ToolError(f"The API returned HTTP {resp.status_code}. Try again in a moment.")
    data = _parse(resp)
    if used is not None:
        data["_keyless"] = (f"{max(0, KEYLESS_MONTHLY - used):,} of {KEYLESS_MONTHLY:,} free keyless lookups left "
                            f"this month. A free RapidAPI key adds 1,000 more: {PRICING}")
    return data


async def _refund(month_key: str) -> None:
    try:
        await _rds().decr(month_key)
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


@mcp.tool(annotations=READ_ONLY, structured_output=True)
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


@mcp.tool(annotations=READ_ONLY, structured_output=True)
async def whois_lookup(domain: str, ctx: Context) -> dict[str, Any]:
    """Registration data for a domain: registrar, created, updated and expiry dates, nameservers and
    status. RDAP first (rdap.org, IANA bootstrap, 22 fallback servers), then port-43 WHOIS for 60+
    TLDs. `_source` says which one answered. Use it for domain age, expiry or registrar checks."""
    d = _clean_domain(domain)
    return await _fetch(ctx, f"/domain/{d}/whois")


@mcp.tool(annotations=READ_ONLY, structured_output=True)
async def dns_records(domain: str, ctx: Context) -> dict[str, Any]:
    """DNS records for a domain: A, AAAA, MX, TXT, NS, CAA and SOA, resolved in parallel."""
    d = _clean_domain(domain)
    return await _fetch(ctx, f"/domain/{d}/dns")


@mcp.tool(annotations=READ_ONLY, structured_output=True)
async def ssl_certificate(domain: str, ctx: Context) -> dict[str, Any]:
    """The certificate a domain serves on port 443, from a live TLS handshake: issuer, subject,
    valid_from, valid_to, days_until_expiry, SANs, signature algorithm and serial number."""
    d = _clean_domain(domain)
    return _trim_sans(await _fetch(ctx, f"/domain/{d}/ssl"))


@mcp.tool(annotations=READ_ONLY, structured_output=True)
async def subdomains(domain: str, ctx: Context, wait: bool = False, limit: int = 100) -> dict[str, Any]:
    """Subdomains of a domain from certificate transparency logs, passive DNS and DNS brute force.
    `live` lists hosts that resolve now, each with its IP; `subdomains` lists every name found, live
    first; `pools` summarises large shared-infrastructure zones. The first lookup of a domain is a fast
    snapshot and later ones are fuller; set wait=true to wait for every source (up to about 20 s)."""
    d = _clean_domain(domain)
    data = await _fetch(ctx, f"/domain/{d}/subdomains", {"wait": 1} if wait else None)
    return _trim_subdomains(data, _clamp(limit))


@mcp.tool(annotations=READ_ONLY, structured_output=True)
async def email_security(domain: str, ctx: Context) -> dict[str, Any]:
    """Email authentication for a domain: SPF and DMARC records, and DKIM keys found by probing about
    29 common selectors (Google, Microsoft 365, Mailchimp, SendGrid and others). Custom selectors
    may not be found."""
    d = _clean_domain(domain)
    return await _fetch(ctx, f"/domain/{d}/email-security")


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(request):
    return JSONResponse({"status": "ok", "server": "domain-intelligence-mcp", "version": "1.1.0"})


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
