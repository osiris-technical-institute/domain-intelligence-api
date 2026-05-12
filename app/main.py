"""FastAPI entrypoint for Domain Intelligence service (Sprint D)."""
import asyncio
import logging
import os
import time
import re
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from app.dns_lookup import get_dns_records
from app.ssl_lookup import get_ssl_info
from app.whois_lookup import get_whois
from app.subdomains import get_subdomains
from app.email_security import get_email_security
from app.cache import cached_call, get_client as get_redis
from app.metrics import (
    REQUEST_COUNT, REQUEST_LATENCY, CACHE_HITS, CACHE_MISSES, INFLIGHT, render as render_metrics,
)
from app.timeouts import with_timeout
from app.logging_config import configure as configure_logging

configure_logging()
log = logging.getLogger("domain-intel")

PROXY_SECRET = os.environ.get("RAPIDAPI_PROXY_SECRET", "")
AUTH_BYPASS_PATHS = {"/health", "/docs", "/openapi.json", "/redoc", "/metrics"}
AUTH_BYPASS_PREFIXES = ("/demo/",)

app = FastAPI(
    title="Domain Intelligence API",
    version="0.2.0",
    description="Aggregated WHOIS, DNS, SSL, subdomains, and email security intelligence for any domain.",
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


@app.on_event("startup")
async def _startup():
    try:
        await get_redis().ping()
        log.info("redis_connected")
    except Exception as e:
        log.warning("redis_unavailable err=%s", e)


@app.middleware("http")
async def request_pipeline(request: Request, call_next):
    """Auth + structured logging + metrics in one pass."""
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    request.state.request_id = rid
    path = request.url.path
    method = request.method
    t0 = time.time()
    INFLIGHT.inc()
    status = 500
    try:
        # Auth
        if path not in AUTH_BYPASS_PATHS and not any(path.startswith(p) for p in AUTH_BYPASS_PREFIXES) and PROXY_SECRET:
            incoming = request.headers.get("X-RapidAPI-Proxy-Secret", "")
            if not incoming or incoming != PROXY_SECRET:
                status = 401
                resp = JSONResponse(
                    status_code=401,
                    content={"error": "Unauthorized", "detail": "Missing or invalid X-RapidAPI-Proxy-Secret header."},
                )
                resp.headers["x-request-id"] = rid
                return resp
        response = await call_next(request)
        status = response.status_code
        response.headers["x-request-id"] = rid
        return response
    finally:
        elapsed = time.time() - t0
        INFLIGHT.dec()
        # Normalize endpoint label (collapse domain segments)
        endpoint_label = _label(path)
        try:
            REQUEST_COUNT.labels(method=method, endpoint=endpoint_label, status=str(status)).inc()
            REQUEST_LATENCY.labels(endpoint=endpoint_label).observe(elapsed)
        except Exception:
            pass
        log.info(
            "request",
            extra={
                "request_id": rid,
                "method": method,
                "path": path,
                "endpoint": endpoint_label,
                "status": status,
                "latency_ms": int(elapsed * 1000),
                "client": request.client.host if request.client else None,
                "ua": request.headers.get("user-agent", "")[:120],
            },
        )


def _label(path: str) -> str:
    """Collapse /domain/{x}/dns -> /domain/:d/dns for low-cardinality metrics."""
    parts = path.split("/")
    if len(parts) >= 4 and parts[1] == "domain":
        parts[2] = ":d"
        return "/".join(parts)
    return path


def _validate(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="invalid domain")
    return domain


async def _cached(namespace: str, domain: str, fn):
    value, hit = await cached_call(namespace, domain, fn)
    if hit:
        CACHE_HITS.labels(namespace=namespace).inc()
    else:
        CACHE_MISSES.labels(namespace=namespace).inc()
    return value, hit


@app.get("/health")
async def health():
    redis_ok = False
    try:
        await get_redis().ping()
        redis_ok = True
    except Exception:
        pass
    return {"status": "ok", "service": "domain-intel", "version": "0.2.0", "redis": redis_ok}


@app.get("/metrics")
async def metrics():
    body, ctype = render_metrics()
    return Response(content=body, media_type=ctype)


@app.get("/lookup/{domain}")
async def lookup(domain: str):
    d = _validate(domain)
    t0 = time.time()

    async def dns_fn():
        return await with_timeout("dns", lambda: get_dns_records(d))
    async def ssl_fn():
        return await with_timeout("ssl", lambda: get_ssl_info(d))
    async def whois_fn():
        return await with_timeout("whois", lambda: get_whois(d))
    async def subs_fn():
        return await with_timeout("subdomains", lambda: get_subdomains(d))
    async def email_fn():
        return await with_timeout("email", lambda: get_email_security(d))

    results = await asyncio.gather(
        _cached("dns", d, dns_fn),
        _cached("ssl", d, ssl_fn),
        _cached("whois", d, whois_fn),
        _cached("subdomains", d, subs_fn),
        _cached("email", d, email_fn),
        return_exceptions=True,
    )

    def safe(x):
        if isinstance(x, Exception):
            return {"error": f"{type(x).__name__}: {x}"}, False
        return x

    dns_t, ssl_t, whois_t, subs_t, email_t = [safe(r) for r in results]

    return JSONResponse(
        {
            "domain": d,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "cached": {
                "dns": dns_t[1], "ssl": ssl_t[1], "whois": whois_t[1],
                "subdomains": subs_t[1], "email_security": email_t[1],
            },
            "dns": dns_t[0],
            "ssl": ssl_t[0],
            "whois": whois_t[0],
            "subdomains": subs_t[0],
            "email_security": email_t[0],
        }
    )


@app.get("/domain/{domain}/dns")
async def dns_only(domain: str):
    d = _validate(domain)
    val, _ = await _cached("dns", d, lambda: with_timeout("dns", lambda: get_dns_records(d)))
    return val


@app.get("/domain/{domain}/ssl")
async def ssl_only(domain: str):
    d = _validate(domain)
    val, _ = await _cached("ssl", d, lambda: with_timeout("ssl", lambda: get_ssl_info(d)))
    return val


@app.get("/domain/{domain}/whois")
async def whois_only(domain: str):
    d = _validate(domain)
    val, _ = await _cached("whois", d, lambda: with_timeout("whois", lambda: get_whois(d)))
    return val


@app.get("/domain/{domain}/subdomains")
async def subs_only(domain: str):
    d = _validate(domain)
    val, _ = await _cached("subdomains", d, lambda: with_timeout("subdomains", lambda: get_subdomains(d)))
    return val


@app.get("/domain/{domain}/email-security")
async def email_only(domain: str):
    d = _validate(domain)
    val, _ = await _cached("email", d, lambda: with_timeout("email", lambda: get_email_security(d)))
    return val

# ---------- Sprint G: public demo endpoint ----------
import datetime as _dt
DEMO_DAILY_LIMIT = 5

def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

@app.get("/demo/{domain}")
async def demo_lookup(domain: str, request: Request):
    """Public demo: rate-limited 5 req/IP/day, no auth."""
    d = _validate(domain)
    ip = _client_ip(request)
    today = _dt.datetime.utcnow().strftime("%Y-%m-%d")
    rl_key = f"demo:rl:{ip}:{today}"
    redis = get_redis()
    try:
        count = await redis.incr(rl_key)
        if count == 1:
            await redis.expire(rl_key, 86400)
    except Exception as e:
        log.warning("demo_rl_err err=%s", e)
        count = 1
    if count > DEMO_DAILY_LIMIT:
        ttl = 86400
        try:
            ttl = int(await redis.ttl(rl_key))
        except Exception:
            pass
        return JSONResponse(
            status_code=429,
            content={
                "error": "demo_rate_limit_exceeded",
                "message": f"Demo limit is {DEMO_DAILY_LIMIT} req/IP/day. Subscribe on RapidAPI for full access.",
                "retry_after_seconds": ttl,
                "subscribe_url": "https://rapidapi.com/search/domain-intelligence",
            },
            headers={"Retry-After": str(ttl)},
        )
    dns_t = await _cached("dns", d, lambda: with_timeout("dns", lambda: get_dns_records(d)))
    ssl_t = await _cached("ssl", d, lambda: with_timeout("ssl", lambda: get_ssl_info(d)))
    whois_t = await _cached("whois", d, lambda: with_timeout("whois", lambda: get_whois(d)))
    subs_t = await _cached("subdomains", d, lambda: with_timeout("subdomains", lambda: get_subdomains(d)))
    email_t = await _cached("email", d, lambda: with_timeout("email", lambda: get_email_security(d)))
    return {
        "domain": d,
        "demo_meta": {
            "requests_used_today": count,
            "daily_limit": DEMO_DAILY_LIMIT,
            "requests_remaining": max(0, DEMO_DAILY_LIMIT - count),
            "note": "Public demo. Subscribe on RapidAPI for more free usage.",
        },
        "dns": dns_t[0],
        "ssl": ssl_t[0],
        "whois": whois_t[0],
        "subdomains": subs_t[0],
        "email_security": email_t[0],
    }
