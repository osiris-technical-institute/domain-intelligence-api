"""Redis cache helper with per-endpoint TTLs."""
import json
import os
import hashlib
import logging
from typing import Any, Optional, Callable, Awaitable

import redis.asyncio as aioredis

log = logging.getLogger("domain-intel.cache")

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

# TTLs in seconds per endpoint type
TTL = {
    "dns": 300,           # 5 min
    "whois": 3600,        # 1 hr
    "ssl": 21600,         # 6 hr
    "subdomains": 3600,   # 1 hr
    "email": 3600,        # 1 hr (mostly DNS-derived)
    "aggregate": 300,     # 5 min (limited by shortest component)
}

_client: Optional[aioredis.Redis] = None


def get_client() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2, socket_connect_timeout=2)
    return _client


def _key(namespace: str, domain: str) -> str:
    h = hashlib.sha1(domain.encode()).hexdigest()[:16]
    return f"di:{namespace}:{h}"


async def get_cached(namespace: str, domain: str) -> Optional[Any]:
    try:
        c = get_client()
        raw = await c.get(_key(namespace, domain))
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as e:
        log.warning("cache_get_failed ns=%s err=%s", namespace, e)
        return None


async def set_cached(namespace: str, domain: str, value: Any) -> None:
    try:
        c = get_client()
        ttl = TTL.get(namespace, 300)
        await c.set(_key(namespace, domain), json.dumps(value, default=str), ex=ttl)
    except Exception as e:
        log.warning("cache_set_failed ns=%s err=%s", namespace, e)


async def cached_call(namespace: str, domain: str, fn: Callable[[], Awaitable[Any]]) -> tuple[Any, bool]:
    """Return (value, hit_bool). Calls fn() on miss."""
    cached = await get_cached(namespace, domain)
    if cached is not None:
        return cached, True
    value = await fn()
    await set_cached(namespace, domain, value)
    return value, False
