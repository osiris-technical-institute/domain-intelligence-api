"""Timeout wrapper for external lookups with metrics."""
import asyncio
import logging
from typing import Any, Awaitable, Callable

from app.metrics import LOOKUP_TIMEOUTS, LOOKUP_ERRORS

log = logging.getLogger("domain-intel.lookup")

# Per-source timeouts in seconds
TIMEOUTS = {
    "dns": 5.0,
    "whois": 8.0,
    "ssl": 8.0,
    "subdomains": 10.0,
    "email": 6.0,
}


async def with_timeout(source: str, coro_fn: Callable[[], Awaitable[Any]], fallback: Any = None) -> Any:
    timeout = TIMEOUTS.get(source, 8.0)
    try:
        return await asyncio.wait_for(coro_fn(), timeout=timeout)
    except asyncio.TimeoutError:
        LOOKUP_TIMEOUTS.labels(source=source).inc()
        log.warning("lookup_timeout source=%s timeout=%s", source, timeout)
        if fallback is not None:
            return fallback
        return {"error": "timeout", "source": source, "timeout_seconds": timeout}
    except Exception as e:
        LOOKUP_ERRORS.labels(source=source).inc()
        log.warning("lookup_error source=%s err=%s", source, e)
        if fallback is not None:
            return fallback
        return {"error": f"{type(e).__name__}: {e}", "source": source}
