"""HTML report endpoint — polished single-page domain intelligence report.

Designed for SEO indexing: each /report/{domain} URL returns a static-looking
HTML page suitable for search engines, with the same underlying data as
/lookup/{domain} but rendered for human consumption.
"""
import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.dns_lookup import get_dns_records
from app.ssl_lookup import get_ssl_info
from app.whois_lookup import get_whois
from app.subdomains import get_subdomains
from app.email_security import get_email_security
from app.cache import cached_call, get_client as get_redis
from app.timeouts import with_timeout
from app.seed_domains import SITEMAP_DOMAINS

log = logging.getLogger("domain-intel")

TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

REPORT_HTML_TTL = 86400  # 24h Redis cache for the rendered HTML page


def _related_for(domain: str, n: int = 8) -> list:
    """Deterministic rotation of sibling domains for the Related Reports section.

    Same input domain always returns the same N sibling links (good for SEO
    crawl stability) but different domains see different subsets (so the link
    graph is varied across reports rather than every report linking to the
    same 8 hub pages).
    """
    candidates = [d for d in SITEMAP_DOMAINS if d != domain]
    if not candidates:
        return []
    offset = sum(ord(c) for c in domain) % len(candidates)
    return (candidates[offset:] + candidates[:offset])[:n]


async def _gather_data(domain: str) -> dict:
    """Fetch all five categories in parallel using the existing data-layer cache."""

    async def safe(ns: str, fn):
        try:
            val, _ = await cached_call(ns, domain, lambda: with_timeout(ns, fn))
            return val
        except Exception as e:
            log.warning("report_gather_err ns=%s domain=%s err=%s", ns, domain, e)
            return {"error": f"{type(e).__name__}: {e}"}

    dns_t, ssl_t, whois_t, subs_t, email_t = await asyncio.gather(
        safe("dns", lambda: get_dns_records(domain)),
        safe("ssl", lambda: get_ssl_info(domain)),
        safe("whois", lambda: get_whois(domain)),
        safe("subdomains", lambda: get_subdomains(domain)),
        safe("email", lambda: get_email_security(domain)),
    )
    return {
        "dns": dns_t,
        "ssl": ssl_t,
        "whois": whois_t,
        "subdomains": subs_t,
        "email_security": email_t,
    }


def _compute_stats(data: dict) -> dict:
    """Derive the four hero-stat values from the raw data dict."""
    # DNS record types found
    dns_types = 0
    dns_v = data.get("dns", {})
    if isinstance(dns_v, dict) and "error" not in dns_v:
        dns_types = sum(1 for v in dns_v.values() if v)

    # SSL days remaining + status class
    ssl_days = None
    ssl_class = "muted"
    ssl_v = data.get("ssl", {})
    if isinstance(ssl_v, dict) and "error" not in ssl_v:
        ssl_days = ssl_v.get("days_until_expiry")
        if isinstance(ssl_days, (int, float)):
            if ssl_days > 30:
                ssl_class = "ok"
            elif ssl_days > 7:
                ssl_class = "warn"
            else:
                ssl_class = "danger"

    # Subdomain count
    sub_count = 0
    subs_v = data.get("subdomains", {})
    if isinstance(subs_v, dict) and "error" not in subs_v:
        sub_count = subs_v.get("count", 0) or 0

    # Email security: SPF + DMARC + DKIM presence
    email_present = []
    es_v = data.get("email_security", {})
    if isinstance(es_v, dict) and "error" not in es_v:
        if (es_v.get("spf") or {}).get("present"):
            email_present.append("SPF")
        if (es_v.get("dmarc") or {}).get("present"):
            email_present.append("DMARC")
        if (es_v.get("dkim") or {}).get("found"):
            email_present.append("DKIM")

    if len(email_present) == 3:
        # Short label so it fits the small hero-stat box
        email_label = "All 3"
    elif email_present:
        email_label = " + ".join(email_present)
    else:
        email_label = "—"

    return {
        "dns_types": dns_types,
        "ssl_days": ssl_days,
        "ssl_class": ssl_class,
        "sub_count": sub_count,
        "email_count": len(email_present),
        "email_label": email_label,
    }


def _any_errors(data: dict) -> bool:
    """Return True if any of the five data sections is an error-shaped dict."""
    for v in data.values():
        if isinstance(v, dict) and "error" in v:
            return True
    return False


async def render_report(domain: str) -> tuple[str, bool]:
    """Render the report HTML for a domain (uncached page-level).

    Returns (html, has_errors). has_errors=True if any of the five upstream
    data sections returned an error; callers can use this to skip caching.
    """
    data = await _gather_data(domain)
    stats = _compute_stats(data)
    related = _related_for(domain, n=8)
    template = _env.get_template("report.html")
    now_utc = datetime.now(timezone.utc)
    generated_at = now_utc.strftime("%Y-%m-%d %H:%M UTC")
    generated_at_iso = now_utc.replace(microsecond=0).isoformat()  # e.g. 2026-05-28T19:55:00+00:00 — required by schema.org
    html = template.render(
        domain=domain,
        data=data,
        stats=stats,
        related=related,
        generated_at=generated_at,
        generated_at_iso=generated_at_iso,
    )
    return html, _any_errors(data)


async def render_report_cached(domain: str, force_refresh: bool = False) -> str:
    """Render the report, with a 24h page-level Redis cache.

    The underlying data fetchers also have their own per-namespace cache
    (DNS 5min, WHOIS 1h, SSL 6h, etc.); this is an additional page-level
    cache so we can serve crawlers in <100ms instead of waiting on data
    fetch even when the data layer is hot.

    If force_refresh=True, all caches (HTML + per-namespace except dns) are
    invalidated before re-fetching. Used by the ?refresh=1 escape hatch when
    upstream sources have timed out and locked the page in a failed state.

    The rendered HTML is also NOT cached when any namespace returned an error,
    so a visitor hitting a partially-failed page during normal operation gets
    auto-retry on the next request without waiting 24h for the HTML TTL.
    """
    from app.cache import invalidate_all
    redis = get_redis()
    cache_key = f"report:html:{domain}"

    if force_refresh:
        # Clear per-namespace caches so the data layer re-fetches fresh.
        # dns is excluded — 5min TTL means it's almost always already expired.
        await invalidate_all(domain, ["whois", "ssl", "subdomains", "email"])
        try:
            await redis.delete(cache_key)
        except Exception as e:
            log.warning("report_cache_del_err domain=%s err=%s", domain, e)
    else:
        try:
            cached = await redis.get(cache_key)
            if cached:
                if isinstance(cached, bytes):
                    return cached.decode("utf-8")
                return cached
        except Exception as e:
            log.warning("report_cache_get_err domain=%s err=%s", domain, e)

    html, has_errors = await render_report(domain)

    if not has_errors:
        try:
            await redis.set(cache_key, html, ex=REPORT_HTML_TTL)
        except Exception as e:
            log.warning("report_cache_set_err domain=%s err=%s", domain, e)
    else:
        log.info("report_html_uncached_due_to_errors domain=%s", domain)

    return html


async def render_reports_index() -> str:
    """Render the /reports directory page (uncached). Lists all SITEMAP_DOMAINS grouped by category."""
    from app.seed_domains import CATEGORIES, SITEMAP_DOMAINS, category_slug
    template = _env.get_template("reports_index.html")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slugs = {cat: category_slug(cat) for cat in CATEGORIES}
    return template.render(
        categorized=CATEGORIES,
        categories=list(CATEGORIES.keys()),
        slugs=slugs,
        total=len(SITEMAP_DOMAINS),
        generated_at=generated_at,
    )


async def render_reports_index_cached() -> str:
    """Render the /reports directory with a 24h Redis cache (same TTL as per-report HTML)."""
    redis = get_redis()
    cache_key = "report:html:_index"
    try:
        cached = await redis.get(cache_key)
        if cached:
            if isinstance(cached, bytes):
                return cached.decode("utf-8")
            return cached
    except Exception as e:
        log.warning("reports_index_cache_get_err err=%s", e)

    html = await render_reports_index()

    try:
        await redis.set(cache_key, html, ex=REPORT_HTML_TTL)
    except Exception as e:
        log.warning("reports_index_cache_set_err err=%s", e)

    return html
