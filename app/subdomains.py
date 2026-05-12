"""Subdomain discovery via Certificate Transparency + DNS bruteforce fallback.

Sources queried concurrently (asyncio.gather):
  1. crt.sh          - Sectigo CT log aggregator, largest free dataset
  2. certspotter     - SSLMate CT mirror, complementary coverage
  3. hackertarget    - passive DNS hostsearch (rate-limited free tier)
  4. DNS bruteforce  - small wordlist via dnspython async resolver
                       (only activated when ALL CT sources fail)

At least one source succeeding = HTTP 200 with results + warnings list.
All sources failing = HTTP 200 with error key and empty subdomains list
(the route layer can convert to 502 if desired, but graceful is better).

Response shape (backward-compatible):
  count, returned, subdomains   <- same as before
  sources_used                  <- list of source result strings
  warnings                      <- list of non-fatal issues
"""
import asyncio
import logging
from typing import Optional

import httpx

log = logging.getLogger("domain-intel.subdomains")

CRT_TIMEOUT         = 3.0
CERTSPOTTER_TIMEOUT = 6.0
HACKERTARGET_TIMEOUT = 4.0
DNS_BRUTE_TIMEOUT   = 1.5   # per name
DNS_BRUTE_CONCURRENCY = 25

_BRUTE_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "pop3", "imap",
    "ns1", "ns2", "ns3", "dns1", "dns2", "mx", "mx1", "mx2",
    "admin", "administrator", "blog", "dev", "test", "staging", "stage",
    "api", "app", "apps", "cdn", "static", "assets", "media",
    "m", "mobile", "secure", "vpn", "remote", "portal",
    "support", "help", "docs", "status", "shop", "store",
    "beta", "demo", "old", "new", "my", "webdisk", "cpanel", "whm",
    "autodiscover", "autoconfig", "mail2", "email",
]


def _add(out: set, candidate: str, domain: str) -> None:
    """Validate and add a candidate hostname to the result set."""
    if not candidate:
        return
    n = candidate.strip().lower().rstrip(".")
    if not n or n.startswith("*"):
        return
    if "@" in n or " " in n:
        return
    if n != domain and not n.endswith("." + domain):
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
    """Query hackertarget hostsearch (passive DNS, free tier)."""
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


async def _resolve_one(resolver, name: str) -> Optional[str]:
    """Try to resolve a single hostname; return name on success, None on NXDOMAIN/timeout."""
    try:
        await resolver.resolve(name, "A")
        return name
    except Exception:
        pass
    try:
        await resolver.resolve(name, "AAAA")
        return name
    except Exception:
        pass
    try:
        await resolver.resolve(name, "CNAME")
        return name
    except Exception:
        return None


async def _src_dns_bruteforce(domain: str, out: set) -> str:
    """Async DNS bruteforce against a small common-subdomain wordlist."""
    try:
        import dns.asyncresolver
    except ImportError:
        return "dns-brute skipped: dnspython not installed"

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = DNS_BRUTE_TIMEOUT
    resolver.lifetime = DNS_BRUTE_TIMEOUT

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


async def get_subdomains(domain: str, limit: int = 1000) -> dict:
    """Discover subdomains for *domain* via concurrent multi-source aggregation."""
    domain = domain.strip().lower().rstrip(".")
    found: set = set()
    warnings: list = []
    sources_used: list = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=3.0),
        follow_redirects=True,
    ) as client:
        # Run CT sources concurrently
        ct_results = await asyncio.gather(
            _src_crtsh(client, domain, found),
            _src_certspotter(client, domain, found),
            _src_hackertarget(client, domain, found),
            return_exceptions=True,
        )

    for res in ct_results:
        if isinstance(res, Exception):
            msg = f"{type(res).__name__}: {res}"
            warnings.append(msg)
            sources_used.append(msg)
        else:
            sources_used.append(res)
            if "ok" not in res:
                warnings.append(res)

    ct_ok = any("ok" in s for s in sources_used if isinstance(s, str))

    # DNS bruteforce: only if ALL CT sources failed (saves time when CT works)
    if not ct_ok:
        log.warning("subdomains_ct_all_failed domain=%s trying_dns_brute", domain)
        brute_result = await _src_dns_bruteforce(domain, found)
        sources_used.append(brute_result)
        if "ok" not in brute_result:
            warnings.append(brute_result)
        else:
            ct_ok = True   # dns brute succeeded

    if not ct_ok and not found:
        return {
            "error": "all subdomain sources failed",
            "domain": domain,
            "sources_used": sources_used,
            "subdomains": [],
            "count": 0,
            "returned": 0,
        }

    subdomains = sorted(found)
    returned = subdomains[:limit]

    result = {
        "count":       len(found),
        "returned":    len(returned),
        "subdomains":  returned,
        "sources_used": sources_used,
    }
    if warnings:
        result["warnings"] = warnings
    return result
