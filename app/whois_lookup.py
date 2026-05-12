"""RDAP/WHOIS lookup with multi-source fallback chain.

Chain (per request, first success wins):
  1. rdap.org universal redirect  (handles most TLDs, fast)
  2. IANA RDAP bootstrap registry -> authoritative TLD RDAP server
  3. Hardcoded fallback endpoints  for ~22 common TLDs

Each step has its own short timeout so a single hanging source
cannot block the whole request.  IANA bootstrap is cached 24h.
"""
import time
import logging
from typing import Optional

import httpx

log = logging.getLogger("domain-intel.whois")

RDAP_ORG_TIMEOUT     = 4.0
IANA_BOOTSTRAP_TIMEOUT = 3.0
IANA_BOOTSTRAP_CACHE_TTL = 86400
DIRECT_RDAP_TIMEOUT  = 4.0

_bootstrap_cache: dict = {"data": None, "fetched_at": 0.0}

_FALLBACK_RDAP_SERVERS = {
    "com":    "https://rdap.verisign.com/com/v1/",
    "net":    "https://rdap.verisign.com/net/v1/",
    "org":    "https://rdap.publicinterestregistry.org/rdap/",
    "info":   "https://rdap.identitydigital.services/rdap/",
    "biz":    "https://rdap.nic.biz/",
    "io":     "https://rdap.identitydigital.services/rdap/",
    "co":     "https://rdap.nic.co/",
    "ai":     "https://rdap.nic.ai/",
    "app":    "https://rdap.nic.google/",
    "dev":    "https://rdap.nic.google/",
    "xyz":    "https://rdap.centralnic.com/xyz/",
    "online": "https://rdap.centralnic.com/online/",
    "site":   "https://rdap.centralnic.com/site/",
    "tech":   "https://rdap.centralnic.com/tech/",
    "store":  "https://rdap.centralnic.com/store/",
    "me":     "https://rdap.nic.me/",
    "tv":     "https://rdap.verisign.com/tv/v1/",
    "cc":     "https://rdap.verisign.com/cc/v1/",
    "us":     "https://rdap.nic.us/",
    "uk":     "https://rdap.nominet.uk/uk/",
    "de":     "https://rdap.denic.de/",
    "eu":     "https://rdap.eu/",
}


def _parse_rdap(data: dict) -> dict:
    """Normalise a raw RDAP response dict into our flat output shape."""
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar: Optional[str] = None
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])
            if len(vcard) >= 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        registrar = item[3]
                        break
            if registrar:
                break
    return {
        "handle":      data.get("handle"),
        "ldhName":     data.get("ldhName"),
        "status":      data.get("status", []),
        "registrar":   registrar,
        "created":     events.get("registration"),
        "updated":     events.get("last changed"),
        "expires":     events.get("expiration"),
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
    }


async def _fetch_iana_bootstrap(client: httpx.AsyncClient) -> Optional[dict]:
    """Fetch (and in-process cache) the IANA RDAP DNS bootstrap registry."""
    now = time.time()
    if _bootstrap_cache["data"] and (now - _bootstrap_cache["fetched_at"]) < IANA_BOOTSTRAP_CACHE_TTL:
        return _bootstrap_cache["data"]
    try:
        r = await client.get(
            "https://data.iana.org/rdap/dns.json",
            timeout=IANA_BOOTSTRAP_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            _bootstrap_cache["data"] = data
            _bootstrap_cache["fetched_at"] = now
            return data
    except Exception as exc:
        log.warning("iana_bootstrap_failed err=%s", exc)
    return None


def _rdap_server_for_tld(bootstrap: dict, tld: str) -> Optional[str]:
    """Look up the authoritative RDAP base URL for a TLD from the bootstrap registry."""
    for entry in bootstrap.get("services", []):
        if not isinstance(entry, list) or len(entry) < 2:
            continue
        tlds, urls = entry[0], entry[1]
        if tld in tlds and urls:
            url = urls[0]
            return url if url.endswith("/") else url + "/"
    return None


async def _try_rdap_org(client: httpx.AsyncClient, domain: str):
    """Attempt lookup via rdap.org universal redirect service."""
    try:
        r = await client.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json"},
            timeout=RDAP_ORG_TIMEOUT,
            follow_redirects=True,
        )
        if r.status_code == 200:
            return r.json(), None
        return None, f"rdap.org status {r.status_code}"
    except Exception as exc:
        return None, f"rdap.org {type(exc).__name__}: {exc}"


async def _try_direct_rdap(client: httpx.AsyncClient, base_url: str, domain: str):
    """Attempt lookup against a known RDAP base URL."""
    url = f"{base_url}domain/{domain}"
    try:
        r = await client.get(
            url,
            headers={"Accept": "application/rdap+json"},
            timeout=DIRECT_RDAP_TIMEOUT,
            follow_redirects=True,
        )
        if r.status_code == 200:
            return r.json(), None
        return None, f"direct status {r.status_code}"
    except Exception as exc:
        return None, f"direct {type(exc).__name__}: {exc}"


async def get_whois(domain: str) -> dict:
    """Return WHOIS/RDAP data for *domain* using a 3-tier fallback chain."""
    domain = domain.strip().lower().rstrip(".")
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    attempts: list = []

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(12.0, connect=3.0),
        headers={"User-Agent": "domain-intel/0.3 (+rdap)"},
    ) as client:

        # --- Tier 1: rdap.org ---
        data, err = await _try_rdap_org(client, domain)
        attempts.append(f"rdap.org: {'ok' if data else err}")
        if data:
            out = _parse_rdap(data)
            out["_source"] = "rdap.org"
            return out

        # --- Tier 2: IANA bootstrap -> direct RDAP ---
        bootstrap = await _fetch_iana_bootstrap(client)
        if bootstrap:
            base = _rdap_server_for_tld(bootstrap, tld)
            if base:
                data, err = await _try_direct_rdap(client, base, domain)
                attempts.append(f"iana[{tld}]: {'ok' if data else err}")
                if data:
                    out = _parse_rdap(data)
                    out["_source"] = f"iana-bootstrap:{base}"
                    return out
            else:
                attempts.append(f"iana[{tld}]: tld not in registry")
        else:
            attempts.append("iana: bootstrap fetch failed")

        # --- Tier 3: hardcoded fallback for common TLDs ---
        fallback = _FALLBACK_RDAP_SERVERS.get(tld)
        if fallback:
            data, err = await _try_direct_rdap(client, fallback, domain)
            attempts.append(f"fallback[{tld}]: {'ok' if data else err}")
            if data:
                out = _parse_rdap(data)
                out["_source"] = f"fallback:{fallback}"
                return out
        else:
            attempts.append(f"fallback[{tld}]: no hardcoded entry")

    log.warning("whois_all_sources_failed domain=%s attempts=%s", domain, attempts)
    return {
        "error":    "all RDAP sources failed",
        "domain":   domain,
        "attempts": attempts,
    }
