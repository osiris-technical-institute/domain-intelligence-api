"""RDAP/WHOIS lookup with multi-source fallback chain.

Chain (per request, first success wins):
  1. rdap.org universal redirect  (handles most TLDs, fast)
  2. IANA RDAP bootstrap registry -> authoritative TLD RDAP server
  3. Hardcoded fallback endpoints  for ~22 common TLDs (direct RDAP)
  4. Port-43 socket WHOIS         for legacy/ccTLDs without RDAP, plus
                                  IANA referral lookup for unknown TLDs

Each step has its own short timeout so a single hanging source
cannot block the whole request.  IANA bootstrap is cached 24h.
"""
import asyncio
import time
import logging
import re
from typing import Optional

import httpx

log = logging.getLogger("domain-intel.whois")

RDAP_ORG_TIMEOUT     = 4.0
IANA_BOOTSTRAP_TIMEOUT = 3.0
IANA_BOOTSTRAP_CACHE_TTL = 86400
DIRECT_RDAP_TIMEOUT  = 4.0
PORT43_CONNECT_TIMEOUT = 3.0
PORT43_READ_TIMEOUT  = 5.0
PORT43_MAX_BYTES     = 65536

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

# Port-43 WHOIS servers per TLD. Sourced from IANA's published WHOIS server data
# (https://www.iana.org/domains/root/db/). Covers all the gTLDs we also have RDAP
# for (so we have a true fallback), plus the common ccTLDs that don't have RDAP yet.
_PORT43_SERVERS = {
    # gTLDs (RDAP exists too; port-43 is the final fallback)
    "com":    "whois.verisign-grs.com",
    "net":    "whois.verisign-grs.com",
    "org":    "whois.publicinterestregistry.org",
    "info":   "whois.afilias.net",
    "biz":    "whois.nic.biz",
    "io":     "whois.nic.io",
    "co":     "whois.nic.co",
    "ai":     "whois.nic.ai",
    "app":    "whois.nic.google",
    "dev":    "whois.nic.google",
    "xyz":    "whois.nic.xyz",
    "online": "whois.nic.online",
    "site":   "whois.nic.site",
    "tech":   "whois.nic.tech",
    "store":  "whois.nic.store",
    "me":     "whois.nic.me",
    "tv":     "whois.nic.tv",
    "cc":     "whois.nic.cc",
    "us":     "whois.nic.us",
    "uk":     "whois.nic.uk",
    "de":     "whois.denic.de",
    "eu":     "whois.eu",
    # ccTLDs commonly missing from RDAP coverage
    "fr":     "whois.nic.fr",
    "nl":     "whois.domain-registry.nl",
    "au":     "whois.auda.org.au",
    "ca":     "whois.cira.ca",
    "jp":     "whois.jprs.jp",
    "ru":     "whois.tcinet.ru",
    "cn":     "whois.cnnic.cn",
    "br":     "whois.registro.br",
    "es":     "whois.nic.es",
    "it":     "whois.nic.it",
    "ch":     "whois.nic.ch",
    "at":     "whois.nic.at",
    "pl":     "whois.dns.pl",
    "se":     "whois.iis.se",
    "no":     "whois.norid.no",
    "fi":     "whois.fi",
    "dk":     "whois.dk-hostmaster.dk",
    "be":     "whois.dns.be",
    "pt":     "whois.dns.pt",
    "ie":     "whois.weare.ie",
    "nz":     "whois.srs.net.nz",
    "za":     "whois.registry.net.za",
    "in":     "whois.registry.in",
    "kr":     "whois.kr",
    "sg":     "whois.sgnic.sg",
    "il":     "whois.isoc.org.il",
    "ar":     "whois.nic.ar",
    "tr":     "whois.nic.tr",
    "hu":     "whois.nic.hu",
    "cz":     "whois.nic.cz",
    "ro":     "whois.rotld.ro",
    "gr":     "whois.ics.forth.gr",
    "lv":     "whois.nic.lv",
    "lt":     "whois.domreg.lt",
    "ee":     "whois.tld.ee",
    "is":     "whois.isnic.is",
    "lu":     "whois.dns.lu",
    "li":     "whois.nic.li",
    # Special / restricted (often respond but with limited data)
    "edu":    "whois.educause.edu",
}

# Fallback when we have no entry for a TLD: ask IANA, parse its referral.
_PORT43_IANA = "whois.iana.org"


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


# --- Port-43 helpers ---

# Field-name aliases seen across registries. Order matters: first match wins.
_FIELD_ALIASES = {
    "registrar": (
        "registrar", "sponsoring registrar", "registrar name", "registrant",
        "organisation", "organization",
    ),
    "created": (
        "creation date", "created", "created on", "registered on", "registered",
        "domain registration date", "registration time", "created date",
        "domain create date",
    ),
    "updated": (
        "updated date", "updated", "last updated", "last-update", "modified",
        "changed", "last modified",
    ),
    "expires": (
        "expiration date", "registry expiry date", "registrar registration expiration date",
        "expires", "expires on", "expiry", "expire date", "expire",
        "paid-till", "valid until",
    ),
    "handle": (
        "registry domain id", "domain id", "roid",
    ),
}
_STATUS_ALIASES = ("domain status", "status")
_NAMESERVER_ALIASES = ("name server", "nserver", "nameserver", "name servers")
_WHOIS_REFERRAL = re.compile(r"^\s*(?:whois|refer)\s*:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


def _parse_port43(raw: str, domain: str) -> Optional[dict]:
    """Tolerant key/value parser for port-43 WHOIS text. Returns None on obvious miss."""
    if not raw or not raw.strip():
        return None
    lower = raw.lower()
    # Common "no match" indicators (registry-specific, kept short)
    miss_patterns = [
        "no match for", "not found", "no entries found", "no data found",
        "no such domain", "domain not found", "not registered",
    ]
    if any(pat in lower for pat in miss_patterns):
        return None

    out: dict = {
        "handle": None, "ldhName": domain, "status": [], "registrar": None,
        "created": None, "updated": None, "expires": None, "nameservers": [],
    }
    status_set: list = []
    ns_set: list = []

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(("%", "#", ">>>")):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        # Multi-value fields
        if key in _STATUS_ALIASES:
            # Strip trailing "https://icann.org/..." link present in some registries
            v = value.split(" https://", 1)[0].strip()
            if v and v not in status_set:
                status_set.append(v)
            continue
        if key in _NAMESERVER_ALIASES:
            v = value.split()[0].lower().rstrip(".")
            if v and v not in ns_set:
                ns_set.append(v)
            continue
        # Single-value fields (first match wins to honor registry's own ordering)
        for canonical, aliases in _FIELD_ALIASES.items():
            if key in aliases and out[canonical] is None:
                out[canonical] = value
                break

    out["status"] = status_set
    out["nameservers"] = ns_set
    # Return None if we got essentially nothing useful (likely a thin registrar response)
    if not any([out["registrar"], out["created"], out["expires"], out["nameservers"], out["status"]]):
        return None
    return out


async def _query_port43(server: str, query: str) -> Optional[str]:
    """Send `query\\r\\n` to `server:43`, read whole response, return decoded text."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43),
            timeout=PORT43_CONNECT_TIMEOUT,
        )
    except Exception as exc:
        log.warning("port43_connect_failed server=%s err=%s", server, exc)
        return None
    try:
        writer.write((query + "\r\n").encode("utf-8", "ignore"))
        await writer.drain()
        try:
            buf = await asyncio.wait_for(
                reader.read(PORT43_MAX_BYTES),
                timeout=PORT43_READ_TIMEOUT,
            )
        except asyncio.TimeoutError:
            log.warning("port43_read_timeout server=%s", server)
            return None
        # Best-effort decode, falling back to latin-1 for non-UTF8 ccTLD responses.
        for enc in ("utf-8", "latin-1"):
            try:
                return buf.decode(enc)
            except UnicodeDecodeError:
                continue
        return buf.decode("utf-8", "replace")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _resolve_port43_server(tld: str) -> tuple[Optional[str], str]:
    """Return (server, source_label) for a TLD's port-43 WHOIS server.

    First checks the static map; if absent, queries whois.iana.org for the TLD
    and parses the `refer:` / `whois:` line from its response.
    """
    if tld in _PORT43_SERVERS:
        return _PORT43_SERVERS[tld], "static"
    iana_resp = await _query_port43(_PORT43_IANA, tld)
    if iana_resp:
        m = _WHOIS_REFERRAL.search(iana_resp)
        if m:
            return m.group(1), "iana-referral"
    return None, "no-server"


async def _try_port43_whois(domain: str, tld: str) -> tuple[Optional[dict], str]:
    """Tier 4: port-43 socket WHOIS fallback. Returns (parsed_or_None, log_msg)."""
    server, source = await _resolve_port43_server(tld)
    if not server:
        return None, f"port43[{tld}]: no whois server"
    raw = await _query_port43(server, domain)
    if not raw:
        return None, f"port43[{tld}]: {server} no response"
    parsed = _parse_port43(raw, domain)
    if parsed is None:
        return None, f"port43[{tld}]: {server} parsed empty / no-match"
    parsed["_source"] = f"port43:{server}" + ("" if source == "static" else " (via iana-referral)")
    return parsed, f"port43[{tld}]: ok via {server}"


# --- RDAP helpers (unchanged) ---


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
    """Return WHOIS/RDAP data for *domain* using a 4-tier fallback chain.

    Tiers:
      1. rdap.org universal redirect (HTTPS)
      2. IANA RDAP bootstrap -> direct RDAP query (HTTPS)
      3. Hardcoded RDAP base for ~22 common TLDs (HTTPS)
      4. Port-43 socket WHOIS (TCP/43, IANA referral for unknown TLDs)
    """
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

    # --- Tier 4: port-43 socket WHOIS (outside the httpx client context) ---
    parsed, msg = await _try_port43_whois(domain, tld)
    attempts.append(msg)
    if parsed:
        return parsed

    log.warning("whois_all_sources_failed domain=%s attempts=%s", domain, attempts)
    return {
        "error":    "all RDAP and WHOIS sources failed",
        "domain":   domain,
        "attempts": attempts,
    }
