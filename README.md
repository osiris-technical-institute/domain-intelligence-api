# Domain Intelligence API

[![Live](https://img.shields.io/badge/API-live-brightgreen)](https://oti-labs.com/domain-intelligence-api)
[![RapidAPI](https://img.shields.io/badge/RapidAPI-listed-2196f3)](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](#self-hosting)

> Aggregate domain reconnaissance — **DNS, WHOIS/RDAP, SSL/TLS, subdomains, and email security posture** — in a single REST call.

A FastAPI service that pulls five categories of public domain intelligence concurrently and returns clean, predictable JSON. Built for security teams, threat-intel enrichment pipelines, and domain monitoring SaaS. Sub-second responses on cache hits, no LLMs in the request path.

- **Live API:** <https://oti-labs.com/domain-intelligence-api>
- **Pricing & API key:** [RapidAPI listing](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api)
- **OpenAPI spec:** [`rapidapi/openapi.json`](rapidapi/openapi.json)

---

## Try it (no key needed)

The landing page exposes a public demo, rate-limited to 5 requests per IP per day:

```bash
curl -s https://oti-labs.com/demo/example.com | jq
```

## Production usage (via RapidAPI)

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
        "X-RapidAPI-Key":  "YOUR_RAPIDAPI_KEY",
    },
    timeout=15,
)
data = r.json()
print(data["ssl"]["issuer"], data["whois"]["registrar"])
```

```javascript
// Node 18+ has built-in fetch — no import needed
const res = await fetch(
  "https://domain-intelligence-api.p.rapidapi.com/lookup/example.com",
  { headers: {
      "X-RapidAPI-Host": "domain-intelligence-api.p.rapidapi.com",
      "X-RapidAPI-Key":  "YOUR_RAPIDAPI_KEY",
  }},
);
const data = await res.json();
```

Full OpenAPI spec: [`rapidapi/openapi.json`](rapidapi/openapi.json).

---

## Endpoints

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/lookup/{domain}` | **Aggregate** — DNS + WHOIS + SSL + subdomains + email-security in one parallel call. The endpoint most users want. |
| `GET` | `/domain/{d}/dns` | A, AAAA, MX, TXT, NS, CAA, SOA |
| `GET` | `/domain/{d}/whois` | Registration data via a 4-tier fallback chain (RDAP → port-43 WHOIS) |
| `GET` | `/domain/{d}/ssl` | Live TLS handshake — issuer, validity window, SAN list, key strength |
| `GET` | `/domain/{d}/subdomains` | Multi-source enumeration — CT logs + passive DNS (crt.sh, certspotter, hackertarget, rapiddns, VirusTotal) + always-on DNS bruteforce with wildcard filtering, plus optional subfinder background enrichment |
| `GET` | `/domain/{d}/email-security` | SPF + DMARC presence/records. DKIM keys auto-probed across ~29 common selectors (Google, Microsoft 365, Mailchimp, SendGrid, etc.). |

All endpoints accept the bare hostname as a path parameter (no scheme, no trailing slash). Punycode-encoded IDN domains are supported.

---

## Why it's resilient

- **WHOIS — 4-tier fallback chain:**
  1. `rdap.org` universal redirect (~4s timeout)
  2. IANA RDAP bootstrap → authoritative TLD-specific RDAP server (bootstrap cached 24h)
  3. Hardcoded RDAP base URLs for 22 common TLDs (.com, .net, .org, .info, .io, .ai, .app, .dev, .xyz, .me, .tv, .uk, .de, .eu, etc.) for resilience when the bootstrap is slow
  4. **Port-43 socket WHOIS** with 50+ TLD-specific servers (all gTLDs plus 35+ ccTLDs incl. .fr, .nl, .au, .ca, .jp, .ru, .cn, .br, .es, .it, .ch, .at, .pl, .se, .no, .fi, .dk, .be, .ie, .nz, .za, .in, .kr, .sg, and more). For any TLD not pre-mapped, the client queries `whois.iana.org` and follows the `refer:` line.

  Every tier has its own short timeout. The response includes a `_source` field naming which tier succeeded (e.g. `"rdap.org"`, `"port43:whois.verisign-grs.com"`).

- **Subdomains — multi-source aggregation, structural floor, wildcard filtering, background enrichment:**
  - **Direct sources** run concurrently for a fast cold response: crt.sh + certspotter (Certificate Transparency logs), hackertarget + rapiddns + VirusTotal v3 (passive DNS; VT paginated to ~120 results). Each has a split connect/read timeout so an unreachable host fails fast (2.5s connect) instead of gating the batch.
  - **Always-on DNS bruteforce** against a curated 773-word wordlist, rotated across 8 anycast resolvers (Cloudflare, Google, Quad9, OpenDNS) at 100 concurrent / 1s per name, resolving A + CNAME. Runs *every time* — so the response is never empty regardless of upstream status.
  - **Wildcard detection:** before brute-forcing, three random labels are resolved; if the zone answers them it has a `*.domain` wildcard and the brute-force is skipped (it would otherwise return the entire wordlist as false positives). CT and passive-DNS sources still return the *real* subdomains.
  - **Optional subfinder enrichment:** if the [`subfinder`](https://github.com/projectdiscovery/subfinder) binary is installed, it runs as a background source aggregating 20+ more passive sources for comprehensive coverage; it gracefully no-ops (`subfinder skipped: not installed`) if absent.
  - **Fast-return + background enrichment:** reliable fast sources return within a ~3s soft deadline; slow stragglers (crt.sh, subfinder) keep running in the background and write the fuller result into the cache, so the next lookup of that domain is complete — *first lookup good, second lookup comprehensive*.
  - Results merged, deduplicated, sorted. The `sources_used` array reports per-source status (contributed / rate-limited / failed / skipped). `warnings` is coverage-aware (only populated when total found drops below 20 subdomains).

- **SSL:** Direct TLS handshake against the host — no third-party scanner, no rate limit, accurate certificate chain. 5s socket timeout.

- **All upstream calls** are timeout-bounded via `asyncio.wait_for` (DNS 5s, WHOIS 8s, SSL 8s, subdomains 10s, email 6s). The aggregate `/lookup` endpoint completes in ~1-5s uncached, ~50ms cached.

## Caching

Redis-backed response cache with per-endpoint TTLs:

| Endpoint | TTL |
|----------|-----|
| DNS | 5 min |
| WHOIS | 1 hour |
| SSL | 6 hours |
| Subdomains | 24 hours |
| Email security | 1 hour |

## Pricing

| Plan | Price | Quota | Rate limit |
|------|-------|-------|------------|
| **BASIC** | Free | 1,000 req/mo | 10 rpm |
| **PRO** | $9.99/mo | 50,000 req/mo | 60 rpm |
| **ULTRA** | $39.99/mo | 500,000 req/mo | 300 rpm |
| **MEGA** | $149.99/mo | 5,000,000 req/mo | 1,000 rpm |

Subscribe via the [RapidAPI pricing page](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api/pricing).

---

## Self-hosting

```bash
git clone https://github.com/osiris-technical-institute/domain-intelligence-api.git
cd domain-intelligence-api
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8001
```

The service expects Redis at `localhost:6379` (set `REDIS_URL` to override). For TLS termination behind a real domain, point Caddy or nginx at `127.0.0.1:8001`. To require an auth header, set `RAPIDAPI_PROXY_SECRET` and have your reverse proxy enforce `X-RapidAPI-Proxy-Secret` on inbound requests.

For the VirusTotal subdomain source, set `VT_API_KEY` in the environment (optional — it no-ops cleanly if absent). For **comprehensive** subdomain coverage, optionally install [`subfinder`](https://github.com/projectdiscovery/subfinder) on `PATH` (or point `SUBFINDER_BIN` at it); the service uses it as a background-enrichment source when present and skips it otherwise. The direct CT/passive-DNS sources + DNS bruteforce run regardless.

The included [`domain-intel.service`](domain-intel.service) is a working systemd unit that mirrors the production deployment.

## Repo layout

```
app/                  FastAPI service code
  main.py             Routes, middleware, app wiring
  cache.py            Redis cache layer
  dns_lookup.py       DNS resolver (A, AAAA, MX, TXT, NS, CAA, SOA)
  whois_lookup.py     4-tier WHOIS chain: rdap.org → IANA bootstrap → 22 hardcoded RDAP servers → port-43 socket WHOIS (50+ TLDs + IANA referral)
  ssl_lookup.py       Live TLS handshake
  subdomains.py       crt.sh, certspotter, hackertarget, rapiddns, VirusTotal, DNS bruteforce (773-word, wildcard detection) + optional subfinder background enrichment
  email_security.py   SPF + DMARC + DKIM (auto-probed across ~29 common selectors)
  report.py           SEO-indexable HTML report renderer (page-level cache, ?refresh=1 escape hatch)
  seed_domains.py     Curated sitemap domain list + prewarm set
  templates/          Jinja2 templates for the HTML report + reports index
  metrics.py          Prometheus exporter
  logging_config.py   Structured JSON logging
  timeouts.py         asyncio.wait_for helpers
rapidapi/
  openapi.json        OpenAPI 3.0 spec
  terms.md            Terms of use
domain-intel.service  systemd unit
requirements.txt      Python deps
```

## Terms of use

[`rapidapi/terms.md`](rapidapi/terms.md)

## License

[MIT](LICENSE) — Copyright (c) 2026 Osiris Technical Institute.

---

Built and maintained by [Osiris Technical Institute](https://oti-labs.com).



