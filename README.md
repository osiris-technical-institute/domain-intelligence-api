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
| `GET` | `/domain/{d}/dns` | A, AAAA, MX, TXT, NS, CNAME, SOA |
| `GET` | `/domain/{d}/whois` | Registration data via RDAP, with port-43 WHOIS fallback |
| `GET` | `/domain/{d}/ssl` | Live TLS handshake — issuer, validity window, SAN list, key strength |
| `GET` | `/domain/{d}/subdomains` | crt.sh + certspotter + hackertarget concurrent enum, DNS bruteforce fallback |
| `GET` | `/domain/{d}/email-security` | SPF + DMARC presence and records. DKIM stub only (selector-required). |

All endpoints accept the bare hostname as a path parameter (no scheme, no trailing slash). Punycode-encoded IDN domains are supported.

---

## Why it's resilient

- **WHOIS:** RDAP via `rdap.org` → IANA bootstrap → legacy port-43, every step under an `asyncio.wait_for` timeout. The endpoint reports which source returned the data via a `_source` field.
- **Subdomains:** crt.sh + certspotter + hackertarget run concurrently. If all CT log sources fail, the endpoint falls back to a DNS bruteforce wordlist. Whatever succeeded is returned, with a `warnings[]` field naming what didn't.
- **SSL:** Direct TLS handshake against the host — no third-party scanner, no rate limit, accurate certificate chain.
- **All upstream calls** are timeout-bounded (DNS 5s, WHOIS 8s, SSL 8s, subdomains 10s, email 6s). The aggregate `/lookup` endpoint completes in ~3-5s uncached, ~50ms cached.

## Caching

Redis-backed response cache with per-endpoint TTLs:

| Endpoint | TTL |
|----------|-----|
| DNS | 5 min |
| WHOIS | 1 hour |
| SSL | 6 hours |
| Subdomains | 1 hour |
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

The included [`domain-intel.service`](domain-intel.service) is a working systemd unit that mirrors the production deployment.

## Repo layout

```
app/                  FastAPI service code
  main.py             Routes, middleware, app wiring
  cache.py            Redis cache layer
  dns_lookup.py       DNS resolver
  whois_lookup.py     RDAP chain + port-43 fallback
  ssl_lookup.py       Live TLS handshake
  subdomains.py       crt.sh + certspotter + hackertarget + DNS bruteforce
  email_security.py   SPF + DMARC; DKIM stub
  metrics.py          Prometheus exporter
  logging_config.py   Structured JSON logging
  timeouts.py         asyncio.wait_for helpers
rapidapi/
  openapi.json        OpenAPI 3.0 spec
  terms.md            Terms of use
landing.html          Public landing page (served at oti-labs.com/domain-intelligence-api)
domain-intel.service  systemd unit
requirements.txt      Python deps
```

## Terms of use

[`rapidapi/terms.md`](rapidapi/terms.md)

## License

[MIT](LICENSE) — Copyright (c) 2026 Osiris Technical Institute.

---

Built and maintained by [Osiris Technical Institute](https://oti-labs.com).
