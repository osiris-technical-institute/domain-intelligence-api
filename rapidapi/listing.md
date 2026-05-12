# Domain Intelligence API — RapidAPI Listing Package

## Listing Metadata

| Field | Value |
|---|---|
| **API Name** | Domain Intelligence API |
| **Short Tagline** | DNS · SSL · WHOIS · Subdomains · Email Security — one domain, one call |
| **Category** | Data / Cybersecurity / DNS |
| **Tags** | dns, ssl, whois, domain, subdomain, email-security, spf, dmarc, cybersecurity, threat-intelligence, domain-lookup, certificate |
| **Visibility** | Public |
| **Base URL** | https://87-99-152-31.sslip.io |

## Long Description

Domain Intelligence API gives you a complete picture of any domain in a single API call — or drill into individual data layers when you only need one thing.

**What you get:**
- 🔍 **DNS Records** — A, AAAA, MX, TXT, NS, CNAME, SOA
- 🔒 **SSL/TLS Certificate** — issuer, validity dates, SANs, expiry countdown
- 📋 **WHOIS / RDAP** — registrar, creation/expiry dates, registrant info
- 🌐 **Subdomains** — enumerated via Certificate Transparency logs (crt.sh), zero brute-force
- 📧 **Email Security** — SPF, DKIM (common selectors), DMARC, BIMI, MTA-STS
- 🗺️ **ASN / Network** — autonomous system number, org, and BGP prefix

**Use cases:**
- Security tools & threat intelligence platforms
- Lead enrichment pipelines (verify domain ownership, age, MX)
- Phishing / fraud detection (check SPF/DMARC health)
- Compliance & due-diligence automation
- SaaS onboarding (validate customer domains)
- Competitive intelligence (track competitor subdomains)
- DevOps / infrastructure auditing

**Why choose this API:**
- ✅ Sub-second responses on cached lookups
- ✅ Clean, consistent JSON — no HTML scraping noise
- ✅ Aggregate endpoint returns everything at once
- ✅ Individual endpoints for bandwidth-efficient partial lookups
- ✅ No login, no OAuth — just your RapidAPI key

---

## Pricing Tiers

| Tier | Price/mo | Requests/mo | Rate Limit | Notes |
|---|---|---|---|---|
| **BASIC** (Free) | $0 | 100 | 5 req/min | Get started, no CC required |
| **PRO** | $9 | 5,000 | 30 req/min | Hobbyists & small projects |
| **BUSINESS** | $29 | 25,000 | 60 req/min | Production integrations |
| **ENTERPRISE** | $79 | 100,000 | 120 req/min | High-volume / commercial use |

Overage: $0.002 per additional request (all paid tiers)

---

## Endpoints Summary

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| GET | /health | No | Service health check |
| GET | /lookup?domain={d} | Yes | Full aggregate lookup |
| GET | /domain/{d}/dns | Yes | DNS records only |
| GET | /domain/{d}/ssl | Yes | SSL certificate details |
| GET | /domain/{d}/whois | Yes | WHOIS/RDAP data |
| GET | /domain/{d}/subdomains | Yes | CT-log subdomain enum |
| GET | /domain/{d}/email-security | Yes | Email security posture |

---

## RapidAPI Submission Checklist

- [ ] Provider account created (requires PayPal/Payoneer)
- [ ] Base URL set to https://87-99-152-31.sslip.io
- [ ] Auth header: X-RapidAPI-Proxy-Secret (already wired in service)
- [ ] OpenAPI spec uploaded: openapi.json (this directory)
- [ ] Pricing tiers configured (see table above)
- [ ] Long description pasted
- [ ] Test endpoint verified from RapidAPI playground
- [ ] Category: Data > Cybersecurity
- [ ] Tags added (see Listing Metadata above)
