---
name: domain-due-diligence
description: Build a due-diligence profile of a domain from live registration, DNS, certificate, email and subdomain data. Use before buying a domain, paying or partnering with the company behind it, onboarding a vendor or supplier, or reviewing an acquisition target's web footprint, and when the user asks how established a domain is, when it expires, where it is hosted, or what public subdomains it has.
---

# Domain due diligence

Call `domain_lookup` once. If the user needs the complete subdomain picture, call it with `wait` set to true (it can take up to about 20 seconds). A section with an `error` field is unknown; say so rather than guessing.

## What to read in each section

**Registration (`whois`)**
- Age from `created`. Note `updated` if it is recent: it can mean a renewal, a transfer or a change of hands.
- Renewal risk from `expires`: flag anything within 60 days.
- `status`: `client transfer prohibited` and `client delete prohibited` are the normal registrar locks. `server hold` or `client hold` means suspended; `redemption period` or `pending delete` means the registration has lapsed.
- `registrar`: corporate brand-protection registrars (MarkMonitor, CSC, SafeNames, Com Laude and similar) usually mean an established organisation; retail registrars are normal for everyone else.
- Owner identity is not in the data: most WHOIS records are redacted. Never guess who owns the domain.

**Hosting and DNS (`dns`)**
- DNS provider from `NS` (for example `awsdns` → Amazon Route 53, `cloudflare.com` → Cloudflare).
- `A` / `AAAA` addresses, and whether the domain has `MX` (business email in use) and with which provider.
- `CAA` records list the certificate authorities allowed to issue for the domain, a sign of a deliberate setup.

**Certificate (`ssl`)**
- Issuer, `valid_from`, `valid_to` and `days_until_expiry`; flag fewer than 14 days.
- `sans` lists other names on the same certificate, which can reveal related domains and brands. The tool returns at most 50.

**Email (`email_security`)**
- One line each for SPF, DMARC policy and DKIM. DMARC at `p=reject` shows an organisation that has invested in email security. An empty DKIM list only means no common selector was found.

**Public footprint (`subdomains`)**
- `live_count` (hosts that resolve now) against `count` (every name found, including historical ones).
- Notable live hosts: login, SSO, API, admin, VPN, staging, dev, test, Git or ticketing hosts. Publicly reachable staging, dev or admin hosts are worth raising in a security review.
- In `live`, each host normally shows an IP address. A hostname instead means the host is a CNAME whose target returned no IP address. If that target is a cloud or SaaS service (for example `*.herokuapp.com`, `*.azurewebsites.net`, `*.cloudfront.net`, `*.github.io`), the record may be dangling: a possible subdomain-takeover risk worth checking, not proof of one.
- `pools` summarises large shared-infrastructure zones that were collapsed.

## Buying a domain

Also cover: when it expires and whether it is lapsing (`redemption period`, `pending delete`), whether it is in active use (MX, live subdomains, a current certificate), and any clash with a well-known brand or trademark. Past owners and ownership history are not available from this data.

## Report

1. A short table: age, registrar, expiry, DNS provider, mail provider, certificate issuer and days left, DMARC policy, live and total subdomains.
2. **Red flags**, if any, each with its value.
3. **Worth verifying:** things the data suggests but can't confirm.
4. **Not covered:** owner identity, company registration, finances, website content and reputation. Suggest the company registry, references and a direct contact for those.
