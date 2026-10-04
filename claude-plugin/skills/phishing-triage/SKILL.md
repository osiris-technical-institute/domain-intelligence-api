---
name: phishing-triage
description: Triage a suspicious domain, link or email sender using live registration, certificate, DNS and email-authentication data. Use when the user asks whether a domain, URL or email is legitimate, safe, a scam or phishing, pastes a link or sender from an unexpected message, or receives a request to change bank or payment details.
---

# Phishing triage

Give the user a clear verdict backed by evidence they can check. Use the `domain_lookup` tool (and the single-section tools where noted).

## 1. Work out which domain to check

- From a URL, take the hostname. From an email address, take the part after `@`. If the user pasted headers, also note the `Reply-To` and `Return-Path` domains and the domains of any links.
- Reduce the hostname to its registrable domain (`login.secure-example.co.uk` → `secure-example.co.uk`) and look that up. Keep the full hostname for the report: a brand name placed in a subdomain (`paypal.com.account-check.net`) is itself a red flag.
- **Shared platforms:** if the registrable domain is a hosting or site-builder platform (for example `vercel.app`, `netlify.app`, `pages.dev`, `github.io`, `web.app`, `firebaseapp.com`, `workers.dev`, `blogspot.com`, `azurewebsites.net`), the registration and certificate belong to the platform, not to whoever made the page. Say so, skip the age argument, and judge the hostname itself.
- If the domain imitates a brand, name the brand and its real domain. Look up the real one too when the comparison helps (age, registrar, DMARC).

## 2. Look it up

Call `domain_lookup` with the domain. A section that comes back with an `error` field is unknown, not evidence either way. If a tool returns a usage-limit message, tell the user and stop retrying.

## 3. Weigh the signals

Compare every date with today's date.

**Strong signals**
- `whois.created` within the last 30 days (moderate if within 90 days).
- A lookalike of a known brand: swapped characters (`rn`/`m`, `0`/`o`, `1`/`l`), added words (`-secure`, `-verify`, `-support`, `-billing`, `-login`), a different TLD than the brand uses, or the brand in a subdomain of an unrelated domain.
- The sender's domain differs from the organisation the message claims to be from, or `Reply-To` points to a different domain.
- `whois.status` contains `client hold` or `server hold` (the registry or registrar has suspended the domain, often for abuse), or `pending delete` / `redemption period`.

**Supporting signals**
- `ssl.valid_from` only days ago on a site that presents itself as long-established. Free certificates (Let's Encrypt, ZeroSSL, Google Trust Services) are normal for legitimate sites; the issuer alone is not evidence.
- No working certificate (an `ssl` error) on a page that asks for a login or payment.
- No MX records (`dns.MX` empty) on a domain that supposedly sent the email: the message came from somewhere else.
- No SPF and no DMARC (`email_security`) on a domain presented as an established business.
- Few or no subdomains together with a very recent registration: typical of a throwaway domain.

**Reassuring, but not proof**
- Several years of age, a stable registrar, DMARC `p=reject` or `p=quarantine`, many live subdomains. Old domains can be compromised and legitimate platforms can host phishing pages, so these lower the risk without ruling it out.

## 4. Payment-change and invoice emails

If the message asks the user to pay a new account or update bank details:
- Compare the sender's domain character by character with the domain the user normally deals with, and look up both.
- A recently registered lookalike of a supplier's domain is the classic invoice-fraud pattern. Domain data can't prove an email is genuine, even when every check passes.
- Always tell the user to confirm the change by phone, using a number from an earlier invoice or contract, never one from the email.

## 5. Report

Use this shape:

**Verdict:** Likely malicious / Suspicious / No red flags found, in one line.

**Evidence:** 3 to 6 bullets, each with the value and its source, for example "Registered 2026-09-28, 6 days ago (WHOIS via rdap.org)".

**What to do:** concrete next steps (don't click, report it, verify by phone, block the domain).

**What this didn't check:** the page's content, the email's own authentication results (the `Authentication-Results` header) and reputation or blocklist feeds.

Never call a domain "safe". Say "no red flags found in its registration, certificate, DNS and email-authentication data".
