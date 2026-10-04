---
name: email-security-audit
description: Audit a domain's email authentication (SPF, DKIM, DMARC) and mail setup, explain what is weak or missing, and give the exact DNS records to fix it. Use when the user asks about SPF, DKIM or DMARC, email spoofing or impersonation of their domain, email landing in spam, deliverability, or whether other people can send email as their domain.
---

# Email-security audit

Use `email_security` and `dns_records` for the domain. Both take a bare domain such as `example.com`; the DMARC record comes from `email_security`, so don't look up `_dmarc.` names directly.

## 1. Mail servers (`dns.MX`)

- Name the mail provider from the MX hosts: `google.com` / `googlemail.com` → Google Workspace, `mail.protection.outlook.com` → Microsoft 365, `pphosted.com` → Proofpoint, `mimecast.com` → Mimecast, and so on.
- No MX records means the domain doesn't receive mail. If it doesn't send mail either, recommend locking it down: SPF `v=spf1 -all`, DMARC `v=DMARC1; p=reject`, and optionally a null MX record (`0 .`).

## 2. SPF (`email_security.spf.records`)

- **Missing:** nothing says which servers may send for the domain.
- **More than one `v=spf1` record:** SPF fails with a permanent error. They must be merged into one record.
- **The ending:** `-all` rejects others; `~all` (softfail) is common and fine alongside an enforced DMARC policy; `?all` gives no protection; `+all` lets anyone send as the domain and is critical.
- **The 10-lookup limit:** count `include:`, `a`, `mx`, `ptr`, `exists:` and `redirect=`. Includes count their own nested lookups too; if the top level is near 10, look up the TXT records of each included domain with `dns_records` to count properly. Over 10 makes SPF fail.
- `ptr` is deprecated; recommend removing it.
- Map each `include:` to the service it belongs to (for example `_spf.google.com` → Google Workspace, `spf.protection.outlook.com` → Microsoft 365, `sendgrid.net` → SendGrid, `mailgun.org` → Mailgun, `amazonses.com` → Amazon SES, `servers.mcsv.net` → Mailchimp) and ask the user whether each is still in use. Stale includes widen who can send as them.

## 3. DMARC (`email_security.dmarc.records`)

- **Missing:** receivers apply their own rules, and the owner gets no reports.
- More than one DMARC record is invalid.
- Read the tags: `p` (policy: `none`, `quarantine`, `reject`), `sp` (policy for subdomains, defaults to `p`), `pct` (share of mail the policy applies to, default 100), `rua` (where aggregate reports go), `ruf`, `adkim` and `aspf` (alignment, `r` relaxed by default or `s` strict).
- `p=none` only monitors; it gives no protection against spoofing. The usual path is `p=none` with `rua` → review reports until every real sender passes → `p=quarantine` → `p=reject`.
- No `rua`: the owner can't see who is sending as the domain. `pct` below 100 leaves part of the mail unprotected.

## 4. DKIM (`email_security.dkim`)

- `found` lists the selectors discovered among about 29 common ones (Google, Microsoft 365, Mailchimp, SendGrid and others). **An empty list does not mean DKIM is missing:** custom selectors, such as Amazon SES's hashed ones, can't be discovered. Ask the user for their selector, or read `s=` in the `DKIM-Signature` header of an email they sent.
- For each record: an empty `p=` means the key was revoked. Estimate RSA key size from the length of the `p=` value: about 216 characters is a 1024-bit key (weak, recommend 2048), about 392 is 2048-bit.

## 5. Grade and report

- **Strong:** one valid SPF record ending in `-all` or `~all`, DKIM found, DMARC `p=reject` (or `p=quarantine` at `pct=100`) with `rua`.
- **Partial:** SPF and DMARC exist but DMARC is `p=none`, or DKIM wasn't found on common selectors.
- **Weak:** SPF or DMARC missing, SPF with `+all` or `?all`, or duplicate records.

Report the grade, then the findings in priority order, each with the exact record to publish, for example:

```
_dmarc.example.com  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
```

Tell the user to replace the example values with their own.

## What this audit can't see

It reads public DNS only. It can't tell whether a given message passed (that's in the message's `Authentication-Results` header or in DMARC reports), and it doesn't check BIMI, MTA-STS, TLS-RPT or blocklists. Don't claim results for those.
