# OTI Labs Domain Intelligence

Look up any domain from Claude: who registered it and when (WHOIS/RDAP), its DNS records, the SSL certificate it serves right now, its live subdomains with their IP addresses, and its email authentication (SPF, DKIM, DMARC). Three skills turn those lookups into finished checks.

## Skills

| Skill | Use it for |
|---|---|
| **Phishing triage** | "Is this link, sender or domain legitimate?" Checks domain age, lookalike patterns, the certificate, DNS and email authentication, then gives a verdict with the evidence. Covers "our bank details have changed" emails. |
| **Email-security audit** | Grades a domain's SPF, DKIM and DMARC setup, explains what's weak or missing, and gives the exact records to publish. |
| **Domain due diligence** | A profile of a domain before you buy it, pay or partner with the company behind it, or onboard a vendor: age, renewal risk, hosting, certificate, email setup and public subdomains. |

You don't have to call a skill by name. Ask in plain words, for example "Is paypa1-billing.com a scam?" or "Audit DMARC for example.com".

## Tools

The plugin connects Claude to one hosted MCP server, `https://oti-labs.com/mcp`. All six tools are read-only.

| Tool | Returns |
|---|---|
| `domain_lookup` | Everything below in one call |
| `whois_lookup` | Registrar, created, updated and expiry dates, nameservers, status (RDAP, with port-43 WHOIS fallback) |
| `dns_records` | A, AAAA, MX, TXT, NS, CAA and SOA records |
| `ssl_certificate` | The live certificate: issuer, validity dates, days until expiry, SANs |
| `subdomains` | Live hosts with their IPs, plus names seen in certificate logs and passive DNS |
| `email_security` | SPF and DMARC records, and DKIM keys on about 29 common selectors |

## Limits and keys

No sign-up or key is needed. Without a key, Claude Code gets 1,000 lookups a month per IP address; in Claude on the web, desktop and Cowork, lookups come from a shared allowance for Claude users. To use your own plan instead, enter a RapidAPI key subscribed to the [Domain Intelligence API](https://rapidapi.com/osiris-technical-institute-osiris-technical-institute-default/api/domain-intelligence-api) when the plugin asks for one (free plan: 1,000 requests a month).

## What the plugin sends, and where

- Each tool call sends the domain you asked about (and your RapidAPI key, if you set one) to `https://oti-labs.com/mcp`, run by OTI Labs. Nothing runs on your computer, and the plugin has no hooks or scripts.
- To answer, the server queries public sources about that domain: RDAP and WHOIS servers, public DNS resolvers, certificate transparency logs, passive DNS services, and the domain's own web server (a TLS handshake on port 443 to read its certificate). With a key, the request goes through RapidAPI.
- The server never receives your conversation, files or chat history. See the [privacy policy](https://oti-labs.com/privacy).

## Source and support

The MCP server is open source (MIT): [github.com/osiris-technical-institute/domain-intelligence-api](https://github.com/osiris-technical-institute/domain-intelligence-api/tree/main/mcp). Report problems in [GitHub issues](https://github.com/osiris-technical-institute/domain-intelligence-api/issues). Setup for other MCP clients: [oti-labs.com/mcp-server](https://oti-labs.com/mcp-server).
