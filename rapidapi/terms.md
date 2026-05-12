# Domain Intelligence API — Terms of Use

**Last updated:** 2026-04-30

## 1. Service Description
Domain Intelligence API ("the Service") is a read-only HTTP API providing aggregated public information about internet domain names, including DNS records, SSL/TLS certificate metadata, WHOIS/RDAP registration data, observed subdomains (from Certificate Transparency logs), and email-security posture (SPF/DMARC/DKIM/DNSBL).

The Service is operated by Osiris Technical Institute ("we", "us") and distributed exclusively via the RapidAPI marketplace. By subscribing to any plan, you ("the Subscriber") agree to these Terms in addition to RapidAPI's own Terms of Service.

## 2. Permitted Use
You may query the Service for:
- Security research and threat-intelligence enrichment
- IT asset inventory and attack-surface monitoring
- Domain due-diligence and brand protection
- Educational and journalistic research
- Integration into your own products, subject to your plan quota

## 3. Prohibited Use
You must NOT use the Service to:
- Conduct or facilitate unauthorized access to third-party systems
- Build a competing aggregation product that resells substantially the same dataset
- Circumvent rate limits, plan quotas, or authentication
- Send queries at a rate or volume that degrades service for other Subscribers
- Process personal data in violation of applicable privacy law (GDPR, CCPA, etc.)

## 4. Data Sources & Accuracy
All data is derived from public sources: authoritative DNS, public RDAP/WHOIS endpoints, the Certificate Transparency log ecosystem (crt.sh), public DNSBLs, and live TLS handshakes against the queried host. We make no warranty as to accuracy, completeness, or timeliness. Data may be cached for up to 6 hours per record type.

## 5. Service Availability
We target 99.5% monthly availability but provide no formal SLA on free or entry-level paid plans. Scheduled maintenance and source-upstream outages are excluded.

## 6. Billing, Refunds, Changes
All billing is handled by RapidAPI. Refund and chargeback policy follows RapidAPI marketplace terms. We reserve the right to modify pricing with 30 days notice; existing subscriptions honor their original price through the end of the current billing cycle.

## 7. Suspension
We may suspend or terminate access immediately for: violation of these Terms, fraudulent payment, or use that we reasonably believe to be malicious.

## 8. Liability
The Service is provided "AS IS". To the maximum extent permitted by law, our aggregate liability for any claim is limited to amounts paid by the Subscriber in the three (3) months preceding the claim.

## 9. Changes to These Terms
We may update these Terms from time to time. Material changes will be announced via the API listing description.

## 10. Contact
For support, billing disputes, or security disclosures: use the RapidAPI provider message channel on the API listing page.
