"""Email security posture: SPF, DMARC, DKIM presence checks.

DKIM probing strategy: there is no DNS spec for "discover all DKIM selectors"
because selectors are arbitrary strings chosen by each mail provider. We probe
a curated list of ~30 common selectors used by major providers (Google
Workspace, Microsoft 365, Mailchimp, SendGrid, Postmark, Mandrill, etc.) plus
generic catch-alls. This covers ~60-80% of real domains in practice; custom or
hash-based selectors (e.g. Amazon SES) won't be found and require manual lookup
at `<selector>._domainkey.{domain}`.
"""
import asyncio
import dns.asyncresolver
import dns.exception

# Common DKIM selectors used by major mail providers. Order matters slightly:
# the most-used selectors (google, selector1) come first so partial timeouts
# still return useful data.
COMMON_SELECTORS = [
    "google",       # Google Workspace
    "selector1",    # Microsoft 365 (rotating pair with selector2)
    "selector2",    # Microsoft 365
    "k1", "k2", "k3",  # Mailchimp / various
    "s1", "s2",     # SendGrid / various
    "sg",           # SendGrid alt
    "pm",           # Postmark
    "mandrill",     # Mandrill
    "klaviyo",      # Klaviyo
    "mailgun",      # Mailgun
    "default",      # generic catchall
    "mail",         # generic catchall
    "dkim",         # generic catchall
    "email",        # generic catchall
    "em",           # generic catchall
    "dk",           # legacy DomainKeys carryover
    "smtp",         # generic catchall
    "smtp1", "smtp2",
    "mxvault",      # MXVault
    "amazonses",    # Amazon SES generic (real selectors are hash-based, but try anyway)
    "intercom",     # Intercom
    "m1",           # various
    "20210112",     # date-based selector pattern (some Google Workspace tenants)
    "dkim1", "dkim2",  # generic numbered
]


async def _txt(resolver, name):
    """Resolve TXT records for a name. Returns [] on any failure."""
    try:
        ans = await resolver.resolve(name, "TXT", lifetime=3.0)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    except (dns.exception.DNSException, Exception):
        return []


async def _try_dkim_selector(resolver, domain: str, selector: str):
    """Probe one DKIM selector. Returns dict if found (with records), else None."""
    name = f"{selector}._domainkey.{domain}"
    records = await _txt(resolver, name)
    # Filter for records that actually look like DKIM (contain v=DKIM1 or k=rsa).
    # Some domains have unrelated TXT at _domainkey paths (rare); this filters them out.
    dkim_records = [
        t for t in records
        if "v=dkim1" in t.lower() or "k=rsa" in t.lower() or "k=ed25519" in t.lower()
    ]
    if dkim_records:
        return {"selector": selector, "records": dkim_records}
    return None


async def get_email_security(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    # SPF + DMARC + DKIM all probed in parallel for minimum total latency.
    spf_task = _txt(resolver, domain)
    dmarc_task = _txt(resolver, f"_dmarc.{domain}")
    dkim_tasks = [_try_dkim_selector(resolver, domain, sel) for sel in COMMON_SELECTORS]

    results = await asyncio.gather(spf_task, dmarc_task, *dkim_tasks, return_exceptions=True)
    spf_records, dmarc_records = results[0], results[1]
    dkim_results = results[2:]

    # Defensive: if any task raised, treat as empty
    if isinstance(spf_records, Exception):
        spf_records = []
    if isinstance(dmarc_records, Exception):
        dmarc_records = []

    spf = [t for t in spf_records if t.lower().startswith("v=spf1")]
    dmarc_rec = [t for t in dmarc_records if t.lower().startswith("v=dmarc1")]

    found = []
    records = []
    for r in dkim_results:
        if isinstance(r, dict) and r.get("selector"):
            found.append(r["selector"])
            records.append(r)

    return {
        "spf": {"present": bool(spf), "records": spf},
        "dmarc": {"present": bool(dmarc_rec), "records": dmarc_rec},
        "dkim": {
            "found": found,
            "records": records,
            "note": (
                "Probed common selectors (Google, Microsoft 365, Mailchimp, SendGrid, etc.). "
                "Custom or hash-based selectors aren't auto-discoverable."
            ),
        },
    }
