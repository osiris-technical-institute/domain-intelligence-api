"""Email security posture: SPF, DMARC, DKIM presence checks.

DKIM probing strategy: there is no DNS spec for "discover all DKIM selectors"
because selectors are arbitrary strings chosen by each mail provider. We probe
a curated list of ~30 common selectors used by major providers (Google
Workspace, Microsoft 365, Mailchimp, SendGrid, Postmark, Mandrill, etc.) plus
generic catch-alls. This covers ~60-80% of real domains in practice; custom or
hash-based selectors (e.g. Amazon SES) won't be found and require manual lookup
at `<selector>._domainkey.{domain}`.

A selector only counts as found when its record carries a public key. An empty
p= means the key was revoked (RFC 6376 3.6.1); those selectors are listed in
the note instead. Some zones publish a wildcard at *._domainkey that answers
every selector with the same record, so we also probe random selector names and
ignore answers that match the wildcard.
"""
import asyncio
import secrets

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

# Random selector names that can't be in real use. If they return TXT, the zone
# has a wildcard under _domainkey and selectors answering with that same record
# are catch-all answers, not discovered selectors.
WILDCARD_PROBES = 2


async def _txt(resolver, name):
    """Resolve TXT records for a name. Returns [] on any failure."""
    try:
        ans = await resolver.resolve(name, "TXT", lifetime=3.0)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    except (dns.exception.DNSException, Exception):
        return []


def _dkim_tags(record: str) -> dict:
    """Parse a DKIM tag-list ("v=DKIM1; k=rsa; p=...") into {tag: value}.
    Tag names are lowercased and whitespace inside values is dropped."""
    tags = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if sep:
            tags[name.strip().lower()] = "".join(value.split())
    return tags


def _is_dkim(record: str) -> bool:
    # Filters out unrelated TXT at _domainkey paths (rare).
    tags = _dkim_tags(record)
    return tags.get("v", "").lower() == "dkim1" or "k" in tags or "p" in tags


def _has_key(record: str) -> bool:
    """True if the record publishes a public key. p= is required; empty means revoked."""
    return bool(_dkim_tags(record).get("p"))


def _dkim_result(answers: dict, wildcard: set) -> dict:
    """Build {found, records, note} from {selector: [txt, ...]} and the wildcard answers."""
    found, records, no_key = [], [], []
    for selector, txts in answers.items():
        if wildcard and txts and set(txts) <= wildcard:
            continue  # catch-all answer from *._domainkey
        dkim = [t for t in txts if _is_dkim(t)]
        keys = [t for t in dkim if _has_key(t)]
        if keys:
            found.append(selector)
            records.append({"selector": selector, "records": keys})
        elif dkim:
            no_key.append(selector)

    note = (
        "Probed common selectors (Google, Microsoft 365, Mailchimp, SendGrid, etc.). "
        "Custom or hash-based selectors aren't auto-discoverable."
    )
    wild_dkim = [t for t in wildcard if _is_dkim(t)]
    if wild_dkim:
        if any(_has_key(t) for t in wild_dkim):
            note += (" A wildcard at *._domainkey answers any selector name with the same DKIM record; "
                     "those answers weren't counted as found selectors.")
        else:
            note += (" A wildcard at *._domainkey answers any selector name with the same record and an "
                     "empty p= (a revoked key); those answers weren't counted.")
    if no_key:
        note += (" Not counted because the record has no public key (an empty p= means the key "
                 "was revoked): " + ", ".join(no_key) + ".")
    return {"found": found, "records": records, "note": note}


async def get_email_security(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    # SPF + DMARC + DKIM (plus the wildcard probes) all run in parallel for minimum latency.
    probes = [f"{secrets.token_hex(8)}-wildcardprobe" for _ in range(WILDCARD_PROBES)]
    selectors = COMMON_SELECTORS + probes
    spf_task = _txt(resolver, domain)
    dmarc_task = _txt(resolver, f"_dmarc.{domain}")
    dkim_tasks = [_txt(resolver, f"{sel}._domainkey.{domain}") for sel in selectors]

    results = await asyncio.gather(spf_task, dmarc_task, *dkim_tasks, return_exceptions=True)
    # Defensive: if any task raised, treat as empty
    results = [r if isinstance(r, list) else [] for r in results]
    spf_records, dmarc_records = results[0], results[1]
    dkim_answers = dict(zip(selectors, results[2:]))

    spf = [t for t in spf_records if t.lower().startswith("v=spf1")]
    dmarc_rec = [t for t in dmarc_records if t.lower().startswith("v=dmarc1")]

    wildcard = set()
    for p in probes:
        wildcard.update(dkim_answers.pop(p))

    return {
        "spf": {"present": bool(spf), "records": spf},
        "dmarc": {"present": bool(dmarc_rec), "records": dmarc_rec},
        "dkim": _dkim_result(dkim_answers, wildcard),
    }
