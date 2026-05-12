"""Email security posture: SPF, DMARC, DKIM presence checks."""
import dns.asyncresolver
import dns.exception

async def _txt(resolver, name):
    try:
        ans = await resolver.resolve(name, "TXT", lifetime=3.0)
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    except (dns.exception.DNSException, Exception):
        return []

async def get_email_security(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    spf_records = await _txt(resolver, domain)
    spf = [t for t in spf_records if t.lower().startswith("v=spf1")]
    dmarc = await _txt(resolver, f"_dmarc.{domain}")
    dmarc_rec = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    return {
        "spf": {"present": bool(spf), "records": spf},
        "dmarc": {"present": bool(dmarc_rec), "records": dmarc_rec},
        "dkim": {"note": "DKIM requires selector; not auto-discoverable"},
    }
