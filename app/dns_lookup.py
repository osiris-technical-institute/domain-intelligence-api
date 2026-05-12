"""DNS record lookups using dnspython."""
import asyncio
import dns.asyncresolver
import dns.exception

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CAA", "SOA"]

async def _query(resolver, domain, rtype):
    try:
        answers = await resolver.resolve(domain, rtype, lifetime=3.0)
        return rtype, [r.to_text() for r in answers]
    except (dns.exception.DNSException, Exception):
        return rtype, []

async def get_dns_records(domain: str) -> dict:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    tasks = [_query(resolver, domain, rt) for rt in RECORD_TYPES]
    results = await asyncio.gather(*tasks)
    return {rt: vals for rt, vals in results}
