"""SSL/TLS certificate inspection on port 443."""
import asyncio
import ssl
import socket
from datetime import datetime, timezone

def _fetch_cert_sync(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        x = x509.load_der_x509_certificate(der, default_backend())
        # Support both cryptography >=42 (not_valid_before_utc) and older (not_valid_before)
        try:
            not_before = x.not_valid_before_utc
            not_after = x.not_valid_after_utc
        except AttributeError:
            not_before = x.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = x.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        try:
            sans = x.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except Exception:
            sans = []
        return {
            "issuer": x.issuer.rfc4514_string(),
            "subject": x.subject.rfc4514_string(),
            "valid_from": not_before.isoformat(),
            "valid_to": not_after.isoformat(),
            "days_until_expiry": days_left,
            "serial_number": str(x.serial_number),
            "sans": sans[:20],
            "signature_algorithm": str(x.signature_algorithm_oid),
        }
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}

async def get_ssl_info(domain: str) -> dict:
    return await asyncio.to_thread(_fetch_cert_sync, domain)
