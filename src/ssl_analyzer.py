import logging
import socket
import ssl
from datetime import datetime, timezone

from cache import get_cache, set_cache
from config import SSL_CACHE_TTL_SECONDS, SSL_TIMEOUT

logger = logging.getLogger(__name__)


def _parse_cert_date(date_str):
    if not date_str:
        return None
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _format_name(name_tuple):
    if not name_tuple:
        return None
    parts = []
    for item in name_tuple:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            key, value = item
            parts.append(f"{key}={value}")
        else:
            parts.append(str(item))
    return ", ".join(parts) if parts else None


def _issuer_mismatch(hostname, issuer, subject):
    if not issuer or not subject:
        return False

    hostname = hostname.lower()
    issuer_lower = issuer.lower()
    subject_lower = subject.lower()

    for token in hostname.split("."):
        if len(token) > 3 and token not in subject_lower and token not in issuer_lower:
            if "let's encrypt" in issuer_lower or "digicert" in issuer_lower:
                return False
            return True
    return False


def _ssl_lookup(hostname, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=SSL_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            cert = secure_sock.getpeercert()

            result = {
                "available": True,
                "expired": False,
                "self_signed": False,
                "issuer_suspicious": False,
                "issuer": _format_name(cert.get("issuer")),
                "subject": _format_name(cert.get("subject")),
                "days_until_expiry": None,
                "error": None,
            }

            not_after = _parse_cert_date(cert.get("notAfter"))
            if not_after:
                days_left = (not_after - datetime.now(timezone.utc)).days
                result["days_until_expiry"] = days_left
                if days_left < 0:
                    result["expired"] = True

            issuer_lower = (result["issuer"] or "").lower()
            subject_lower = (result["subject"] or "").lower()
            if issuer_lower and subject_lower and issuer_lower == subject_lower:
                result["self_signed"] = True

            if _issuer_mismatch(hostname, result["issuer"], result["subject"]):
                result["issuer_suspicious"] = True

            return result


def analyze_ssl_certificate(domain, port=443):
    """Inspect TLS certificate with timeout protection and caching."""
    hostname = domain.lower().strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    hostname = hostname.split(":")[0]

    result = {
        "available": False,
        "expired": False,
        "self_signed": False,
        "issuer_suspicious": False,
        "issuer": None,
        "subject": None,
        "days_until_expiry": None,
        "error": None,
    }

    if not hostname:
        result["error"] = "Invalid hostname"
        logger.warning("SSL analysis skipped: invalid hostname")
        return result

    cache_key = f"{hostname}:{port}"
    cached = get_cache("ssl", cache_key)
    if cached is not None:
        return cached

    try:
        result = _ssl_lookup(hostname, port=port)
    except ssl.SSLCertVerificationError as exc:
        result["error"] = str(exc)
        message = str(exc).lower()
        if "self signed" in message or "self-signed" in message:
            result["self_signed"] = True
        if "expired" in message:
            result["expired"] = True
        logger.warning("SSL certificate verification failed for %s: %s", hostname, exc)
    except (ssl.SSLError, socket.timeout, TimeoutError, OSError) as exc:
        result["error"] = str(exc)
        if "self signed" in str(exc).lower():
            result["self_signed"] = True
        logger.warning("SSL failure for domain %s: %s", hostname, exc)
    except Exception as exc:
        result["error"] = str(exc)
        logger.warning("SSL failure for domain %s: %s", hostname, exc)

    if result.get("error") is None or result.get("available"):
        set_cache("ssl", cache_key, result, SSL_CACHE_TTL_SECONDS)

    return result
