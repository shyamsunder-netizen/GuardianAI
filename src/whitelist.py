from urllib.parse import urlparse

from config import TRUSTED_DOMAINS


def _normalize_domain(domain):
    if not domain:
        return ""
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split(":")[0]


def is_whitelisted(url_or_domain):
    """
    Return (is_trusted, matched_domain).
    Matches exact domain or any subdomain of a trusted root.
    """
    if "://" in url_or_domain:
        domain = urlparse(url_or_domain).netloc
    else:
        domain = url_or_domain

    domain = _normalize_domain(domain)
    if not domain:
        return False, None

    for trusted in TRUSTED_DOMAINS:
        trusted = trusted.lower()
        if domain == trusted or domain.endswith("." + trusted):
            return True, trusted

    return False, None
