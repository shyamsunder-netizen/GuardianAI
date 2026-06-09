import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime, timezone

from cache import get_cache, set_cache
from config import NEW_DOMAIN_AGE_DAYS, WHOIS_CACHE_TTL_SECONDS, WHOIS_TIMEOUT

logger = logging.getLogger(__name__)


def _normalize_lookup_domain(domain):
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.split(":")[0]


def _parse_creation_date(creation_date):
    if creation_date is None:
        return None
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(creation_date, datetime):
        if creation_date.tzinfo is None:
            return creation_date.replace(tzinfo=timezone.utc)
        return creation_date
    return None


def _whois_lookup(lookup_domain):
    import whois

    info = whois.whois(lookup_domain)
    creation = _parse_creation_date(info.creation_date)

    if creation is None:
        return {
            "domain_age_days": -1,
            "is_new_domain": 0,
            "registrar": info.registrar,
            "creation_date": None,
            "error": "Creation date not available in WHOIS record",
        }

    now = datetime.now(timezone.utc)
    age_days = max(0, (now - creation).days)
    return {
        "domain_age_days": age_days,
        "is_new_domain": 1 if age_days < NEW_DOMAIN_AGE_DAYS else 0,
        "registrar": info.registrar,
        "creation_date": creation.isoformat(),
        "error": None,
    }


def analyze_domain_age(domain):
    """
    Perform WHOIS lookup with timeout protection and caching.
    Returns domain_age_days=-1 when lookup fails.
    """
    lookup_domain = _normalize_lookup_domain(domain)
    result = {
        "domain_age_days": -1,
        "is_new_domain": 0,
        "registrar": None,
        "creation_date": None,
        "error": None,
    }

    if not lookup_domain:
        result["error"] = "Invalid domain"
        logger.warning("WHOIS lookup skipped: invalid domain")
        return result

    cached = get_cache("whois", lookup_domain)
    if cached is not None:
        return cached

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_whois_lookup, lookup_domain)
            result = future.result(timeout=WHOIS_TIMEOUT)
    except ImportError:
        result["error"] = "python-whois is not installed"
        logger.error("WHOIS failure for %s: python-whois is not installed", lookup_domain)
        return result
    except FuturesTimeoutError:
        result["error"] = f"WHOIS lookup timed out after {WHOIS_TIMEOUT}s"
        logger.warning("WHOIS timeout for domain %s after %ss", lookup_domain, WHOIS_TIMEOUT)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        logger.warning("WHOIS failure for domain %s: %s", lookup_domain, exc)
        return result

    if result.get("error"):
        logger.warning("WHOIS incomplete for domain %s: %s", lookup_domain, result["error"])
    else:
        set_cache("whois", lookup_domain, result, WHOIS_CACHE_TTL_SECONDS)

    return result
