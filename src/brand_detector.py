from urllib.parse import urlparse

from config import BRAND_LEVENSHTEIN_THRESHOLD, KNOWN_BRANDS


def levenshtein_distance(a, b):
    if len(a) < len(b):
        return levenshtein_distance(b, a)

    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)

    for i, c1 in enumerate(a):
        current_row = [i + 1]
        for j, c2 in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def _normalize_domain(value):
    if "://" in value:
        domain = urlparse(value).netloc
    else:
        domain = value

    domain = domain.lower().strip().split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _domain_label(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def detect_brand_impersonation(url_or_domain, is_whitelisted=False):
    """
    Unified brand impersonation detection.
    Returns (flag, brand_name, detail).
    """
    if is_whitelisted:
        return False, None, None

    domain = _normalize_domain(url_or_domain)
    if not domain:
        return False, None, None

    label = _domain_label(domain)

    for brand, official_domain in KNOWN_BRANDS.items():
        if brand in domain and official_domain not in domain:
            return True, brand, "Domain-level impersonation detected"

        distance = levenshtein_distance(label, brand)
        if distance <= BRAND_LEVENSHTEIN_THRESHOLD and domain != official_domain:
            if not domain.endswith("." + official_domain) and domain != official_domain:
                return True, brand, f"Typo-squat similarity (distance={distance})"

    return False, None, None


def detect_brand_similarity(domain):
    """Backward-compatible alias used by older imports."""
    flag, brand, detail = detect_brand_impersonation(domain, is_whitelisted=False)
    distance = None
    if detail and "distance=" in detail:
        try:
            distance = int(detail.split("distance=")[1].rstrip(")"))
        except (IndexError, ValueError):
            distance = None
    return flag, brand, distance
