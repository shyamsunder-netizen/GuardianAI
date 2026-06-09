from urllib.parse import urlparse
import re

from config import SUSPICIOUS_TLDS, SUSPICIOUS_WORDS
from entropy_utils import calculate_entropy, domain_entropy


def has_unicode_spoof(domain):
    for char in domain:
        if ord(char) > 127:
            return 1
    return 0


def detect_base64(text):
    return 1 if re.search(r"[A-Za-z0-9+/=]{20,}", text) else 0


def extract_features(url, use_whois=False, whois_data=None):
    features = {}

    url_lower = url.lower()
    parsed = urlparse(url_lower)
    domain = parsed.netloc.split(":")[0]

    features["url_length"] = len(url)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["uses_ip"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+", domain) else 0
    features["suspicious_words"] = sum(word in url_lower for word in SUSPICIOUS_WORDS)
    features["suspicious_tld"] = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
    features["subdomain_count"] = domain.count(".")
    features["special_char_count"] = len(re.findall(r"[!@#$%^&*(),?\":{}|<>]", url))
    features["has_port"] = 1 if ":" in parsed.netloc else 0
    features["path_length"] = len(parsed.path)
    features["query_length"] = len(parsed.query)
    features["query_entropy"] = calculate_entropy(parsed.query)
    features["base64_detected"] = detect_base64(parsed.query)
    features["domain_entropy"] = domain_entropy(domain)
    features["unicode_spoof"] = has_unicode_spoof(domain)
    features["domain_age_days"] = -1
    features["is_new_domain"] = 0

    if whois_data is None and use_whois:
        from whois_analyzer import analyze_domain_age

        whois_data = analyze_domain_age(domain)

    if whois_data:
        age = whois_data.get("domain_age_days", -1)
        if age >= 0:
            features["domain_age_days"] = age
            features["is_new_domain"] = whois_data.get("is_new_domain", 0)

    return features
