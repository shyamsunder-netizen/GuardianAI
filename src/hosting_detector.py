from config import SUSPICIOUS_HOSTING


def is_suspicious_hosting(url):
    url_lower = url.lower()
    for host in SUSPICIOUS_HOSTING:
        if host in url_lower:
            return True
    return False
