import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.join(BASE_DIR, "..")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "phishing_model.pkl")

# Cache directories
FEED_CACHE_DIR = os.path.join(PROJECT_ROOT, "data", "feeds")
RUNTIME_CACHE_DIR = os.path.join(PROJECT_ROOT, "data", "cache")

# Trusted domains (exact match or subdomain)
TRUSTED_DOMAINS = [
    "github.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "ibm.com",
    "cisco.com",
]

# Brand impersonation
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
}
BRAND_LEVENSHTEIN_THRESHOLD = 2

# URL lexical features
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "account",
    "bank",
    "confirm",
    "password",
]
SUSPICIOUS_TLDS = [".xyz", ".tk", ".top", ".gq", ".ml", ".cf"]

# Suspicious hosting providers (substring match)
SUSPICIOUS_HOSTING = [
    "ngrok",
    "trycloudflare",
    "localtunnel",
    "herokuapp",
    "onrender",
    "vercel",
    "firebaseapp",
    "serveo",
    "duckdns",
    "000webhost",
]

# Threat feed settings
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
OPENPHISH_CACHE_TTL_SECONDS = 3600
PHISHTANK_CHECK_URL = "https://checkurl.phishtank.com/checkurl/"
PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", "")

# Timeouts (seconds)
HTTP_TIMEOUT = 8
WHOIS_TIMEOUT = 10
SSL_TIMEOUT = 8
FEED_FETCH_TIMEOUT = 10

# Runtime cache TTL (seconds)
WHOIS_CACHE_TTL_SECONDS = 86400
SSL_CACHE_TTL_SECONDS = 3600

# Form analysis: static HTML first; headless fallback is opt-in
USE_HEADLESS_FORMS = os.environ.get("USE_HEADLESS_FORMS", "false").lower() == "true"

# Domain age
NEW_DOMAIN_AGE_DAYS = 30

# Entropy
ENTROPY_THRESHOLD = 3.8

# Risk bands
RISK_HIGH_THRESHOLD = 70
RISK_MEDIUM_THRESHOLD = 40

# Whitelist score cap (when no feed hit)
WHITELIST_SCORE_CAP = 25

# Threat scoring weights
SCORE_WEIGHTS = {
    "ml_multiplier": 0.6,
    "entropy": 15,
    "suspicious_hosting": 15,
    "brand_impersonation": 25,
    "stealth_phishing": 20,
    "openphish_match": 40,
    "phishtank_verified": 35,
    "phishtank_unverified": 20,
    "new_domain": 18,
    "ssl_expired": 15,
    "ssl_self_signed": 15,
    "ssl_issuer_mismatch": 10,
    "password_field": 15,
    "external_form": 20,
    "login_form": 10,
}

# HTTP user agent
USER_AGENT = "Mozilla/5.0 (compatible; GuardianAI/1.0; +https://github.com/GuardianAI)"

# Logging
LOG_LEVEL = os.environ.get("GUARDIANAI_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def setup_logging():
    logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO), format=LOG_FORMAT)
