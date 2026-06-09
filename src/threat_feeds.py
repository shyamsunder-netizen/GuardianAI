import logging
import os
import time
from urllib.parse import urlparse

import requests

from config import (
    FEED_CACHE_DIR,
    FEED_FETCH_TIMEOUT,
    HTTP_TIMEOUT,
    OPENPHISH_CACHE_TTL_SECONDS,
    OPENPHISH_FEED_URL,
    PHISHTANK_API_KEY,
    PHISHTANK_CHECK_URL,
    USER_AGENT,
)

logger = logging.getLogger(__name__)


def _normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def _url_variants(url):
    parsed = urlparse(_normalize_url(url))
    domain = parsed.netloc.lower().split(":")[0]
    bare_domain = domain[4:] if domain.startswith("www.") else domain

    variants = {
        url.strip().lower(),
        _normalize_url(url).lower(),
        domain,
        bare_domain,
        f"http://{domain}",
        f"https://{domain}",
        f"http://{bare_domain}",
        f"https://{bare_domain}",
    }
    return variants, domain, bare_domain


class ThreatFeedChecker:
    def __init__(self):
        self._openphish_urls = set()
        self._openphish_domains = set()
        self._openphish_loaded_at = 0
        self._last_fetch_error = None

    def check_url(self, url):
        openphish = self.check_openphish(url)
        phishtank = self.check_phishtank(url)
        return {
            "openphish_match": openphish["match"],
            "openphish_detail": openphish.get("detail"),
            "phishtank_match": phishtank["match"],
            "phishtank_verified": phishtank.get("verified", False),
            "phishtank_detail": phishtank.get("detail"),
            "feed_errors": self._collect_errors(openphish, phishtank),
        }

    def _collect_errors(self, openphish, phishtank):
        errors = []
        if self._last_fetch_error:
            errors.append(self._last_fetch_error)
        phishtank_detail = phishtank.get("detail") or ""
        if phishtank_detail.startswith("PhishTank lookup failed"):
            errors.append(phishtank_detail)
        return errors

    def check_openphish(self, url):
        self._ensure_openphish_feed()
        variants, domain, bare_domain = _url_variants(url)

        for candidate in variants:
            if candidate in self._openphish_urls:
                return {"match": True, "detail": "Exact URL match in OpenPhish feed"}

        if domain in self._openphish_domains or bare_domain in self._openphish_domains:
            return {
                "match": True,
                "detail": f"Domain '{bare_domain}' found in OpenPhish feed",
            }

        return {"match": False, "detail": None}

    def check_phishtank(self, url):
        if not PHISHTANK_API_KEY:
            return {
                "match": False,
                "verified": False,
                "detail": "PhishTank API key not configured (set PHISHTANK_API_KEY)",
            }

        try:
            response = requests.post(
                PHISHTANK_CHECK_URL,
                data={
                    "url": _normalize_url(url),
                    "format": "json",
                    "app_key": PHISHTANK_API_KEY,
                },
                headers={"User-Agent": USER_AGENT},
                timeout=HTTP_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()

            results = payload.get("results", {})
            in_database = results.get("in_database") in (True, "true", "1", 1)
            verified = results.get("verified") in (True, "true", "1", 1)

            if in_database:
                return {
                    "match": True,
                    "verified": verified,
                    "detail": "PhishTank verified phishing URL"
                    if verified
                    else "PhishTank listed URL (unverified)",
                }

            return {"match": False, "verified": False, "detail": None}

        except requests.Timeout:
            message = f"PhishTank lookup timed out after {HTTP_TIMEOUT}s"
            logger.warning(message)
            return {"match": False, "verified": False, "detail": message}
        except Exception as exc:
            message = f"PhishTank lookup failed: {exc}"
            logger.warning(message)
            return {"match": False, "verified": False, "detail": message}

    def load_openphish_entries(self, lines):
        """Load OpenPhish entries directly (used by tests)."""
        urls, domains = self._parse_openphish_lines(lines)
        self._openphish_urls = urls
        self._openphish_domains = domains
        self._openphish_loaded_at = time.time()
        self._last_fetch_error = None

    def _ensure_openphish_feed(self):
        now = time.time()
        if self._openphish_urls and (now - self._openphish_loaded_at) < OPENPHISH_CACHE_TTL_SECONDS:
            return

        cached = self._load_openphish_cache()
        if cached:
            self._openphish_urls, self._openphish_domains = cached
            self._openphish_loaded_at = now
            logger.info("Loaded OpenPhish feed from disk cache (%s URLs)", len(self._openphish_urls))
            return

        fetched = self._fetch_openphish_feed()
        if fetched and fetched[0]:
            self._openphish_urls, self._openphish_domains = fetched
            self._openphish_loaded_at = now
            self._save_openphish_cache(fetched)
            logger.info("Fetched OpenPhish feed (%s URLs)", len(self._openphish_urls))
        elif not self._openphish_urls:
            logger.warning("OpenPhish feed unavailable; no cached entries loaded")

    def _fetch_openphish_feed(self):
        try:
            response = requests.get(
                OPENPHISH_FEED_URL,
                headers={"User-Agent": USER_AGENT},
                timeout=FEED_FETCH_TIMEOUT,
            )
            response.raise_for_status()
            lines = [line.strip() for line in response.text.splitlines() if line.strip()]
            self._last_fetch_error = None
            return self._parse_openphish_lines(lines)
        except requests.Timeout:
            self._last_fetch_error = f"OpenPhish feed fetch timed out after {FEED_FETCH_TIMEOUT}s"
            logger.warning(self._last_fetch_error)
        except Exception as exc:
            self._last_fetch_error = f"OpenPhish feed fetch failed: {exc}"
            logger.warning(self._last_fetch_error)

        local_path = os.path.join(FEED_CACHE_DIR, "openphish.txt")
        if os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as handle:
                    lines = [line.strip() for line in handle if line.strip()]
                logger.info("Loaded OpenPhish fallback file: %s", local_path)
                self._last_fetch_error = None
                return self._parse_openphish_lines(lines)
            except Exception as exc:
                logger.warning("OpenPhish fallback file read failed: %s", exc)

        return set(), set()

    def _parse_openphish_lines(self, lines):
        urls = set()
        domains = set()
        for line in lines:
            normalized = line.strip().lower()
            if not normalized:
                continue
            urls.add(normalized)
            parsed = urlparse(normalized if "://" in normalized else "http://" + normalized)
            domain = parsed.netloc.lower().split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            if domain:
                domains.add(domain)
                urls.add(domain)
        return urls, domains

    def _cache_paths(self):
        os.makedirs(FEED_CACHE_DIR, exist_ok=True)
        urls_path = os.path.join(FEED_CACHE_DIR, "openphish_cache_urls.txt")
        meta_path = os.path.join(FEED_CACHE_DIR, "openphish_cache_meta.txt")
        return urls_path, meta_path

    def _save_openphish_cache(self, fetched):
        urls, domains = fetched
        urls_path, meta_path = self._cache_paths()
        with open(urls_path, "w", encoding="utf-8") as handle:
            for item in sorted(urls):
                handle.write(item + "\n")
        with open(meta_path, "w", encoding="utf-8") as handle:
            handle.write(str(int(time.time())) + "\n")
        self._openphish_domains = domains

    def _load_openphish_cache(self):
        urls_path, meta_path = self._cache_paths()
        if not os.path.isfile(urls_path) or not os.path.isfile(meta_path):
            return None

        try:
            with open(meta_path, "r", encoding="utf-8") as handle:
                cached_at = int(handle.read().strip())
            if time.time() - cached_at > OPENPHISH_CACHE_TTL_SECONDS:
                return None
            with open(urls_path, "r", encoding="utf-8") as handle:
                lines = [line.strip().lower() for line in handle if line.strip()]
            return self._parse_openphish_lines(lines)
        except Exception as exc:
            logger.warning("OpenPhish disk cache read failed: %s", exc)
            return None


_feed_checker = None


def get_feed_checker():
    global _feed_checker
    if _feed_checker is None:
        _feed_checker = ThreatFeedChecker()
    return _feed_checker


def check_threat_feeds(url):
    feed_data = get_feed_checker().check_url(url)
    for error in feed_data.get("feed_errors", []):
        logger.warning("Threat feed lookup issue for %s: %s", url, error)
    return feed_data
