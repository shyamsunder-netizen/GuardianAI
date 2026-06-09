import logging
from urllib.parse import urljoin, urlparse

import requests

from config import HTTP_TIMEOUT, USE_HEADLESS_FORMS, USER_AGENT

logger = logging.getLogger(__name__)


def analyze_forms(url):
    """
    Detect credential harvesting signals on a page.
    Uses static HTML analysis by default; optional headless fallback.
    """
    static_results = _analyze_static_forms(url)
    if _needs_headless(static_results):
        headless_results = _analyze_headless_forms(url)
        return _merge_results(static_results, headless_results)

    if static_results.get("error"):
        logger.warning("Form analysis failed for %s: %s", url, static_results["error"])

    return static_results


def _analyze_static_forms(url):
    results = {
        "password_detected": 0,
        "external_form": 0,
        "has_login_form": 0,
        "method": "static",
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
        response.raise_for_status()

        final_url = response.url
        parsed = urlparse(final_url)
        page_domain = parsed.netloc.lower().split(":")[0]

        from bs4 import BeautifulSoup

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            password_inputs = form.find_all("input", {"type": "password"})
            if password_inputs:
                results["password_detected"] = 1

            form_text = form.get_text(" ", strip=True).lower()
            if any(token in form_text for token in ("login", "sign in", "signin", "log in")):
                results["has_login_form"] = 1

            action = form.get("action")
            if action:
                action_url = urljoin(final_url, action)
                action_domain = urlparse(action_url).netloc.lower().split(":")[0]
                if action_domain and action_domain != page_domain:
                    results["external_form"] = 1

        return results

    except requests.Timeout:
        results["error"] = f"Website fetch timed out after {HTTP_TIMEOUT}s"
        logger.warning("Form analysis timeout for %s after %ss", url, HTTP_TIMEOUT)
        return results
    except Exception as exc:
        results["error"] = str(exc)
        logger.warning("Form analysis failed for %s: %s", url, exc)
        return results


def _analyze_headless_forms(url):
    results = {
        "password_detected": 0,
        "external_form": 0,
        "has_login_form": 0,
        "method": "headless",
        "error": None,
    }

    if not USE_HEADLESS_FORMS:
        return results

    try:
        from headless_analyzer import analyze_dynamic_content

        dynamic = analyze_dynamic_content(url)
        results["password_detected"] = dynamic.get("has_password_field", 0)
        results["external_form"] = dynamic.get("external_form_action", 0)
        if results["password_detected"]:
            results["has_login_form"] = 1
        return results
    except Exception as exc:
        results["error"] = str(exc)
        logger.warning("Headless form analysis failed for %s: %s", url, exc)
        return results


def _needs_headless(static_results):
    if not USE_HEADLESS_FORMS:
        return False
    if static_results.get("error"):
        return True
    return static_results["password_detected"] == 0 and static_results["has_login_form"] == 0


def _merge_results(static_results, headless_results):
    merged = static_results.copy()
    merged["password_detected"] = max(
        static_results.get("password_detected", 0),
        headless_results.get("password_detected", 0),
    )
    merged["external_form"] = max(
        static_results.get("external_form", 0),
        headless_results.get("external_form", 0),
    )
    merged["has_login_form"] = max(
        static_results.get("has_login_form", 0),
        headless_results.get("has_login_form", 0),
    )
    if headless_results.get("password_detected") or headless_results.get("external_form"):
        merged["method"] = "static+headless"
    if headless_results.get("error"):
        logger.warning("Headless form analysis failed: %s", headless_results["error"])
        if not merged.get("error"):
            merged["error"] = headless_results["error"]
    return merged
