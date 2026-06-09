import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from brand_detector import detect_brand_impersonation
from config import RISK_HIGH_THRESHOLD, WHITELIST_SCORE_CAP
from entropy_utils import calculate_entropy, domain_entropy
from hosting_detector import is_suspicious_hosting
from pipeline import analyze_url, format_cli_report, format_web_result, normalize_url
from threat_engine import calculate_threat_score, classify_risk
from threat_feeds import get_feed_checker
from whitelist import is_whitelisted


class MockModel:
    """Deterministic model stub for pipeline tests."""

    def __init__(self, prediction=0, confidence=0.12):
        self.prediction = prediction
        self.confidence = confidence

    def predict(self, frame):
        return [self.prediction]

    def predict_proba(self, frame):
        if self.prediction == 1:
            return [[1 - self.confidence, self.confidence]]
        return [[self.confidence, 1 - self.confidence]]


def _safe_external_patches():
    return (
        patch("pipeline.analyze_domain_age", return_value={
            "domain_age_days": 5000,
            "is_new_domain": 0,
            "registrar": "Test Registrar",
            "creation_date": "2010-01-01T00:00:00+00:00",
            "error": None,
        }),
        patch("pipeline.analyze_ssl_certificate", return_value={
            "available": True,
            "expired": False,
            "self_signed": False,
            "issuer_suspicious": False,
            "issuer": "CN=Test CA",
            "subject": "CN=example.com",
            "days_until_expiry": 90,
            "error": None,
        }),
        patch("pipeline.analyze_forms", return_value={
            "password_detected": 0,
            "external_form": 0,
            "has_login_form": 0,
            "method": "static",
            "error": None,
        }),
        patch("pipeline.check_threat_feeds", return_value={
            "openphish_match": False,
            "openphish_detail": None,
            "phishtank_match": False,
            "phishtank_verified": False,
            "phishtank_detail": "PhishTank API key not configured (set PHISHTANK_API_KEY)",
            "feed_errors": [],
        }),
    )


class ConsolidationTests(unittest.TestCase):
    def test_entropy_single_source(self):
        self.assertEqual(calculate_entropy("abc"), domain_entropy("a.bc"))

    def test_hosting_uses_config(self):
        self.assertTrue(is_suspicious_hosting("https://foo.ngrok.io/login"))
        self.assertFalse(is_suspicious_hosting("https://github.com"))

    def test_brand_skipped_for_whitelisted_domain(self):
        flag, _, _ = detect_brand_impersonation("gogle.com", is_whitelisted=False)
        self.assertTrue(flag)
        flag, _, _ = detect_brand_impersonation("google.com", is_whitelisted=True)
        self.assertFalse(flag)


class WhitelistSafetyTests(unittest.TestCase):
    TRUSTED_URLS = [
        "https://github.com",
        "https://google.com",
        "https://www.microsoft.com",
    ]

    def test_trusted_domains_recognized(self):
        for url in self.TRUSTED_URLS:
            trusted, matched = is_whitelisted(url)
            self.assertTrue(trusted, msg=url)
            self.assertIsNotNone(matched)

    def test_trusted_domains_never_high_without_feed(self):
        for url in self.TRUSTED_URLS:
            signals = {
                "ml_prediction": 1,
                "ml_confidence": 95,
                "entropy": 4.5,
                "domain_age_days": 5000,
                "is_new_domain": 0,
                "brand_flag": True,
                "detected_brand": "google",
                "suspicious_hosting": True,
                "password_detected": 1,
                "external_form": 1,
                "has_login_form": 1,
                "is_whitelisted": True,
                "matched_trusted_domain": is_whitelisted(url)[1],
                "openphish_match": False,
                "phishtank_match": False,
                "ssl_expired": True,
                "ssl_self_signed": True,
            }
            score, reasons = calculate_threat_score(signals)
            self.assertLessEqual(score, WHITELIST_SCORE_CAP, msg=url)
            self.assertNotEqual(classify_risk(score), "HIGH", msg=url)
            self.assertTrue(any("whitelist" in reason.lower() for reason in reasons))

    def test_trusted_domain_can_be_high_with_feed_hit(self):
        signals = {
            "ml_prediction": 1,
            "ml_confidence": 95,
            "entropy": 4.5,
            "domain_age_days": 5000,
            "is_new_domain": 0,
            "brand_flag": False,
            "suspicious_hosting": False,
            "password_detected": 0,
            "external_form": 0,
            "has_login_form": 0,
            "is_whitelisted": True,
            "matched_trusted_domain": "google.com",
            "openphish_match": True,
            "openphish_detail": "Exact URL match in OpenPhish feed",
            "phishtank_match": False,
        }
        score, _ = calculate_threat_score(signals)
        self.assertGreaterEqual(score, RISK_HIGH_THRESHOLD)


class OpenPhishTests(unittest.TestCase):
    SAMPLE_URL = "http://openphish-sample.test/phish"

    def setUp(self):
        self.checker = get_feed_checker()
        self.checker.load_openphish_entries([self.SAMPLE_URL])

    def test_openphish_sample_detected(self):
        result = self.checker.check_openphish(self.SAMPLE_URL)
        self.assertTrue(result["match"])

    def test_openphish_sample_scores_high(self):
        signals = {
            "ml_prediction": 0,
            "ml_confidence": 10,
            "entropy": 2.0,
            "domain_age_days": 100,
            "is_new_domain": 0,
            "brand_flag": False,
            "suspicious_hosting": False,
            "password_detected": 0,
            "external_form": 0,
            "has_login_form": 0,
            "is_whitelisted": False,
            "openphish_match": True,
            "openphish_detail": "Exact URL match in OpenPhish feed",
            "phishtank_match": False,
        }
        score, reasons = calculate_threat_score(signals)
        self.assertGreaterEqual(score, 40)
        self.assertTrue(any("OpenPhish" in reason or "Threat intelligence" in reason for reason in reasons))


class PipelineConsistencyTests(unittest.TestCase):
    def test_app_and_cli_outputs_match(self):
        model = MockModel(prediction=1, confidence=0.91)
        patches = _safe_external_patches()

        with patches[0], patches[1], patches[2], patches[3]:
            analysis = analyze_url("https://github.com", model)
            web = format_web_result(analysis)
            cli = format_cli_report(analysis)

        self.assertEqual(web["score"], analysis["score"])
        self.assertEqual(web["risk"], analysis["risk"])
        self.assertEqual(web["reasons"], analysis["reasons"])
        self.assertIn(str(analysis["score"]), cli)
        self.assertIn(analysis["risk"], cli)

    def test_trusted_urls_low_risk_in_pipeline(self):
        model = MockModel(prediction=1, confidence=0.95)
        patches = _safe_external_patches()

        for url in ["https://github.com", "https://google.com", "https://microsoft.com"]:
            with patches[0], patches[1], patches[2], patches[3]:
                analysis = analyze_url(url, model)
            self.assertNotEqual(
                analysis["risk"],
                "HIGH",
                msg=f"{url} should not be HIGH without feed match (score={analysis['score']})",
            )

    def test_paypal_not_whitelisted(self):
        trusted, _ = is_whitelisted("https://paypal.com")
        self.assertFalse(trusted)

    def test_paypal_pipeline_with_safe_model(self):
        model = MockModel(prediction=0, confidence=0.08)
        patches = _safe_external_patches()

        with patches[0], patches[1], patches[2], patches[3]:
            analysis = analyze_url("https://paypal.com", model)

        self.assertFalse(analysis["signals"]["is_whitelisted"])
        self.assertIn(analysis["risk"], ("LOW", "MEDIUM"))

    def test_normalize_url_consistent(self):
        self.assertEqual(normalize_url("github.com"), "http://github.com")


class CacheTests(unittest.TestCase):
    def test_whois_cache_avoids_duplicate_lookup(self):
        from whois_analyzer import analyze_domain_age

        with patch("whois_analyzer._whois_lookup", return_value={
            "domain_age_days": 100,
            "is_new_domain": 0,
            "registrar": "Cached Registrar",
            "creation_date": "2020-01-01T00:00:00+00:00",
            "error": None,
        }) as lookup:
            first = analyze_domain_age("cache-test.example")
            second = analyze_domain_age("cache-test.example")
            self.assertEqual(first["domain_age_days"], 100)
            self.assertEqual(second["domain_age_days"], 100)
            self.assertEqual(lookup.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
