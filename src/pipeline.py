from urllib.parse import urlparse

import pandas as pd

from brand_detector import detect_brand_impersonation
from config import setup_logging
from feature_extractor import extract_features
from form_analyzer import analyze_forms
from hosting_detector import is_suspicious_hosting
from ssl_analyzer import analyze_ssl_certificate
from threat_engine import calculate_threat_score, classify_risk
from threat_feeds import check_threat_feeds
from whitelist import is_whitelisted
from whois_analyzer import analyze_domain_age

setup_logging()


def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def analyze_url(url, model):
    """Run the full GuardianAI analysis pipeline."""
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]

    whitelisted, matched_trusted_domain = is_whitelisted(domain)
    whois_data = analyze_domain_age(domain)
    features = extract_features(url, use_whois=False, whois_data=whois_data)

    feature_frame = pd.DataFrame([features])
    ml_prediction = int(model.predict(feature_frame)[0])
    ml_confidence = round(float(model.predict_proba(feature_frame)[0][ml_prediction]) * 100, 2)

    entropy = features.get("domain_entropy", 0)
    domain_age_days = features.get("domain_age_days", -1)
    is_new_domain = features.get("is_new_domain", 0)

    brand_flag, detected_brand, brand_detail = detect_brand_impersonation(
        domain,
        is_whitelisted=whitelisted,
    )
    suspicious_hosting = is_suspicious_hosting(url)
    ssl_data = analyze_ssl_certificate(domain)
    feed_data = check_threat_feeds(url)
    form_data = analyze_forms(url)

    password_detected = form_data.get("password_detected", 0)
    external_form = form_data.get("external_form", 0)
    has_login_form = form_data.get("has_login_form", 0)

    signals = {
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "entropy": entropy,
        "domain_age_days": domain_age_days,
        "is_new_domain": is_new_domain,
        "brand_flag": brand_flag,
        "detected_brand": detected_brand,
        "brand_detail": brand_detail,
        "suspicious_hosting": suspicious_hosting,
        "password_detected": password_detected,
        "external_form": external_form,
        "has_login_form": has_login_form,
        "is_whitelisted": whitelisted,
        "matched_trusted_domain": matched_trusted_domain,
        "openphish_match": feed_data.get("openphish_match", False),
        "openphish_detail": feed_data.get("openphish_detail"),
        "phishtank_match": feed_data.get("phishtank_match", False),
        "phishtank_verified": feed_data.get("phishtank_verified", False),
        "phishtank_detail": feed_data.get("phishtank_detail"),
        "ssl_expired": ssl_data.get("expired", False),
        "ssl_self_signed": ssl_data.get("self_signed", False),
        "ssl_issuer_suspicious": ssl_data.get("issuer_suspicious", False),
        "ssl_issuer": ssl_data.get("issuer"),
        "ssl_days_until_expiry": ssl_data.get("days_until_expiry"),
        "ssl_error": ssl_data.get("error"),
    }

    score, reasons = calculate_threat_score(signals)
    risk = classify_risk(score)

    explanation = build_explanation(
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
        entropy=entropy,
        domain_age_days=domain_age_days,
        brand_flag=brand_flag,
        detected_brand=detected_brand,
        features=features,
        whitelisted=whitelisted,
        feed_data=feed_data,
        password_detected=password_detected,
        external_form=external_form,
        has_login_form=has_login_form,
        ssl_data=ssl_data,
    )

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "risk": risk,
        "confidence": ml_confidence,
        "reasons": reasons,
        "explanation": explanation,
        "signals": signals,
        "features": features,
        "whois": whois_data,
        "ssl": ssl_data,
        "feeds": feed_data,
        "forms": form_data,
    }


def build_explanation(
    ml_prediction,
    ml_confidence,
    entropy,
    domain_age_days,
    brand_flag,
    detected_brand,
    features,
    whitelisted,
    feed_data,
    password_detected,
    external_form,
    has_login_form,
    ssl_data,
):
    return {
        "ML Prediction": "Phishing" if ml_prediction == 1 else "Safe",
        "ML Confidence (%)": ml_confidence,
        "Domain Entropy": round(entropy, 3),
        "Domain Age (days)": domain_age_days if domain_age_days >= 0 else "Unknown",
        "Brand Similarity": detected_brand if brand_flag else "None",
        "Unicode Spoof": features.get("unicode_spoof", 0),
        "Base64 Payload": features.get("base64_detected", 0),
        "Whitelisted": whitelisted,
        "OpenPhish Match": feed_data.get("openphish_match", False),
        "PhishTank Match": feed_data.get("phishtank_match", False),
        "Password Field": bool(password_detected),
        "External Form": bool(external_form),
        "Login Form": bool(has_login_form),
        "SSL Issuer": ssl_data.get("issuer") or "Unknown",
    }


def format_web_result(analysis):
    """Payload used by the Flask app template."""
    return {
        "url": analysis["url"],
        "score": analysis["score"],
        "risk": analysis["risk"],
        "confidence": analysis["confidence"],
        "reasons": analysis["reasons"],
        "explanation": analysis["explanation"],
    }


def format_cli_report(analysis):
    """Human-readable report shared by predict.py and validation tooling."""
    lines = [
        "",
        "===== Threat Analysis Report =====",
        f"URL: {analysis['url']}",
        f"Threat Score: {analysis['score']} / 100",
        f"Risk Level: {analysis['risk']}",
        "",
        "Reasons:",
    ]

    for reason in analysis["reasons"]:
        lines.append(f"- {reason}")

    lines.extend(
        [
            "",
            "Technical Details:",
            f"- ML Confidence: {analysis['confidence']}%",
            f"- Domain Entropy: {analysis['explanation']['Domain Entropy']}",
            f"- Domain Age (days): {analysis['explanation']['Domain Age (days)']}",
            f"- Whitelisted: {analysis['explanation']['Whitelisted']}",
            f"- OpenPhish Match: {analysis['explanation']['OpenPhish Match']}",
            f"- PhishTank Match: {analysis['explanation']['PhishTank Match']}",
            f"- Password Field Detected: {analysis['explanation']['Password Field']}",
            f"- External Form Submission: {analysis['explanation']['External Form']}",
            f"- Login Form Detected: {analysis['explanation']['Login Form']}",
        ]
    )

    return "\n".join(lines)
