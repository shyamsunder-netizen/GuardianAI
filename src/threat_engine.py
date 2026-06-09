from config import (
    RISK_HIGH_THRESHOLD,
    RISK_MEDIUM_THRESHOLD,
    SCORE_WEIGHTS,
    WHITELIST_SCORE_CAP,
    ENTROPY_THRESHOLD,
)


def classify_risk(score):
    if score >= RISK_HIGH_THRESHOLD:
        return "HIGH"
    if score >= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def calculate_threat_score(signals):
    weights = SCORE_WEIGHTS
    score = 0.0
    reasons = []

    ml_prediction = signals.get("ml_prediction", 0)
    ml_confidence = signals.get("ml_confidence", 0)
    entropy = signals.get("entropy", 0)
    domain_age_days = signals.get("domain_age_days", -1)
    brand_flag = signals.get("brand_flag", False)
    detected_brand = signals.get("detected_brand")
    suspicious_hosting = signals.get("suspicious_hosting", False)
    password_detected = signals.get("password_detected", 0)
    external_form = signals.get("external_form", 0)
    has_login_form = signals.get("has_login_form", 0)

    feed_hit = signals.get("openphish_match") or signals.get("phishtank_match")

    if signals.get("openphish_match"):
        score += weights["openphish_match"]
        detail = signals.get("openphish_detail") or "OpenPhish feed match"
        reasons.append(f"Threat intelligence: {detail}")

    if signals.get("phishtank_match"):
        if signals.get("phishtank_verified"):
            score += weights["phishtank_verified"]
            reasons.append("Threat intelligence: URL verified as phishing on PhishTank")
        else:
            score += weights["phishtank_unverified"]
            detail = signals.get("phishtank_detail") or "PhishTank listing"
            reasons.append(f"Threat intelligence: {detail}")

    if ml_prediction == 1:
        ml_points = ml_confidence * weights["ml_multiplier"]
        score += ml_points
        reasons.append(
            f"Machine learning model flagged this URL as phishing ({ml_confidence:.1f}% confidence)"
        )

    if entropy > ENTROPY_THRESHOLD:
        score += weights["entropy"]
        reasons.append(
            f"High domain randomness detected (entropy {entropy:.2f} exceeds {ENTROPY_THRESHOLD})"
        )

    if suspicious_hosting:
        score += weights["suspicious_hosting"]
        reasons.append("URL uses a hosting provider commonly abused for phishing infrastructure")

    if brand_flag:
        score += weights["brand_impersonation"]
        brand_label = detected_brand or "a trusted brand"
        reasons.append(f"Domain appears to impersonate {brand_label}")

    if signals.get("is_new_domain") and domain_age_days >= 0:
        score += weights["new_domain"]
        reasons.append(
            f"Domain was registered recently ({domain_age_days} days ago), which is common for phishing sites"
        )

    if signals.get("ssl_expired"):
        score += weights["ssl_expired"]
        reasons.append("SSL/TLS certificate has expired")

    if signals.get("ssl_self_signed"):
        score += weights["ssl_self_signed"]
        reasons.append("Self-signed SSL/TLS certificate detected")

    if signals.get("ssl_issuer_suspicious"):
        score += weights["ssl_issuer_mismatch"]
        issuer = signals.get("ssl_issuer") or "unknown issuer"
        reasons.append(f"SSL certificate issuer may not match the domain ({issuer})")

    if password_detected:
        score += weights["password_field"]
        reasons.append("Page contains a password input field")

    if external_form:
        score += weights["external_form"]
        reasons.append("Form submits data to a different domain than the page URL")

    if has_login_form:
        score += weights["login_form"]
        reasons.append("Login form detected on the page")

    if ml_prediction == 0 and entropy > ENTROPY_THRESHOLD and suspicious_hosting:
        score += weights["stealth_phishing"]
        reasons.append(
            "Stealth phishing pattern: safe ML classification combined with suspicious hosting and high entropy"
        )

    if signals.get("is_whitelisted") and not feed_hit:
        matched = signals.get("matched_trusted_domain") or "trusted domain"
        if score > WHITELIST_SCORE_CAP:
            reasons.append(
                f"Trusted domain whitelist applied for {matched}; score reduced to limit false positives"
            )
        score = min(score, WHITELIST_SCORE_CAP)
    elif signals.get("is_whitelisted") and feed_hit:
        reasons.append(
            "URL matches a trusted domain pattern but remains flagged due to threat feed intelligence"
        )

    if not reasons:
        reasons.append("No significant phishing indicators detected")

    if score > 100:
        score = 100

    return int(round(score)), reasons


def calculate_threat_score_legacy(
    ml_prediction,
    ml_confidence,
    entropy,
    domain_age,
    brand_flag,
    suspicious_hosting,
    password_detected,
    external_form,
):
    """Backward-compatible wrapper for older callers."""
    signals = {
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "entropy": entropy,
        "domain_age_days": domain_age,
        "is_new_domain": 1 if isinstance(domain_age, (int, float)) and 0 <= domain_age < 30 else 0,
        "brand_flag": brand_flag,
        "suspicious_hosting": suspicious_hosting,
        "password_detected": password_detected,
        "external_form": external_form,
        "has_login_form": 0,
        "is_whitelisted": False,
        "openphish_match": False,
        "phishtank_match": False,
    }
    return calculate_threat_score(signals)
