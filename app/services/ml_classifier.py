"""
ML Classifier — Robust scoring with proper weights.
"""
import os
import logging
from typing import Dict, List
import numpy as np

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "urgency_score", "sentiment_score", "grammar_error_rate",
    "impersonation_score", "keyword_density", "text_risk_score",
    "max_link_risk", "mismatch_count", "homoglyph_count",
    "malicious_link_count", "spf_fail", "dkim_fail",
    "spoofing", "reply_mismatch", "sender_rep_score",
]

FEATURE_EXPLANATIONS = {
    "urgency_score":       "creates false urgency to pressure you into acting immediately",
    "sentiment_score":     "uses threatening or negative language",
    "grammar_error_rate":  "contains unusual grammar errors common in phishing emails",
    "impersonation_score": "impersonates a trusted brand such as Microsoft or PayPal",
    "keyword_density":     "contains a high density of phishing-related keywords",
    "text_risk_score":     "has suspicious text content patterns",
    "max_link_risk":       "contains a suspicious or dangerous link",
    "mismatch_count":      "contains a mismatched link where the text doesn't match the URL",
    "homoglyph_count":     "uses a lookalike domain name designed to deceive",
    "malicious_link_count":"contains a link flagged as malicious",
    "spf_fail":            "failed SPF authentication — may not be from the claimed sender",
    "dkim_fail":           "failed DKIM signature check",
    "spoofing":            "the sender display name does not match their actual email domain",
    "reply_mismatch":      "replies would go to a different address than the sender",
    "sender_rep_score":    "the sender has a history of sending phishing emails",
}


def build_feature_vector(nlp, links, header, sender_rep_rate=0.0):
    urgency       = nlp.get("urgency_score", 0.0) / 100.0
    sentiment     = min(1.0, nlp.get("sentiment_score", 0.0))
    grammar       = nlp.get("grammar_error_rate", 0.0)
    impersonation = nlp.get("impersonation_score", 0.0) / 100.0
    keyword       = nlp.get("keyword_density", 0.0)
    text_risk     = nlp.get("text_risk_score", 0.0) / 100.0
    max_link      = max((l.get("link_risk_score",0.0) for l in links), default=0.0) / 100.0
    mismatch      = min(1.0, sum(1 for l in links if l.get("mismatch_flag")) / max(len(links),1))
    homoglyph     = min(1.0, sum(1 for l in links if l.get("homoglyph_flag")) / max(len(links),1))
    malicious     = min(1.0, sum(1 for l in links if l.get("reputation")=="malicious") / max(len(links),1))
    spf_fail      = 1.0 if header.get("spf_result") in ("fail","softfail","none") else 0.0
    dkim_fail     = 0.0 if header.get("dkim_valid") else 1.0
    spoofing      = 1.0 if header.get("spoofing_flag") else 0.0
    reply_mis     = 1.0 if header.get("reply_to_mismatch") else 0.0
    rep           = float(sender_rep_rate)

    return np.array([
        urgency, sentiment, grammar, impersonation, keyword, text_risk,
        max_link, mismatch, homoglyph, malicious,
        spf_fail, dkim_fail, spoofing, reply_mis, rep,
    ], dtype=np.float32)


def classify_email(nlp, links, header, sender_rep_rate=0.0,
                   model_path=None, threshold=65):

    features = build_feature_vector(nlp, links, header, sender_rep_rate)

    # Try ML model
    if model_path and JOBLIB_AVAILABLE and os.path.exists(model_path):
        try:
            model      = joblib.load(model_path)
            proba      = model.predict_proba(features.reshape(1, -1))[0]
            phish_prob = proba[1] if len(proba) > 1 else proba[0]
            risk_score = round(float(phish_prob) * 100.0, 2)
        except Exception as e:
            logger.warning(f"ML model error: {e}, using rule-based")
            risk_score = _rule_based_score(features, nlp, links, header)
    else:
        risk_score = _rule_based_score(features, nlp, links, header)

    # Hard rules — override ML for obvious cases
    risk_score = _apply_hard_rules(risk_score, nlp, links, header)

    if risk_score >= threshold:
        label = "phishing"
    elif risk_score >= 35:
        label = "suspicious"
    else:
        label = "safe"

    top_features   = _top_features(features)
    explanation    = _build_explanation(top_features, label)

    return {
        "risk_score":       risk_score,
        "label":            label,
        "top_feature_1":    top_features[0] if len(top_features) > 0 else None,
        "top_feature_2":    top_features[1] if len(top_features) > 1 else None,
        "top_feature_3":    top_features[2] if len(top_features) > 2 else None,
        "explanation_text": explanation,
    }


def _rule_based_score(features, nlp, links, header) -> float:
    """Weighted rule-based score."""
    weights = np.array([
        15, 10, 5, 15, 8, 15,   # NLP (text_risk gets high weight)
        12, 8, 10, 15,           # Links
        5, 5, 10, 5, 7           # Headers + rep
    ], dtype=np.float32)
    raw = float(np.dot(features, weights))
    return round(min(100.0, raw * 100.0 / weights.sum()), 2)


def _apply_hard_rules(score, nlp, links, header) -> float:
    """
    Hard rules for phishing indicators.
    A single weak/moderate signal pushes into the SUSPICIOUS (spam) band;
    only a confirmed-malicious link or a combination of strong signals
    pushes into the PHISHING (quarantine) band.
    """
    for link in links:
        if link.get("suspicious_tld"):
            score = max(score, 45.0)
        if link.get("homoglyph_flag"):
            score = max(score, 55.0)
        if link.get("reputation") == "suspicious":
            score = max(score, 45.0)
        if link.get("reputation") == "malicious":
            score = max(score, 75.0)   # confirmed malicious -> quarantine

    # Brand impersonation alone -> moderate risk (spam-band)
    if nlp.get("impersonation_score", 0) > 25:
        score = max(score, 45.0)

    # High urgency + impersonation together -> strong combined signal -> quarantine
    if nlp.get("urgency_score", 0) > 40 and nlp.get("impersonation_score", 0) > 20:
        score = max(score, 65.0)

    # Spoofed sender alone -> moderate risk (spam-band)
    if header.get("spoofing_flag"):
        score = max(score, 50.0)

    # Suspicious keywords in body -> moderate risk (spam-band)
    kws = nlp.get("suspicious_keywords", "")
    if "suspicious_domain" in kws:
        score = max(score, 50.0)

    # Multiple urgent keywords -> boost
    if nlp.get("urgency_score", 0) > 60:
        score = min(100.0, score + 15)

    # High text risk -> boost
    if nlp.get("text_risk_score", 0) > 60:
        score = min(100.0, score + 10)

    return round(score, 2)


def _top_features(features) -> List[str]:
    pairs  = list(zip(FEATURE_NAMES, features.tolist()))
    sorted_feats = sorted(pairs, key=lambda x: x[1], reverse=True)
    return [name for name, val in sorted_feats[:3] if val > 0.05]


def _build_explanation(top_features, label) -> str:
    if label == "safe":
        return ("This email passed all security checks. "
                "No phishing indicators were detected.")
    if not top_features:
        return "This email was flagged based on multiple suspicious indicators."
    reasons = [FEATURE_EXPLANATIONS.get(f, f) for f in top_features[:3]]
    if len(reasons) == 1:
        return f"This email {reasons[0]}."
    elif len(reasons) == 2:
        return f"This email {reasons[0]} and {reasons[1]}."
    else:
        return f"This email {reasons[0]}, {reasons[1]}, and {reasons[2]}."
