"""
NLP Analyzer — Robust version with Trusted Domain Whitelist.
Real emails from Google, Microsoft etc. are never flagged.
"""
import re
from typing import Dict, List

# ── Trusted domains — NEVER flag as phishing ──────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com", "accounts.google.com", "mail.google.com",
    "notifications.google.com", "no-reply.accounts.google.com",
    "microsoft.com", "live.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com", "amazon.com", "amazonses.com",
    "paypal.com", "ebay.com", "facebook.com", "instagram.com",
    "twitter.com", "linkedin.com", "github.com", "netflix.com",
    "spotify.com", "adobe.com", "dropbox.com", "zoom.us",
    "yahoo.com", "gmail.com",
}

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "action required",
    "expires", "limited time", "last chance", "final notice",
    "account suspended", "verify now", "confirm now", "24 hours",
    "account will be closed", "security alert", "warning", "critical",
    "do not delay", "time sensitive", "act immediately", "respond now",
    "will be deleted", "permanently deleted", "permanently erased",
    "do not ignore", "expire", "blocked", "locked", "unauthorized",
    "unusual activity", "suspicious activity", "account expires",
    "verify immediately", "suspended", "terminated", "flagged",
    "compromised", "breached", "hacked", "stolen",
]

CREDENTIAL_KEYWORDS = [
    "password", "username", "login", "sign in", "credentials",
    "bank account", "credit card", "social security", "ssn",
    "verify your account", "update your information", "billing",
    "confirm your identity", "payment details", "account number",
    "cvv", "verification", "enter your",
]

SUSPICIOUS_KEYWORDS = [
    "click here immediately", "follow the link", "you have won",
    "congratulations", "free prize", "gift card", "wire transfer",
    "bitcoin", "verify account", "confirm account", "validate your",
    "save your account", "restore your account",
]

NEGATIVE_WORDS = [
    "suspended", "terminated", "deleted", "blocked", "locked",
    "expired", "unauthorized", "illegal", "violation", "fraud",
    "dangerous", "risk", "warning", "alert", "critical", "urgent",
    "final", "failed", "erased", "permanently", "consequences",
    "legal action", "law enforcement",
]

KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bank of america", "chase", "citibank", "wells fargo",
    "irs", "hmrc", "ebay", "dropbox", "docusign", "linkedin",
    "outlook", "gmail", "yahoo", "instagram", "twitter",
]

SUSPICIOUS_TLDS = {
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click",
    "loan", "work", "pw", "cc", "online", "site", "space",
}


def _extract_sender_domain(sender_email: str) -> str:
    """Extract domain from sender like 'Google <no-reply@accounts.google.com>'"""
    sender_lower = sender_email.lower()
    # Handle "Display Name <email@domain.com>" format
    if "<" in sender_lower:
        match = re.search(r'@([\w.\-]+)>', sender_lower)
        if match:
            return match.group(1).strip()
    # Handle plain "email@domain.com" format
    if "@" in sender_lower:
        return sender_lower.split("@")[-1].strip().strip(">")
    return sender_lower


def _is_trusted_sender(sender_domain: str) -> bool:
    """Check if sender is from a trusted domain."""
    for trusted in TRUSTED_DOMAINS:
        if sender_domain == trusted or sender_domain.endswith("." + trusted):
            return True
    return False


def analyze_text(email_body: str, sender_email: str = "") -> Dict:
    """
    Analyze email for phishing. Trusted senders always return SAFE.
    """
    # ── Trusted sender check (first priority) ────────────────────────────────
    sender_domain = _extract_sender_domain(sender_email)

    if _is_trusted_sender(sender_domain):
        return {
            "urgency_score":       0.0,
            "sentiment_score":     0.0,
            "grammar_error_rate":  0.0,
            "impersonation_score": 0.0,
            "keyword_density":     0.0,
            "suspicious_keywords": "",
            "text_risk_score":     0.0,
        }

    # ── Analyze sender domain for suspicious signals ──────────────────────────
    sender_score = _analyze_sender_domain(sender_domain)

    # ── If body is empty, use sender domain score ─────────────────────────────
    if not email_body or not email_body.strip():
        return {
            "urgency_score":       sender_score,
            "sentiment_score":     0.5 if sender_score > 30 else 0.0,
            "grammar_error_rate":  0.0,
            "impersonation_score": sender_score,
            "keyword_density":     0.0,
            "suspicious_keywords": f"suspicious_domain:{sender_domain}" if sender_score > 0 else "",
            "text_risk_score":     round(min(100.0, sender_score), 2),
        }

    # ── Clean HTML ────────────────────────────────────────────────────────────
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', email_body,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'&[a-z#0-9]+;', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    text_lower = text.lower()

    words      = text_lower.split()
    word_count = max(len(words), 1)
    sentences  = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]

    urgency_score       = _urgency_score(text_lower)
    sentiment_score     = _sentiment_score(text_lower)
    grammar_error_rate  = _grammar_error_rate(sentences, word_count)
    impersonation_score = max(
        _impersonation_score(text_lower, sender_email),
        sender_score
    )
    keyword_density     = _keyword_density(words, word_count)
    suspicious_kws      = _extract_suspicious_keywords(text_lower)

    if sender_score > 0:
        suspicious_kws.append(f"suspicious_domain:{sender_domain}")

    text_risk_score = min(100.0, (
        urgency_score              * 0.30 +
        (sentiment_score * 100)    * 0.15 +
        (grammar_error_rate * 100) * 0.10 +
        impersonation_score        * 0.25 +
        (keyword_density * 100)    * 0.20
    ))

    # Boost if sender domain is suspicious
    if sender_score > 50:
        text_risk_score = min(100.0, text_risk_score + 20)

    return {
        "urgency_score":       round(urgency_score, 2),
        "sentiment_score":     round(sentiment_score, 4),
        "grammar_error_rate":  round(grammar_error_rate, 4),
        "impersonation_score": round(impersonation_score, 2),
        "keyword_density":     round(keyword_density, 4),
        "suspicious_keywords": ", ".join(suspicious_kws[:15]),
        "text_risk_score":     round(text_risk_score, 2),
    }


def _analyze_sender_domain(domain: str) -> float:
    """Score suspicious sender domains."""
    if not domain:
        return 0.0
    score = 0.0
    tld = domain.split(".")[-1] if "." in domain else ""

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        score += 60.0

    # Number substitution (m1crosoft, paypa1 etc.)
    denumbered = (domain.replace("0", "o").replace("1", "l")
                        .replace("3", "e").replace("4", "a")
                        .replace("5", "s"))
    for brand in KNOWN_BRANDS:
        brand_clean = brand.replace(" ", "")
        if brand_clean in denumbered and brand_clean not in domain:
            score += 50.0
            break
        if (brand_clean in domain
                and not domain.startswith(brand_clean + ".")
                and tld not in ["com", "org", "net", "gov", "edu", "co"]):
            score += 40.0
            break

    return min(100.0, score)


def _urgency_score(text_lower: str) -> float:
    hits         = sum(1 for kw in URGENCY_KEYWORDS if kw in text_lower)
    first_line   = text_lower.split('\n')[0]
    subject_hits = sum(1 for kw in URGENCY_KEYWORDS if kw in first_line)
    return min(100.0, (hits + subject_hits) * 6.0)


def _sentiment_score(text_lower: str) -> float:
    negative_count    = sum(1 for w in NEGATIVE_WORDS if w in text_lower)
    exclamation_count = text_lower.count('!')
    total = negative_count + (exclamation_count * 0.5)
    return min(1.0, total / 10.0)


def _grammar_error_rate(sentences: list, word_count: int) -> float:
    errors = 0
    for sent in sentences:
        if re.search(r'[.,][A-Za-z]', sent):
            errors += 1
        if re.search(r'[!?]{2,}', sent):
            errors += 1
        caps = [w for w in sent.split()
                if len(w) > 3 and w.isupper() and w.isalpha()]
        errors += len(caps)
    return min(1.0, errors / max(word_count, 1))


def _impersonation_score(text_lower: str, sender_email: str) -> float:
    sender_lower = sender_email.lower()
    hits = 0
    for brand in KNOWN_BRANDS:
        if brand in text_lower:
            brand_domain = brand.replace(" ", "") + ".com"
            if brand_domain not in sender_lower:
                hits += 1
    return min(100.0, hits * 30.0)


def _keyword_density(words: list, word_count: int) -> float:
    all_kws = set()
    for kw_list in [URGENCY_KEYWORDS, CREDENTIAL_KEYWORDS, SUSPICIOUS_KEYWORDS]:
        for kw in kw_list:
            all_kws.update(kw.split())
    hits = sum(1 for w in words if w in all_kws)
    return min(1.0, hits / word_count)


def _extract_suspicious_keywords(text_lower: str) -> List[str]:
    found = []
    for kw in URGENCY_KEYWORDS + CREDENTIAL_KEYWORDS + SUSPICIOUS_KEYWORDS:
        if kw in text_lower and kw not in found:
            found.append(kw)
    return found
