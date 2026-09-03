"""
Email Header & Sender Reputation Analysis Service
Parses SPF, DKIM, DMARC, display-name spoofing,
Reply-To mismatch, and routing anomalies.
"""
import re
import email as email_lib
from typing import Dict, Optional
from urllib.parse import urlparse

import dns.resolver

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "chase", "citibank", "ebay", "linkedin", "twitter",
    "irs", "hmrc", "docusign", "dropbox",
]


def analyze_headers(raw_headers: str, sender_email: str = "") -> Dict:
    """
    Parse raw email headers string and return a risk feature dict.
    """
    if not raw_headers:
        return _empty_result()

    headers = _parse_headers(raw_headers)

    spf_result        = _check_spf(headers)
    dkim_valid        = _check_dkim(headers)
    dmarc_policy      = _check_dmarc(sender_email)
    spoofing_flag     = _check_display_name_spoofing(headers, sender_email)
    reply_to_mismatch = _check_reply_to_mismatch(headers, sender_email)
    routing_anomaly   = _check_routing_anomaly(headers)
    sender_domain     = _extract_domain(sender_email)
    display_name      = _extract_display_name(headers)

    header_risk_score = _calculate_header_risk(
        spf_result, dkim_valid, spoofing_flag, reply_to_mismatch, routing_anomaly
    )

    return {
        "spf_result":          spf_result,
        "dkim_valid":          dkim_valid,
        "dmarc_policy":        dmarc_policy,
        "spoofing_flag":       spoofing_flag,
        "reply_to_mismatch":   reply_to_mismatch,
        "routing_anomaly":     routing_anomaly,
        "sender_domain":       sender_domain,
        "display_name":        display_name,
        "header_risk_score":   round(header_risk_score, 2),
    }


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_headers(raw: str) -> Dict[str, str]:
    """Convert raw header string to lowercase-keyed dict."""
    headers = {}
    try:
        msg = email_lib.message_from_string(raw)
        for key in msg.keys():
            headers[key.lower()] = str(msg[key])
    except Exception:
        # Fallback: simple line parsing
        for line in raw.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()
    return headers


def _check_spf(headers: Dict) -> str:
    """Extract SPF result from Received-SPF or Authentication-Results headers."""
    for key in ["received-spf", "authentication-results"]:
        val = headers.get(key, "").lower()
        if "pass" in val:
            return "pass"
        if "fail" in val and "softfail" not in val:
            return "fail"
        if "softfail" in val:
            return "softfail"
        if "neutral" in val:
            return "neutral"
    return "none"


def _check_dkim(headers: Dict) -> bool:
    """Return True if DKIM-Signature is present and looks valid."""
    dkim = headers.get("dkim-signature", "")
    if not dkim:
        return False
    # Minimal validity: must contain v=1 and a=rsa-sha256
    return "v=1" in dkim and ("a=rsa-sha256" in dkim or "a=rsa-sha1" in dkim)


def _check_dmarc(sender_email: str) -> str:
    """
    Look up DMARC TXT record for the sender's domain via DNS.
    Returns 'reject' | 'quarantine' | 'none' | 'unknown'.
    """
    domain = _extract_domain(sender_email)
    if not domain:
        return "unknown"
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = str(rdata).lower()
            if "p=reject" in txt:
                return "reject"
            if "p=quarantine" in txt:
                return "quarantine"
            if "p=none" in txt:
                return "none"
    except Exception:
        pass
    return "unknown"


def _check_display_name_spoofing(headers: Dict, sender_email: str) -> bool:
    """
    Flag if the From display name contains a brand keyword
    but the actual sender domain does not match that brand.
    """
    from_header   = headers.get("from", "")
    sender_domain = _extract_domain(sender_email).lower()
    # Extract display name (text before <email>)
    display_match = re.match(r'^"?([^<"]+)"?\s*<', from_header)
    if not display_match:
        return False
    display_name = display_match.group(1).lower()

    for brand in BRAND_KEYWORDS:
        if brand in display_name:
            if brand not in sender_domain:
                return True
    return False


def _check_reply_to_mismatch(headers: Dict, sender_email: str) -> bool:
    """Flag if Reply-To domain differs from From domain."""
    reply_to = headers.get("reply-to", "")
    if not reply_to:
        return False
    reply_domain  = _extract_domain(reply_to)
    sender_domain = _extract_domain(sender_email)
    return bool(reply_domain and sender_domain and reply_domain != sender_domain)


def _check_routing_anomaly(headers: Dict) -> bool:
    """
    Heuristic: flag if the Received chain has more than 5 hops
    or contains IPs from multiple highly different regions (simplified).
    """
    received_headers = [v for k, v in headers.items() if k == "received"]
    if len(received_headers) > 5:
        return True
    # Look for obvious mismatches (e.g., from-domain in Received doesn't match)
    for header in received_headers:
        if "forged" in header.lower() or "unknown" in header.lower():
            return True
    return False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_domain(email_str: str) -> str:
    """Extract domain from an email address like 'Name <user@domain.com>'."""
    match = re.search(r"@([\w.\-]+)", email_str or "")
    return match.group(1).lower() if match else ""


def _extract_display_name(headers: Dict) -> str:
    from_header = headers.get("from", "")
    match = re.match(r'^"?([^<"]+)"?\s*<', from_header)
    if match:
        return match.group(1).strip()[:255]
    return from_header[:255]


def _calculate_header_risk(spf, dkim_valid, spoofing, reply_mismatch, routing) -> float:
    score = 0.0
    if spf in ("fail", "softfail"):     score += 25.0
    if spf == "none":                   score += 10.0
    if not dkim_valid:                  score += 20.0
    if spoofing:                        score += 35.0
    if reply_mismatch:                  score += 15.0
    if routing:                         score += 10.0
    return min(100.0, score)


def _empty_result() -> Dict:
    return {
        "spf_result":        "none",
        "dkim_valid":        False,
        "dmarc_policy":      "unknown",
        "spoofing_flag":     False,
        "reply_to_mismatch": False,
        "routing_anomaly":   False,
        "sender_domain":     "",
        "display_name":      "",
        "header_risk_score": 0.0,
    }
