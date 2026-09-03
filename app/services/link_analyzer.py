"""
Link & URL Analysis Service
Extracts URLs from email body, checks for anchor mismatch,
homoglyphs, suspicious TLDs, and optional Safe Browsing lookup.
"""
import re
import unicodedata
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

# ── Suspicious TLD list ───────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "loan", "work", "gq", "ml", "cf", "tk",
    "pw", "cc", "biz", "info", "mobi", "ws", "online", "site", "space",
}

# ── Well-known brand domains for homoglyph check ─────────────────────────────
BRAND_DOMAINS = {
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "google.com",
    "facebook.com", "netflix.com", "bankofamerica.com", "chase.com",
    "ebay.com", "linkedin.com", "twitter.com", "instagram.com",
}


def analyze_links(email_html: str, email_body: str, safe_browsing_key: str = "") -> List[Dict]:
    """
    Returns a list of dicts, one per URL found in the email.
    """
    links = _extract_links(email_html, email_body)
    results = []

    for anchor_text, href_url in links:
        if not href_url:
            continue
        final_url      = _follow_redirects(href_url)
        mismatch       = _check_mismatch(anchor_text, href_url)
        homoglyph      = _check_homoglyph(href_url)
        suspicious_tld = _check_suspicious_tld(href_url)
        reputation     = _check_reputation(final_url or href_url, safe_browsing_key)
        risk_score     = _calculate_link_risk(mismatch, homoglyph, suspicious_tld, reputation)

        results.append({
            "anchor_text":     anchor_text,
            "href_url":        href_url[:2000],
            "final_url":       (final_url or href_url)[:2000],
            "mismatch_flag":   mismatch,
            "reputation":      reputation,
            "homoglyph_flag":  homoglyph,
            "suspicious_tld":  suspicious_tld,
            "link_risk_score": round(risk_score, 2),
        })

    return results


def get_max_link_risk(links: List[Dict]) -> float:
    """Return the highest risk score across all links in the email."""
    if not links:
        return 0.0
    return max(l["link_risk_score"] for l in links)


# ── Extraction ────────────────────────────────────────────────────────────────

def _extract_links(html: str, plain: str) -> List[Tuple[str, str]]:
    """Extract (anchor_text, href) pairs from HTML; also plain-text URLs."""
    links = []

    if html:
        soup = BeautifulSoup(html, "lxml")
        for a_tag in soup.find_all("a", href=True):
            href   = a_tag["href"].strip()
            anchor = a_tag.get_text(strip=True) or href
            if href.startswith(("http://", "https://")):
                links.append((anchor[:500], href))

    # Plain-text URL regex
    url_pattern = re.compile(
        r"https?://[^\s<>\"']+",
        re.IGNORECASE
    )
    for url in url_pattern.findall(plain or ""):
        # Avoid duplicating what we already found from HTML
        if not any(url == h for _, h in links):
            links.append((url[:500], url))

    return links[:50]  # cap at 50 links per email


# ── Checks ────────────────────────────────────────────────────────────────────

def _check_mismatch(anchor_text: str, href_url: str) -> bool:
    """
    Flag if anchor text looks like a URL but the domain differs from href domain.
    """
    anchor_lower = anchor_text.lower().strip()
    href_parsed  = urlparse(href_url)
    href_domain  = href_parsed.netloc.lower().lstrip("www.")

    # Anchor text contains a domain-like pattern
    anchor_url_match = re.search(r"([\w-]+\.[a-z]{2,})", anchor_lower)
    if anchor_url_match:
        anchor_domain = anchor_url_match.group(1).lstrip("www.")
        if anchor_domain and anchor_domain != href_domain:
            return True
    return False


def _check_homoglyph(url: str) -> bool:
    """
    Detect lookalike domains using Unicode normalisation and known brand list.
    e.g. paypa1.com, pаypal.com (Cyrillic а)
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower().lstrip("www.")
    # Normalise to ASCII
    try:
        normalised = unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode()
    except Exception:
        normalised = domain

    for brand_domain in BRAND_DOMAINS:
        brand_name = brand_domain.split(".")[0]
        dom_name   = normalised.split(".")[0]
        # Simple Levenshtein-like check: if 1 char different and not exact match
        if dom_name != brand_name and _edit_distance(dom_name, brand_name) <= 2:
            return True
        # Number substitution: pa1pal, paypa1
        de_numbed = re.sub(r"[0-9]", lambda m: {"0":"o","1":"l","3":"e","4":"a","5":"s"}.get(m.group(),""), dom_name)
        if de_numbed == brand_name and dom_name != brand_name:
            return True

    return False


def _check_suspicious_tld(url: str) -> bool:
    extracted = tldextract.extract(url)
    return extracted.suffix.lower() in SUSPICIOUS_TLDS


def _follow_redirects(url: str, max_redirects: int = 5) -> str:
    """Follow up to max_redirects HTTP redirects and return final URL."""
    try:
        response = requests.head(
            url, allow_redirects=True, timeout=5,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        return response.url
    except Exception:
        return url


def _check_reputation(url: str, api_key: str) -> str:
    """
    Check URL against Google Safe Browsing API v4.
    Returns 'safe' | 'malicious' | 'unknown'.
    Falls back to heuristic if no API key.
    """
    if api_key:
        try:
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            resp = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=payload, timeout=5,
            )
            data = resp.json()
            if data.get("matches"):
                return "malicious"
            return "safe"
        except Exception:
            pass

    # Heuristic fallback
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if _check_suspicious_tld(url) or _check_homoglyph(url):
        return "suspicious"
    return "unknown"


def _calculate_link_risk(mismatch, homoglyph, suspicious_tld, reputation) -> float:
    score = 0.0
    if mismatch:       score += 35.0
    if homoglyph:      score += 40.0
    if suspicious_tld: score += 20.0
    if reputation == "malicious":  score += 50.0
    elif reputation == "suspicious": score += 25.0
    return min(100.0, score)


def _edit_distance(s1: str, s2: str) -> int:
    """Simple Levenshtein distance."""
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]
