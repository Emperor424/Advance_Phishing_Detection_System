"""
Gmail Direct Sync — Fixed with trusted domain whitelist.
"""
import imaplib
import email as email_lib
import logging
import threading
import time
import socket
import re
from datetime import datetime
from email.header import decode_header

logger = logging.getLogger(__name__)

GMAIL_FOLDERS = [
    ("INBOX",             "inbox", "received"),
    ("[Gmail]/Sent Mail", "sent",  "sent"),
    ("[Gmail]/Spam",      "spam",  "received"),
]

# Trusted link domains — never flag as suspicious
TRUSTED_LINK_DOMAINS = {
    "google.com", "accounts.google.com", "myaccount.google.com",
    "microsoft.com", "live.com", "office.com", "microsoftonline.com",
    "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "github.com", "linkedin.com", "twitter.com", "facebook.com",
    "instagram.com", "netflix.com", "spotify.com", "adobe.com",
    "dropbox.com", "zoom.us", "yahoo.com", "ebay.com",
    "notifications.google.com", "mail.google.com",
}


def start_gmail_sync(app):
    thread = threading.Thread(
        target=_sync_loop, args=(app,), daemon=True, name="gmail-sync"
    )
    thread.start()
    logger.info("Gmail sync started!")


def _sync_loop(app):
    while True:
        try:
            _run_session(app)
        except Exception as e:
            logger.error(f"Sync error: {e}")
            time.sleep(15)


def _run_session(app):
    cfg  = app.config
    mail = imaplib.IMAP4_SSL(
        cfg.get("IMAP_HOST", "imap.gmail.com"),
        cfg.get("IMAP_PORT", 993)
    )
    mail.login(cfg.get("IMAP_EMAIL", ""), cfg.get("IMAP_PASSWORD", ""))
    logger.info(f"Gmail connected: {cfg.get('IMAP_EMAIL')}")

    for imap_folder, pg_folder, direction in GMAIL_FOLDERS:
        _sync_folder(app, mail, imap_folder, pg_folder, direction)

    logger.info("Full sync done — IDLE starting...")
    mail.select("INBOX")
    _idle_loop(app, mail)


def _idle_loop(app, mail):
    TIMEOUT = 28 * 60
    while True:
        try:
            mail.send(b"A1 IDLE\r\n")
            mail.socket().settimeout(TIMEOUT)
            while True:
                line = mail.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="ignore")
                if "EXISTS" in decoded or "RECENT" in decoded:
                    mail.send(b"DONE\r\n")
                    time.sleep(0.5)
                    mail.select("INBOX")
                    _sync_folder(app, mail, "INBOX", "inbox", "received")
                    break
                if "BYE" in decoded:
                    mail.send(b"DONE\r\n")
                    raise Exception("Server closed")
        except socket.timeout:
            try:
                mail.send(b"DONE\r\n")
            except Exception:
                pass
            mail.select("INBOX")


def _sync_folder(app, mail, imap_folder, pg_folder, direction):
    try:
        r, _ = mail.select(f'"{imap_folder}"', readonly=True)
        if r != "OK":
            r, _ = mail.select(imap_folder, readonly=True)
            if r != "OK":
                return

        _, data = mail.search(None, "ALL")
        uids = data[0].split()
        if not uids:
            return

        new = 0
        for uid in uids:
            try:
                _, msg_data = mail.fetch(uid, "(BODY.PEEK[])")
                if not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                if not raw:
                    continue
                msg = email_lib.message_from_bytes(raw)

                with app.app_context():
                    from app import db
                    record = _save_email(
                        msg, app.config.get("IMAP_EMAIL", ""),
                        pg_folder, direction, db
                    )
                    if record:
                        new += 1
                        if direction == "received":
                            _fast_analyse(record, db, app.config)
                    db.session.remove()

            except Exception as e:
                logger.error(f"UID {uid} error: {e}")
                try:
                    with app.app_context():
                        from app import db
                        db.session.rollback()
                        db.session.remove()
                except Exception:
                    pass

        if new > 0:
            logger.info(f"{imap_folder}: {new} new email(s) synced!")

    except Exception as e:
        logger.error(f"Folder {imap_folder} error: {e}")


def _save_email(msg, imap_email, folder, direction, db):
    from app.models.email_model import Email

    message_id = msg.get("Message-ID", "")
    if message_id:
        existing = Email.query.filter_by(message_id=message_id).first()
        if existing:
            return None

    sender   = _decode_val(msg.get("From", ""))
    receiver = _decode_val(msg.get("To", imap_email))
    subject  = _decode_val(msg.get("Subject", "(No Subject)"))
    raw_hdrs = str(msg)[:8000]
    body_plain, body_html = _extract_body(msg)

    try:
        from email.utils import parsedate_to_datetime
        sent_time = parsedate_to_datetime(msg.get("Date", "")) \
            if msg.get("Date") else datetime.utcnow()
    except Exception:
        sent_time = datetime.utcnow()

    record = Email(
        user_id         = 1,    # IMAP emails belong to admin
        sender_email    = sender[:255],
        receiver_email  = receiver[:255],
        subject         = subject[:500],
        email_body      = body_plain,
        email_html      = body_html,
        raw_headers     = raw_hdrs,
        folder_status   = folder,
        email_direction = direction,
        message_id      = message_id[:500] if message_id else None,
        sent_time       = sent_time,
        received_time   = datetime.utcnow(),
        has_attachments = _has_attachments(msg),
    )
    db.session.add(record)
    db.session.commit()
    logger.info(f"Saved #{record.email_id}: {subject[:50]}")
    return record


def _fast_analyse(record, db, cfg):
    """Fast analysis with trusted sender bypass."""
    from app.models.email_model import EmailMonitoring
    from app.models.analysis import (
        NLPAnalysis, LinkAnalysis, HeaderAnalysis,
        SenderReputation, Classification
    )
    from app.models.quarantine import QuarantineItem, SystemConfig
    from app.services.nlp_analyzer import analyze_text, _extract_sender_domain, _is_trusted_sender
    from app.services.ml_classifier import classify_email
    import secrets

    mon = EmailMonitoring(
        email_id=record.email_id,
        monitoring_status="analysing",
        processing_stage="started"
    )
    db.session.add(mon)
    db.session.commit()

    try:
        # ── Check if sender is trusted → mark safe immediately ────────────────
        sender_domain = _extract_sender_domain(record.sender_email)
        is_trusted    = _is_trusted_sender(sender_domain)

        if is_trusted:
            logger.info(f"Trusted sender #{record.email_id}: {sender_domain} → SAFE")

        # ── Get best text ─────────────────────────────────────────────────────
        body = record.email_body or ""
        if not body.strip() and record.email_html:
            body = _html_to_text(record.email_html)

        # Subject with 2x weight
        subject   = record.subject or ""
        full_text = f"{subject}\n{subject}\n{body}".strip() or subject

        logger.info(
            f"Analysing #{record.email_id}: "
            f"subject='{subject[:40]}' body_len={len(body)} "
            f"trusted={is_trusted}"
        )

        # ── 1. NLP ────────────────────────────────────────────────────────────
        nlp_result = analyze_text(full_text, record.sender_email)
        db.session.add(NLPAnalysis(email_id=record.email_id, **nlp_result))
        logger.info(
            f"NLP #{record.email_id}: "
            f"urgency={nlp_result['urgency_score']:.1f} "
            f"impersonation={nlp_result['impersonation_score']:.1f} "
            f"risk={nlp_result['text_risk_score']:.1f}"
        )

        # ── 2. Links ──────────────────────────────────────────────────────────
        link_results = _fast_link_check(
            record.email_html or "", record.email_body or "",
            is_trusted=is_trusted
        )
        for lr in link_results:
            db.session.add(LinkAnalysis(email_id=record.email_id, **lr))

        # ── 3. Headers ────────────────────────────────────────────────────────
        hdr_result = _fast_header_check(
            record.raw_headers or "", record.sender_email
        )
        db.session.add(HeaderAnalysis(email_id=record.email_id, **hdr_result))
        db.session.commit()

        # ── 4. Sender Reputation ──────────────────────────────────────────────
        rep      = SenderReputation.query.filter_by(
            sender_email=record.sender_email
        ).first()
        rep_rate = rep.phishing_rate if rep else 0.0

        # ── 5. ML Classification ──────────────────────────────────────────────
        threshold  = int(SystemConfig.get("quarantine_threshold", "65"))
        clf_result = classify_email(
            nlp=nlp_result, links=link_results, header=hdr_result,
            sender_rep_rate=rep_rate, model_path=cfg.get("MODEL_PATH"),
            threshold=threshold,
        )

        # Force SAFE for trusted senders
        if is_trusted:
            clf_result["label"]            = "safe"
            clf_result["risk_score"]       = 0.0
            clf_result["explanation_text"] = "Email from trusted sender — marked safe."

        db.session.add(Classification(email_id=record.email_id, **clf_result))

        # ── 6. Route to folder ────────────────────────────────────────────────
        if clf_result["label"] == "phishing" and not is_trusted:
            record.folder_status = "quarantine"
            db.session.add(QuarantineItem(
                email_id=record.email_id, user_id=1,
                status="held", action_token=secrets.token_urlsafe(32),
            ))
            is_phishing = True
        elif clf_result["label"] == "suspicious" and not is_trusted:
            record.folder_status = "spam"
            is_phishing = True
        else:
            record.folder_status = "inbox"
            is_phishing = False

        # ── 7. Sender Reputation ──────────────────────────────────────────────
        if not rep:
            rep = SenderReputation(
                sender_email  = record.sender_email,
                sender_domain = sender_domain,
                total_emails  = 0,
                phishing_count= 0,
            )
            db.session.add(rep)
        rep.update_reputation(is_phishing)

        mon.monitoring_status = "completed"
        mon.processing_stage  = "done"
        mon.finish_time       = datetime.utcnow()
        db.session.commit()

        logger.info(
            f"✅ #{record.email_id} → {clf_result['label'].upper()} "
            f"(score={clf_result['risk_score']}) → {record.folder_status}"
        )

    except Exception as e:
        logger.error(f"Analysis failed #{record.email_id}: {e}", exc_info=True)
        try:
            mon.monitoring_status = "failed"
            mon.error_message     = str(e)[:300]
            mon.finish_time       = datetime.utcnow()
            db.session.rollback()
            db.session.add(mon)
            db.session.commit()
        except Exception:
            pass


def _html_to_text(html):
    if not html:
        return ""
    text = re.sub(r'<style[^>]*>.*?</style>', ' ', html,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<script[^>]*>.*?</script>', ' ', text,
                  flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<p[^>]*>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = text.replace('&amp;','&').replace('&lt;','<') \
               .replace('&gt;','>').replace('&nbsp;',' ')
    return re.sub(r'\s+', ' ', text).strip()


def _fast_link_check(html, plain, is_trusted=False):
    """Link check — skips trusted domains."""
    SUSPICIOUS_TLDS = {
        "xyz","tk","ml","ga","cf","gq","top","click",
        "loan","work","pw","cc","online","site","space",
    }
    BRAND_NAMES = [
        "paypal","amazon","apple","microsoft","google","facebook",
        "netflix","chase","ebay","linkedin","twitter","instagram",
    ]

    links = []
    if html:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "lxml")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith(("http://", "https://")):
                    links.append((a.get_text(strip=True) or href, href))
        except Exception:
            pass

    for url in re.findall(r'https?://[^\s<>"\']+', plain or ""):
        if not any(url == h for _, h in links):
            links.append((url, url))

    import tldextract
    results = []
    for anchor, href in links[:20]:
        try:
            parsed = re.search(r'https?://([^/\s]+)', href)
            domain = parsed.group(1).lower().lstrip("www.") if parsed else ""

            # ── Skip trusted link domains ────────────────────────────────────
            is_trusted_link = any(
                domain == td or domain.endswith("." + td)
                for td in TRUSTED_LINK_DOMAINS
            )
            if is_trusted_link or is_trusted:
                continue

            tld = tldextract.extract(href).suffix.lower()
            suspicious_tld = tld in SUSPICIOUS_TLDS
            anchor_dom = re.search(r'([\w-]+\.[a-z]{2,})', anchor.lower())
            mismatch   = bool(
                anchor_dom and anchor_dom.group(1).lstrip("www.") != domain
            )
            denumbered = domain.replace("0","o").replace("1","l") \
                               .replace("3","e").replace("4","a")
            homoglyph  = any(b in denumbered and b not in domain
                             for b in BRAND_NAMES)
            reputation = "suspicious" if (homoglyph or suspicious_tld) else "unknown"
            risk = min(100.0,
                (35 if mismatch else 0) +
                (40 if homoglyph else 0) +
                (20 if suspicious_tld else 0)
            )
            results.append({
                "anchor_text":     anchor[:500],
                "href_url":        href[:1000],
                "final_url":       href[:1000],
                "mismatch_flag":   mismatch,
                "reputation":      reputation,
                "homoglyph_flag":  homoglyph,
                "suspicious_tld":  suspicious_tld,
                "link_risk_score": risk,
            })
        except Exception:
            continue
    return results


def _fast_header_check(raw_headers, sender_email):
    """Fast header analysis — no DNS."""
    BRANDS = [
        "paypal","amazon","apple","microsoft","google","facebook",
        "netflix","chase","ebay","linkedin","irs","hmrc",
    ]
    headers = {}
    try:
        msg = email_lib.message_from_string(raw_headers)
        for k in msg.keys():
            headers[k.lower()] = str(msg[k])
    except Exception:
        pass

    spf_raw = (headers.get("received-spf", "") +
               headers.get("authentication-results", "")).lower()
    if "spf=pass"     in spf_raw: spf = "pass"
    elif "softfail"   in spf_raw: spf = "softfail"
    elif "fail"       in spf_raw: spf = "fail"
    else:                          spf = "none"

    dkim_sig   = headers.get("dkim-signature", "")
    dkim_valid = bool(dkim_sig and "v=1" in dkim_sig)

    auth  = headers.get("authentication-results", "").lower()
    dmarc = ("pass" if "dmarc=pass" in auth
             else ("quarantine" if "dmarc=fail" in auth else "none"))

    from_header   = headers.get("from", "")
    sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
    dm = re.match(r'^"?([^<"]+)"?\s*<', from_header)
    spoofing = bool(
        dm and any(
            b in dm.group(1).lower() and b not in sender_domain
            for b in BRANDS
        )
    )
    reply_to  = headers.get("reply-to", "")
    reply_dom = (reply_to.split("@")[-1].lower().strip(">")
                 if "@" in reply_to else "")
    reply_mis = bool(reply_dom and sender_domain and reply_dom != sender_domain)

    score = (
        (20 if spf in ("fail", "softfail", "none") else 0) +
        (20 if not dkim_valid else 0) +
        (35 if spoofing else 0) +
        (15 if reply_mis else 0)
    )

    return {
        "spf_result":        spf,
        "dkim_valid":        dkim_valid,
        "dmarc_policy":      dmarc,
        "spoofing_flag":     spoofing,
        "reply_to_mismatch": reply_mis,
        "routing_anomaly":   False,
        "sender_domain":     sender_domain,
        "display_name":      dm.group(1).strip()[:255] if dm else "",
        "header_risk_score": min(100.0, float(score)),
    }


# ── MIME Helpers ──────────────────────────────────────────────────────────────
def _decode_val(value):
    parts = decode_header(value or "")
    return " ".join(
        p.decode(e or "utf-8", errors="replace")
        if isinstance(p, bytes) else str(p)
        for p, e in parts
    )


def _extract_body(msg):
    body_plain = body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode(
                part.get_content_charset() or "utf-8", errors="replace"
            )
            if ct == "text/plain" and not body_plain:
                body_plain = text
            elif ct == "text/html" and not body_html:
                body_html = text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_plain = payload.decode(
                msg.get_content_charset() or "utf-8", errors="replace"
            )
    return body_plain, body_html


def _has_attachments(msg):
    return any(
        "attachment" in str(p.get("Content-Disposition", ""))
        for p in msg.walk()
    )
