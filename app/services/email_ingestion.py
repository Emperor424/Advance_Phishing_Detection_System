import imaplib
import email as email_lib
import logging
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import parsedate_to_datetime
from typing import Optional
 
from flask import current_app
 
logger = logging.getLogger(__name__)
 
 
def _now():
    """Current UTC time — compatible with database."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
 
 
def _parse_email_date(msg) -> datetime:
    """
    Extract actual email send time from Date header.
    This matches the time Gmail shows — NOT the fetch time.
    Falls back to current time if header is missing/invalid.
    """
    date_str = msg.get("Date", "")
    if not date_str:
        return _now()
    try:
        # parsedate_to_datetime handles all timezone formats
        dt = parsedate_to_datetime(date_str)
        # Convert to UTC then strip timezone info for DB
        dt_utc = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt_utc
    except Exception:
        return _now()
 
 
def fetch_and_process_emails(app):
    """
    Scheduled job: connect to IMAP, fetch new emails, run analysis.
    Checks shared/admin inbox AND every user's own connected Gmail.
    Uses PEEK so emails stay unread in Gmail.
    """
    with app.app_context():
        from app import db
        from app.models.email_model import Email, EmailMonitoring
        from app.models.quarantine import SystemConfig
        from app.models.user import User
 
        cfg       = current_app.config
        total_new = 0
 
        # 1) Shared/admin inbox from .env
        imap_host  = cfg.get("IMAP_HOST")
        imap_port  = cfg.get("IMAP_PORT", 993)
        imap_email = cfg.get("IMAP_EMAIL")
        imap_pw    = cfg.get("IMAP_PASSWORD")
 
        if all([imap_host, imap_email, imap_pw]):
            total_new += _fetch_mailbox(
                imap_host, imap_port, imap_email, imap_pw,
                db, cfg, owner_user_id=None, label=imap_email,
            )
        else:
            logger.warning("Shared IMAP_EMAIL not configured — skipping.")
 
        # 2) Each user's own connected Gmail
        try:
            users_with_gmail = User.query.filter(
                User.gmail_email.isnot(None),
                User.gmail_app_password.isnot(None),
            ).all()
 
            for user in users_with_gmail:
                total_new += _fetch_mailbox(
                    cfg.get("IMAP_HOST", "imap.gmail.com"),
                    cfg.get("IMAP_PORT", 993),
                    user.gmail_email,
                    user.gmail_app_password,
                    db, cfg,
                    owner_user_id=user.user_id,
                    label=user.gmail_email,
                )
        except Exception as e:
            logger.error(f"User Gmail fetch error: {e}")
 
        logger.info(f"Processed {total_new} new emails across all accounts.")
 
 
def _fetch_mailbox(imap_host, imap_port, imap_email, imap_pw,
                   db, cfg, owner_user_id, label):
    """Connect to ONE mailbox and ingest new emails."""
    new_count = 0
    try:
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
        mail.login(imap_email, imap_pw)
 
        # Only INBOX — PhishGuard makes its own spam/phishing determination
        for folder in ["INBOX"]:
            try:
                status, _ = mail.select(folder)
                if status != "OK":
                    logger.warning(f"[{label}] Cannot select {folder} — skipping.")
                    continue
            except Exception as e:
                logger.warning(f"[{label}] Folder select error {folder}: {e}")
                continue
 
            _, data = mail.search(None, "ALL")
            uid_list = data[0].split()
            logger.info(f"[{label}] {len(uid_list)} emails in {folder}.")
 
            for uid in uid_list:
                try:
                    # PEEK = don't mark as read in Gmail
                    _, msg_data = mail.fetch(uid, "(BODY.PEEK[])")
                    if not msg_data or not msg_data[0]:
                        continue
                    raw_bytes = msg_data[0][1]
                    if not raw_bytes:
                        continue
 
                    msg       = email_lib.message_from_bytes(raw_bytes)
                    actual_to = _decode_header_value(msg.get("To", imap_email))
                    email_record = _parse_and_store(
                        msg, actual_to, db, owner_user_id=owner_user_id
                    )
                    if email_record:
                        new_count += 1
                        _run_analysis_pipeline(email_record, db, cfg)
 
                except Exception as e:
                    logger.error(f"[{label}] Error on UID {uid}: {e}")
                    db.session.rollback()
 
        mail.logout()
 
    except Exception as e:
        logger.error(f"[{label}] IMAP connection error: {e}")
 
    return new_count
 
 
def _parse_and_store(msg, receiver_email: str, db,
                     owner_user_id=None) -> Optional[object]:
    """Parse raw email and save to database with correct time."""
    from app.models.email_model import Email
 
    message_id = msg.get("Message-ID", "")
 
    # Skip duplicates
    if message_id and Email.query.filter_by(message_id=message_id).first():
        logger.debug(f"Duplicate skipped: {message_id}")
        return None
 
    sender   = _decode_header_value(msg.get("From", ""))
    subject  = _decode_header_value(msg.get("Subject", "(No Subject)"))
    raw_hdrs = str(msg)[:10000]
 
    body_plain, body_html = _extract_body(msg)
 
    # KEY FIX: Use email's own Date header — matches Gmail time exactly!
    email_date = _parse_email_date(msg)
 
    email_record = Email(
        user_id         = owner_user_id,
        sender_email    = sender[:255],
        receiver_email  = receiver_email[:255],
        subject         = subject[:500],
        email_body      = body_plain,
        email_html      = body_html,
        raw_headers     = raw_hdrs,
        folder_status   = "inbox",
        email_direction = "received",
        message_id      = message_id[:500] if message_id else None,
        sent_time       = email_date,   # ← actual send time (matches Gmail)
        received_time   = email_date,   # ← same so display is consistent
        has_attachments = _has_attachments(msg),
    )
    db.session.add(email_record)
    db.session.commit()
    logger.info(f"Stored #{email_record.email_id}: {subject[:50]} @ {email_date}")
    return email_record
 
 
def _run_analysis_pipeline(email_record, db, cfg):
    """Run NLP → Link → Header → ML → route to correct folder."""
    from app.models.email_model import EmailMonitoring
    from app.models.analysis import (
        NLPAnalysis, LinkAnalysis, HeaderAnalysis,
        SenderReputation, Classification
    )
    from app.models.quarantine import QuarantineItem, SystemConfig
    from app.services import nlp_analyzer, link_analyzer, header_analyzer, ml_classifier
    import secrets
 
    mon = EmailMonitoring(
        email_id          = email_record.email_id,
        monitoring_status = "analysing",
        processing_stage  = "nlp_analysis"
    )
    db.session.add(mon)
    db.session.commit()
 
    try:
        # 1. NLP
        mon.processing_stage = "nlp_analysis"
        db.session.commit()
        nlp_result = nlp_analyzer.analyze_text(
            email_record.email_body or "", email_record.sender_email
        )
        db.session.add(NLPAnalysis(email_id=email_record.email_id, **nlp_result))
 
        # 2. Links
        mon.processing_stage = "link_analysis"
        db.session.commit()
        link_results = link_analyzer.analyze_links(
            email_record.email_html or "",
            email_record.email_body or "",
            safe_browsing_key=cfg.get("SAFE_BROWSING_API_KEY", ""),
        )
        for lr in link_results:
            db.session.add(LinkAnalysis(email_id=email_record.email_id, **lr))
 
        # 3. Headers
        mon.processing_stage = "header_analysis"
        db.session.commit()
        hdr_result = header_analyzer.analyze_headers(
            email_record.raw_headers or "", email_record.sender_email
        )
        db.session.add(HeaderAnalysis(email_id=email_record.email_id, **hdr_result))
        db.session.commit()
 
        # 4. Sender reputation
        sender_rep = SenderReputation.query.filter_by(
            sender_email=email_record.sender_email
        ).first()
        rep_rate = sender_rep.phishing_rate if sender_rep else 0.0
 
        # 5. ML Classification
        mon.processing_stage = "ml_classification"
        db.session.commit()
        threshold  = int(SystemConfig.get("quarantine_threshold", "65"))
        clf_result = ml_classifier.classify_email(
            nlp             = nlp_result,
            links           = link_results,
            header          = hdr_result,
            sender_rep_rate = rep_rate,
            model_path      = cfg.get("MODEL_PATH"),
            threshold       = threshold,
        )
        db.session.add(Classification(email_id=email_record.email_id, **clf_result))
 
        # 6. Route to folder
        if clf_result["label"] == "phishing":
            email_record.folder_status = "quarantine"
            db.session.add(QuarantineItem(
                email_id     = email_record.email_id,
                user_id      = email_record.user_id or 1,
                status       = "held",
                action_token = secrets.token_urlsafe(32),
            ))
            is_phishing = True
        elif clf_result["label"] == "suspicious":
            email_record.folder_status = "spam"
            is_phishing = True
        else:
            email_record.folder_status = "inbox"
            is_phishing = False
 
        # 7. Update sender reputation
        if not sender_rep:
            sender_domain = (
                email_record.sender_email.split("@")[-1]
                if "@" in email_record.sender_email else ""
            )
            sender_rep = SenderReputation(
                sender_email   = email_record.sender_email,
                sender_domain  = sender_domain,
                total_emails   = 0,
                phishing_count = 0,
            )
            db.session.add(sender_rep)
        sender_rep.update_reputation(is_phishing)
 
        mon.monitoring_status = "completed"
        mon.processing_stage  = "done"
        mon.finish_time       = _now()
        db.session.commit()
 
        logger.info(
            f"#{email_record.email_id} → {clf_result['label'].upper()} "
            f"(score={clf_result['risk_score']}) → {email_record.folder_status}"
        )
 
    except Exception as e:
        mon.monitoring_status = "failed"
        mon.error_message     = str(e)[:500]
        mon.finish_time       = _now()
        db.session.commit()
        logger.error(f"Pipeline failed #{email_record.email_id}: {e}")
 
 
# ── MIME helpers ──────────────────────────────────────────────────────────────
 
def _decode_header_value(value: str) -> str:
    parts = decode_header(value or "")
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded)
 
 
def _extract_body(msg) -> tuple:
    body_plain = ""
    body_html  = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct   = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                continue
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            charset = part.get_content_charset() or "utf-8"
            text    = payload.decode(charset, errors="replace")
            if ct == "text/plain" and not body_plain:
                body_plain = text
            elif ct == "text/html" and not body_html:
                body_html = text
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset    = msg.get_content_charset() or "utf-8"
            body_plain = payload.decode(charset, errors="replace")
    return body_plain, body_html
 
 
def _has_attachments(msg) -> bool:
    for part in msg.walk():
        if "attachment" in str(part.get("Content-Disposition", "")):
            return True
    return False