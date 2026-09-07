"""
Email Ingestion Service
Connects to IMAP, fetches unseen emails, parses MIME,
runs the full analysis pipeline, and stores results.
"""
import imaplib
import email as email_lib
import logging
from datetime import datetime
from email.header import decode_header
from typing import Optional

from flask import current_app

logger = logging.getLogger(__name__)


def fetch_and_process_emails(app):
    """
    Scheduled job: connect to IMAP, fetch new emails, run analysis pipeline.
    Runs within the given Flask app context.
    Checks BOTH the one shared/admin inbox (from .env, if configured) AND
    every individual user's own connected Gmail account (via their own
    App Password) — so each user's real inbox is analysed separately.
    Uses PEEK so emails stay unread in Gmail — visible in both Gmail and PhishGuard.
    """
    with app.app_context():
        from app import db
        from app.models.email_model import Email, EmailMonitoring
        from app.models.quarantine import SystemConfig
        from app.models.user import User

        cfg       = current_app.config
        total_new = 0

        # 1) The one shared/admin inbox configured in .env (kept for
        #    backward compatibility with existing setup/data).
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
            logger.warning("Shared IMAP_EMAIL not configured — skipping shared inbox.")

        # 2) Every user who has connected their own Gmail account.
        users_with_gmail = User.query.filter(
            User.gmail_email.isnot(None),
            User.gmail_app_password.isnot(None),
        ).all()

        for user in users_with_gmail:
            total_new += _fetch_mailbox(
                cfg.get("IMAP_HOST", "imap.gmail.com"), cfg.get("IMAP_PORT", 993),
                user.gmail_email, user.gmail_app_password,
                db, cfg, owner_user_id=user.user_id, label=user.gmail_email,
            )

        logger.info(f"Processed {total_new} new emails across all accounts.")


def _fetch_mailbox(imap_host, imap_port, imap_email, imap_pw, db, cfg, owner_user_id, label):
    """Connect to ONE mailbox (the shared inbox, or a specific user's own) and ingest new mail."""
    new_count = 0
    try:
        mail = imaplib.IMAP4_SSL(imap_host, imap_port)
        mail.login(imap_email, imap_pw)

        # Poll both INBOX and Gmail's own Spam folder. Gmail's built-in
        # spam filter can intercept phishing-style emails before they
        # ever reach INBOX — but PhishGuard is meant to make its own
        # determination on every email, not rely on Gmail's filter to
        # decide what it even gets to see.
        for folder in ["INBOX", '"[Gmail]/Spam"']:
            try:
                status, _ = mail.select(folder)
                if status != "OK":
                    logger.warning(f"[{label}] Could not select folder {folder} — skipping.")
                    continue
            except Exception as e:
                logger.warning(f"[{label}] Could not select folder {folder}: {e}")
                continue

            # Fetch ALL emails — deduplication by Message-ID handles repeats
            # This ensures emails visible in Gmail AND PhishGuard at the same time
            _, data = mail.search(None, "ALL")
            uid_list = data[0].split()
            logger.info(f"[{label}] Found {len(uid_list)} total emails in {folder} — checking for new ones.")

            for uid in uid_list:
                try:
                    # Use BODY.PEEK[] instead of RFC822
                    # PEEK = fetch email WITHOUT marking as read in Gmail
                    # This means email stays visible in Gmail inbox too
                    _, msg_data = mail.fetch(uid, "(BODY.PEEK[])")

                    if not msg_data or not msg_data[0]:
                        continue

                    raw_bytes = msg_data[0][1]
                    if not raw_bytes:
                        continue

                    msg          = email_lib.message_from_bytes(raw_bytes)
                    actual_to    = _decode_header_value(msg.get("To", imap_email))
                    email_record = _parse_and_store(msg, actual_to, db, owner_user_id=owner_user_id)

                    if email_record:
                        new_count += 1
                        _run_analysis_pipeline(email_record, db, cfg)

                except Exception as e:
                    logger.error(f"[{label}] Error processing email UID {uid} in {folder}: {e}")
                    db.session.rollback()

        mail.logout()

    except Exception as e:
        logger.error(f"[{label}] IMAP connection error: {e}")

    return new_count


def _parse_and_store(msg, receiver_email: str, db, owner_user_id=None) -> Optional[object]:
    """Parse a raw email message and save to the emails table."""
    from app.models.email_model import Email

    message_id = msg.get("Message-ID", "")

    # Deduplication check — skip if already in database
    if message_id and Email.query.filter_by(message_id=message_id).first():
        logger.debug(f"Duplicate email skipped: {message_id}")
        return None

    sender     = _decode_header_value(msg.get("From", ""))
    subject    = _decode_header_value(msg.get("Subject", "(No Subject)"))
    raw_hdrs   = str(msg)[:10000]

    body_plain, body_html = _extract_body(msg)

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
        received_time   = datetime.utcnow(),
        has_attachments = _has_attachments(msg),
    )
    db.session.add(email_record)
    db.session.commit()
    logger.info(f"Stored new email #{email_record.email_id}: {subject[:50]}")
    return email_record


def _run_analysis_pipeline(email_record, db, cfg):
    """Run NLP → Link → Header → ML → Quarantine for a stored email."""
    from app.models.email_model import EmailMonitoring
    from app.models.analysis import (
        NLPAnalysis, LinkAnalysis, HeaderAnalysis,
        SenderReputation, Classification
    )
    from app.models.quarantine import QuarantineItem, SystemConfig
    from app.services import nlp_analyzer, link_analyzer, header_analyzer, ml_classifier
    import secrets

    mon = EmailMonitoring(
        email_id         = email_record.email_id,
        monitoring_status= "analysing",
        processing_stage = "nlp_analysis"
    )
    db.session.add(mon)
    db.session.commit()

    try:
        # 1. NLP Analysis
        mon.processing_stage = "nlp_analysis"
        db.session.commit()
        nlp_result = nlp_analyzer.analyze_text(
            email_record.email_body or "", email_record.sender_email
        )
        nlp = NLPAnalysis(email_id=email_record.email_id, **nlp_result)
        db.session.add(nlp)

        # 2. Link Analysis
        mon.processing_stage = "link_analysis"
        db.session.commit()
        link_results = link_analyzer.analyze_links(
            email_record.email_html or "",
            email_record.email_body or "",
            safe_browsing_key=cfg.get("SAFE_BROWSING_API_KEY", ""),
        )
        for lr in link_results:
            db.session.add(LinkAnalysis(email_id=email_record.email_id, **lr))

        # 3. Header Analysis
        mon.processing_stage = "header_analysis"
        db.session.commit()
        hdr_result = header_analyzer.analyze_headers(
            email_record.raw_headers or "", email_record.sender_email
        )
        hdr = HeaderAnalysis(email_id=email_record.email_id, **hdr_result)
        db.session.add(hdr)
        db.session.commit()

        # 4. Sender Reputation
        sender_rep = SenderReputation.query.filter_by(
            sender_email=email_record.sender_email
        ).first()
        rep_rate = sender_rep.phishing_rate if sender_rep else 0.0

        # 5. ML Classification
        mon.processing_stage = "ml_classification"
        db.session.commit()
        threshold  = int(SystemConfig.get("quarantine_threshold", "65"))
        clf_result = ml_classifier.classify_email(
            nlp            = nlp_result,
            links          = link_results,
            header         = hdr_result,
            sender_rep_rate= rep_rate,
            model_path     = cfg.get("MODEL_PATH"),
            threshold      = threshold,
        )

        classification = Classification(email_id=email_record.email_id, **clf_result)
        db.session.add(classification)

        # 6. Route email to correct folder
        if clf_result["label"] == "phishing":
            email_record.folder_status = "quarantine"
            qi = QuarantineItem(
                email_id    = email_record.email_id,
                user_id     = email_record.user_id or 1,
                status      = "held",
                action_token= secrets.token_urlsafe(32),
            )
            db.session.add(qi)
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
                sender_email  = email_record.sender_email,
                sender_domain = sender_domain,
                total_emails  = 0,
                phishing_count= 0,
            )
            db.session.add(sender_rep)
        sender_rep.update_reputation(is_phishing)

        mon.monitoring_status = "completed"
        mon.processing_stage  = "done"
        mon.finish_time       = datetime.utcnow()
        db.session.commit()

        logger.info(
            f"Email #{email_record.email_id} → {clf_result['label'].upper()} "
            f"(score={clf_result['risk_score']}) → folder: {email_record.folder_status}"
        )

    except Exception as e:
        mon.monitoring_status = "failed"
        mon.error_message     = str(e)[:500]
        mon.finish_time       = datetime.utcnow()
        db.session.commit()
        logger.error(f"Pipeline failed for email #{email_record.email_id}: {e}")


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
        disp = str(part.get("Content-Disposition", ""))
        if "attachment" in disp:
            return True
    return False