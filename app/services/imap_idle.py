"""
IMAP IDLE Service — Real-Time Email Detection
Gmail ले नयाँ email आउनासाथ PhishGuard लाई notify गर्छ।
Gmail जस्तै instant detection!
"""
import imaplib
import threading
import time
import logging
import socket

logger = logging.getLogger(__name__)


def start_imap_idle(app):
    """
    Background thread मा IMAP IDLE start गर्छ।
    नयाँ email आउनासाथ automatically fetch र analyse गर्छ।
    """
    thread = threading.Thread(
        target = _idle_loop,
        args   = (app,),
        daemon = True,
        name   = "imap-idle-thread"
    )
    thread.start()
    logger.info("IMAP IDLE thread started — waiting for emails...")


def _idle_loop(app):
    """
    मुख्य IDLE loop — सधैं चलिरहन्छ।
    Connection टुटियो भने automatically reconnect गर्छ।
    """
    RECONNECT_WAIT = 10  # seconds बाद retry

    while True:
        try:
            logger.info("Connecting to Gmail IMAP...")
            _run_idle_session(app)
        except Exception as e:
            logger.error(f"IMAP IDLE error: {e}")
            logger.info(f"Reconnecting in {RECONNECT_WAIT} seconds...")
            time.sleep(RECONNECT_WAIT)


def _run_idle_session(app):
    """
    एउटा IMAP IDLE session चलाउँछ।
    नयाँ email आयो भने तुरुन्त process गर्छ।
    """
    cfg      = app.config
    host     = cfg.get("IMAP_HOST", "imap.gmail.com")
    port     = cfg.get("IMAP_PORT", 993)
    email    = cfg.get("IMAP_EMAIL", "")
    password = cfg.get("IMAP_PASSWORD", "")

    # Gmail मा connect गर्नुस्
    mail = imaplib.IMAP4_SSL(host, port)
    mail.login(email, password)
    mail.select("INBOX")
    logger.info(f"IMAP IDLE connected: {email}")

    # पहिले existing unprocessed emails check गर्नुस्
    _fetch_new_emails(app, mail)

    # IDLE loop — Gmail ले notify नगरुन्जेल wait गर्छ
    IDLE_TIMEOUT = 29 * 60  # 29 minutes (Gmail IDLE timeout भन्दा कम)

    while True:
        # IDLE mode start
        logger.info("Waiting for new emails (IMAP IDLE)...")
        mail.send(b"IDLE_TAG IDLE\r\n")

        # Gmail को response को लागि wait गर्नुस्
        mail.socket().settimeout(IDLE_TIMEOUT)

        try:
            response = _wait_for_exists(mail)
            if response:
                # नयाँ email आयो!
                logger.info("New email detected! Processing...")
                # IDLE बाट बाहिर निस्कनुस्
                mail.send(b"DONE\r\n")
                time.sleep(1)  # Server को लागि थोरै wait
                # Email fetch र process गर्नुस्
                _fetch_new_emails(app, mail)
            else:
                # Timeout — reconnect गर्नुस्
                mail.send(b"DONE\r\n")
                logger.info("IDLE timeout — reconnecting...")
                break

        except socket.timeout:
            # Normal timeout — फेरि IDLE गर्नुस्
            mail.send(b"DONE\r\n")
            logger.info("IDLE refresh — still connected.")
            continue

        except Exception as e:
            mail.send(b"DONE\r\n")
            raise e

    mail.logout()


def _wait_for_exists(mail):
    """
    Gmail बाट * EXISTS notification आउन कुर्छ।
    यो आयो भने नयाँ email आएको हो।
    """
    try:
        while True:
            line = mail.readline()
            if not line:
                return False
            decoded = line.decode("utf-8", errors="ignore").strip()
            logger.debug(f"IDLE response: {decoded}")
            # नयाँ email को signal
            if "EXISTS" in decoded or "RECENT" in decoded:
                return True
            # Connection closed
            if "BYE" in decoded:
                return False
    except socket.timeout:
        return None
    except Exception:
        return False


def _fetch_new_emails(app, mail):
    """
    नयाँ (unprocessed) emails fetch गरेर analysis pipeline चलाउँछ।
    """
    try:
        with app.app_context():
            from app import db
            from app.models.email_model import Email
            from app.services.email_ingestion import (
                _parse_and_store, _run_analysis_pipeline
            )

            # सबै emails हेर्छ — Message-ID ले duplicate skip गर्छ
            _, data = mail.search(None, "ALL")
            uid_list = data[0].split()

            if not uid_list:
                logger.info("No emails found.")
                return

            new_count = 0
            for uid in uid_list:
                try:
                    # PEEK — Gmail मा read mark हुँदैन
                    _, msg_data = mail.fetch(uid, "(BODY.PEEK[])")

                    if not msg_data or not msg_data[0]:
                        continue

                    raw_bytes = msg_data[0][1]
                    if not raw_bytes:
                        continue

                    import email as email_lib
                    msg = email_lib.message_from_bytes(raw_bytes)

                    imap_email = app.config.get("IMAP_EMAIL", "")
                    email_record = _parse_and_store(msg, imap_email, db)

                    if email_record:
                        new_count += 1
                        _run_analysis_pipeline(
                            email_record, db, app.config
                        )

                except Exception as e:
                    logger.error(f"Error processing UID {uid}: {e}")
                    db.session.rollback()

            if new_count > 0:
                logger.info(f"Processed {new_count} new email(s)!")
            else:
                logger.info("No new emails to process.")

    except Exception as e:
        logger.error(f"Fetch error: {e}")
