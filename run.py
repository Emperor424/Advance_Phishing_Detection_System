"""
PhishGuard — Flask Entry Point
"""
import os
import logging
from app import create_app

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

app = create_app(os.environ.get("FLASK_ENV", "development"))


# ── Re-analyse emails with wrong/missing classification ───────────────────────
def _analyse_pending_emails(app):
    with app.app_context():
        try:
            from app import db
            from app.models.email_model import Email
            from app.models.analysis import (
                Classification, NLPAnalysis, LinkAnalysis, HeaderAnalysis
            )
            from app.services.gmail_sync import _fast_analyse
            from sqlalchemy import or_

            emails_to_fix = (
                db.session.query(Email)
                .outerjoin(
                    Classification,
                    Email.email_id == Classification.email_id
                )
                .filter(
                    Email.email_direction == "received",
                    Email.folder_status   != "trash",
                    or_(
                        Classification.email_id   == None,
                        Classification.risk_score  < 10,
                    )
                )
                .all()
            )

            if emails_to_fix:
                app.logger.info(
                    f"Found {len(emails_to_fix)} email(s) to analyse..."
                )
                for em in emails_to_fix:
                    try:
                        # Delete old wrong records
                        Classification.query.filter_by(email_id=em.email_id).delete()
                        NLPAnalysis.query.filter_by(email_id=em.email_id).delete()
                        LinkAnalysis.query.filter_by(email_id=em.email_id).delete()
                        HeaderAnalysis.query.filter_by(email_id=em.email_id).delete()
                        db.session.commit()

                        # Fresh analysis
                        _fast_analyse(em, db, app.config)
                        app.logger.info(
                            f"Analysed #{em.email_id}: "
                            f"{em.subject[:50] if em.subject else 'No Subject'}"
                        )
                    except Exception as e:
                        app.logger.error(f"Failed #{em.email_id}: {e}")
                        db.session.rollback()
            else:
                app.logger.info("All emails correctly analysed ✅")

        except Exception as e:
            app.logger.error(f"Startup analysis error: {e}")


# ── Daily digest ──────────────────────────────────────────────────────────────
def _send_daily_digest(app):
    with app.app_context():
        try:
            from app.models.user import User
            from app.models.quarantine import QuarantineItem
            from app.services.email_sender import send_digest
            base_url = "http://localhost:5000"
            users    = User.query.filter_by(account_status="active").all()
            for user in users:
                if user.digest_frequency == "disabled":
                    continue
                items = QuarantineItem.query.filter_by(
                    user_id=user.user_id, status="held"
                ).all()
                if items:
                    send_digest(user, items, base_url)
                    app.logger.info(
                        f"Digest sent → {user.email} ({len(items)} items)"
                    )
        except Exception as e:
            app.logger.error(f"Digest error: {e}")


# ── Step 1: Analyse pending emails on startup ─────────────────────────────────
app.logger.info("Checking for unanalyzed/wrong emails...")
_analyse_pending_emails(app)


# ── Step 2: Gmail Real-Time Sync ──────────────────────────────────────────────
try:
    from app.services.gmail_sync import start_gmail_sync
    if app.config.get("IMAP_EMAIL"):
        start_gmail_sync(app)
        app.logger.info(
            f"Gmail IMAP IDLE started → {app.config.get('IMAP_EMAIL')}"
        )
    else:
        app.logger.warning("IMAP_EMAIL not set in .env")
except Exception as e:
    app.logger.error(f"Gmail sync error: {e}")


# ── Step 3: Scheduler ─────────────────────────────────────────────────────────
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from app.services.email_ingestion import fetch_and_process_emails

    scheduler = BackgroundScheduler()

    # Fallback email poll every 5 minutes
    # IMAP IDLE handles real-time — this is just a safety net
    scheduler.add_job(
        func             = fetch_and_process_emails,
        args             = [app],
        trigger          = "interval",
        minutes          = 5,
        id               = "email_poll",
        max_instances    = 1,
        replace_existing = True,
    )

    # Re-analyse wrong emails every 30 minutes (not 2 min — causes slowdowns)
    scheduler.add_job(
        func             = _analyse_pending_emails,
        args             = [app],
        trigger          = "interval",
        minutes          = 30,
        id               = "analyse_pending",
        max_instances    = 1,
        replace_existing = True,
    )

    # Daily digest at 08:00
    scheduler.add_job(
        func             = _send_daily_digest,
        args             = [app],
        trigger          = CronTrigger(hour=8, minute=0),
        id               = "daily_digest",
        max_instances    = 1,
        replace_existing = True,
    )

    scheduler.start()
    app.logger.info(
        "Scheduler started: 30s poll + 2min re-analyse + 08:00 digest"
    )

except Exception as e:
    app.logger.warning(f"Scheduler not started: {e}")


# ── Step 4: Run Flask ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(
        host        = "0.0.0.0",
        port        = 5000,
        debug       = False,
        use_reloader= False,
    )