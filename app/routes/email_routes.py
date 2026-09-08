import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, current_app, jsonify)
from flask_login import login_required, current_user
from app import db
from app.models.email_model import Email, SearchHistory
from app.models.analysis import Classification
from app.models.quarantine import FeedbackLabel

email_bp = Blueprint("email", __name__)
logger   = logging.getLogger(__name__)


def _email_matches(column, email):
    """
    Exact email address match (case insensitive).
    Handles formats: "user@example.com" and "Name <user@example.com>"
    Avoids partial matches like "phish" matching "phishguard604@gmail.com"
    """
    return db.or_(
        db.func.lower(column) == email,                    # exact match
        column.ilike(f"{email},%"),                        # first in list
        column.ilike(f"%, {email}"),                       # last in list
        column.ilike(f"%, {email},%"),                     # middle of list
        column.ilike(f"%<{email}>%"),                      # inside < >
        column.ilike(f"% {email} %"),                      # surrounded by spaces
    )


def _base_query():
    """All emails visible to current user — matched by their own registered email address."""
    if current_user.is_admin:
        return Email.query
    uid   = current_user.user_id
    email = current_user.email.lower().strip()
    return Email.query.filter(
        db.or_(
            Email.user_id == uid,
            _email_matches(Email.sender_email,   email),
            _email_matches(Email.receiver_email, email),
        )
    )


def _sent_query():
    """Only emails THIS user sent."""
    if current_user.is_admin:
        return Email.query.filter_by(folder_status="sent")
    return Email.query.filter_by(
        user_id       = current_user.user_id,
        folder_status = "sent",
    )


def _inbox_query():
    """Inbox: exact email match to avoid false positives."""
    if current_user.is_admin:
        return Email.query.filter_by(folder_status="inbox")

    uid   = current_user.user_id
    email = current_user.email.lower().strip()
    return Email.query.filter(
        Email.folder_status == "inbox",
        db.or_(
            Email.user_id == uid,
            _email_matches(Email.receiver_email, email),
        )
    )


# ── Inbox ─────────────────────────────────────────────────────────────────────
@email_bp.route("/inbox")
@login_required
def inbox():
    folder = request.args.get("folder", "inbox")
    page   = request.args.get("page", 1, type=int)
    search = request.args.get("q", "").strip()

    if folder == "sent":
        query = _sent_query()
    elif folder == "inbox":
        query = _inbox_query()
    elif folder == "starred":
        query = _base_query().filter_by(is_starred=True)
    elif folder == "trash":
        query = _base_query().filter_by(folder_status="trash")
    elif folder == "archive":
        query = _base_query().filter_by(folder_status="archive")
    elif folder == "draft":
        query = (Email.query.filter_by(user_id=current_user.user_id, folder_status="draft")
                 if not current_user.is_admin
                 else Email.query.filter_by(folder_status="draft"))
    elif folder == "spam":
        query = _base_query().filter_by(folder_status="spam")
    elif folder == "quarantine":
        query = _base_query().filter_by(folder_status="quarantine")
    else:
        query = _inbox_query()

    if search:
        like = f"%{search}%"
        query = query.filter(
            db.or_(
                Email.subject.ilike(like),
                Email.sender_email.ilike(like),
                Email.email_body.ilike(like),
            )
        )
        db.session.add(SearchHistory(
            user_id=current_user.user_id,
            search_keyword=search[:255],
            searched_folder=folder,
        ))
        db.session.commit()

    emails_page = query.order_by(
        Email.received_time.desc()
    ).paginate(page=page, per_page=20, error_out=False)

    counts = {
        "inbox":      _inbox_query().count(),
        "starred":    _base_query().filter_by(is_starred=True).count(),
        "spam":       _base_query().filter_by(folder_status="spam").count(),
        "quarantine": _base_query().filter_by(folder_status="quarantine").count(),
        "sent":       _sent_query().count(),
        "trash":      _base_query().filter_by(folder_status="trash").count(),
        "archive":    _base_query().filter_by(folder_status="archive").count(),
        "draft":      (Email.query.filter_by(user_id=current_user.user_id, folder_status="draft").count()
                       if not current_user.is_admin
                       else Email.query.filter_by(folder_status="draft").count()),
        "unread":     _inbox_query().filter_by(is_read=False).count(),
    }

    return render_template(
        "email/inbox.html",
        emails=emails_page, folder=folder,
        search=search, counts=counts,
    )


# ── View ──────────────────────────────────────────────────────────────────────
@email_bp.route("/view/<int:email_id>")
@login_required
def view(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Email not found or access denied.", "danger")
        return redirect(url_for("email.inbox"))

    if not em.is_read and em.folder_status != "draft":
        em.is_read = True
        db.session.commit()

    feedback = FeedbackLabel.query.filter_by(
        email_id=email_id, user_id=current_user.user_id
    ).first()

    if em.folder_status == "sent":
        base = _sent_query()
    elif em.folder_status == "inbox":
        base = _inbox_query()
    else:
        base = _base_query().filter_by(folder_status=em.folder_status)

    ids     = [e.email_id for e in base.order_by(Email.received_time.desc()).all()]
    idx     = ids.index(email_id) if email_id in ids else -1
    prev_id = ids[idx - 1] if idx > 0 else None
    next_id = ids[idx + 1] if 0 <= idx < len(ids) - 1 else None

    return render_template(
        "email/view.html", email=em,
        feedback=feedback, prev_id=prev_id, next_id=next_id,
    )


# ── Compose ───────────────────────────────────────────────────────────────────
@email_bp.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    reply_to_id = request.args.get("reply_to",   type=int)
    forward_id  = request.args.get("forward_id", type=int)
    draft_id    = request.args.get("draft_id",   type=int)

    prefill = {}
    if reply_to_id:
        orig = Email.query.get(reply_to_id)
        if orig:
            raw  = orig.sender_email
            addr = raw.split("<")[-1].strip(">").strip() if "<" in raw else raw
            prefill["to"]      = addr
            prefill["subject"] = f"Re: {orig.subject or ''}"
            prefill["body"]    = (
                f"\n\n--- Original Message ---\n"
                f"From: {orig.sender_email}\n"
                f"Date: {orig.received_time.strftime('%b %d, %Y %H:%M UTC') if orig.received_time else ''}\n\n"
                f"{orig.email_body or ''}"
            )
    elif forward_id:
        orig = Email.query.get(forward_id)
        if orig:
            prefill["subject"] = f"Fwd: {orig.subject or ''}"
            prefill["body"]    = (
                f"\n\n--- Forwarded Message ---\n"
                f"From: {orig.sender_email}\n"
                f"Date: {orig.received_time.strftime('%b %d, %Y %H:%M UTC') if orig.received_time else ''}\n"
                f"Subject: {orig.subject or ''}\n\n"
                f"{orig.email_body or ''}"
            )
    elif draft_id:
        draft = Email.query.filter_by(
            email_id=draft_id, user_id=current_user.user_id, folder_status="draft"
        ).first()
        if draft:
            prefill["to"]       = draft.receiver_email or ""
            prefill["subject"]  = draft.subject or ""
            prefill["body"]     = draft.email_body or ""
            prefill["draft_id"] = draft_id

    if request.method == "POST":
        to_addr = request.form.get("to", "").strip()
        subject = request.form.get("subject", "").strip()
        body    = request.form.get("body", "").strip()
        action  = request.form.get("action", "send")
        d_id    = request.form.get("draft_id", type=int)

        if action == "save_draft":
            if d_id:
                draft = Email.query.filter_by(
                    email_id=d_id, user_id=current_user.user_id
                ).first()
                if draft:
                    draft.receiver_email = to_addr[:255]
                    draft.subject        = subject[:500]
                    draft.email_body     = body
                    db.session.commit()
                    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                        return jsonify({"status": "saved", "draft_id": d_id})
                    flash("Draft updated.", "info")
                    return redirect(url_for("email.inbox", folder="draft"))

            draft = Email(
                user_id=current_user.user_id, sender_email=current_user.email,
                receiver_email=to_addr[:255], subject=subject[:500],
                email_body=body, folder_status="draft",
                email_direction="sent", received_time=datetime.utcnow(),
            )
            db.session.add(draft)
            db.session.commit()
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"status": "saved", "draft_id": draft.email_id})
            flash("Draft saved.", "info")
            return redirect(url_for("email.inbox", folder="draft"))

        # ── SEND ─────────────────────────────────────────────────────────────
        errors = []
        if not to_addr or "@" not in to_addr:
            errors.append("Valid recipient email required.")
        if not body:
            errors.append("Body cannot be empty.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("email/compose.html", prefill=prefill)

        success = _smtp_send(current_user.email, to_addr, subject, body)
        if success:
            # Delete draft if existed
            if d_id:
                draft = Email.query.filter_by(
                    email_id=d_id, user_id=current_user.user_id
                ).first()
                if draft:
                    db.session.delete(draft)

            # Save to sender's Sent folder
            db.session.add(Email(
                user_id=current_user.user_id,
                sender_email=current_user.email,
                receiver_email=to_addr[:255],
                subject=subject[:500], email_body=body,
                folder_status="sent", email_direction="sent",
                sent_time=datetime.utcnow(), received_time=datetime.utcnow(),
            ))
            db.session.commit()

            # ── KEY FIX: Deliver to recipient's PhishGuard inbox ─────────────
            from app.models.user import User
            recipient_user = User.query.filter(
                User.email.ilike(to_addr.strip())
            ).first()

            if recipient_user and recipient_user.user_id != current_user.user_id:
                # Create a copy in recipient's inbox
                inbox_copy = Email(
                    user_id         = recipient_user.user_id,
                    sender_email    = current_user.email,
                    receiver_email  = to_addr[:255],
                    subject         = subject[:500],
                    email_body      = body,
                    folder_status   = "inbox",
                    email_direction = "received",
                    sent_time       = datetime.utcnow(),
                    received_time   = datetime.utcnow(),
                    is_read         = False,
                )
                db.session.add(inbox_copy)
                db.session.commit()

                # Run phishing analysis on the received copy
                try:
                    from app.services.gmail_sync import _fast_analyse
                    _fast_analyse(inbox_copy, db, current_app.config)
                except Exception as e:
                    logger.error(f"Analysis on inbox copy failed: {e}")

                logger.info(
                    f"Delivered '{subject}' to {recipient_user.email}'s inbox"
                )

            flash("Email sent!", "success")
            return redirect(url_for("email.inbox", folder="sent"))
        else:
            flash("Send failed. Check SMTP in .env", "danger")

    return render_template("email/compose.html", prefill=prefill)


# ── Shortcuts ─────────────────────────────────────────────────────────────────
@email_bp.route("/reply/<int:email_id>")
@login_required
def reply(email_id):
    return redirect(url_for("email.compose", reply_to=email_id))

@email_bp.route("/forward/<int:email_id>")
@login_required
def forward(email_id):
    return redirect(url_for("email.compose", forward_id=email_id))

@email_bp.route("/star/<int:email_id>", methods=["POST"])
@login_required
def toggle_star(email_id):
    em = _get_email(email_id)
    if not em:
        return jsonify({"error": "Not found"}), 404
    em.is_starred = not em.is_starred
    db.session.commit()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"starred": em.is_starred})
    flash("⭐ Starred!" if em.is_starred else "Unstarred.", "info")
    return redirect(request.referrer or url_for("email.inbox"))

@email_bp.route("/unread/<int:email_id>", methods=["POST"])
@login_required
def mark_unread(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    em.is_read = False
    db.session.commit()
    flash("Marked as unread.", "info")
    return redirect(url_for("email.inbox", folder=em.folder_status))

@email_bp.route("/archive/<int:email_id>", methods=["POST"])
@login_required
def archive(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    em.folder_status = "archive"
    db.session.commit()
    flash("Archived.", "success")
    return redirect(url_for("email.inbox"))

@email_bp.route("/quarantine/<int:email_id>", methods=["POST"])
@login_required
def move_to_quarantine(email_id):
    import secrets
    from app.models.quarantine import QuarantineItem
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    if em.folder_status == "quarantine":
        flash("Already in quarantine.", "info")
        return redirect(url_for("email.view", email_id=email_id))
    em.folder_status = "quarantine"
    if not em.quarantine_item:
        db.session.add(QuarantineItem(
            email_id=em.email_id, user_id=current_user.user_id,
            status="held", action_token=secrets.token_urlsafe(32),
        ))
    db.session.commit()
    flash("Moved to quarantine.", "warning")
    return redirect(url_for("quarantine.index"))

@email_bp.route("/delete/<int:email_id>", methods=["POST"])
@login_required
def delete_email(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    prev = em.folder_status
    em.folder_status = "trash"
    db.session.commit()
    flash("Moved to Trash.", "success")
    return redirect(url_for("email.inbox", folder=prev))

@email_bp.route("/delete-permanent/<int:email_id>", methods=["POST"])
@login_required
def delete_permanent(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    db.session.delete(em)
    db.session.commit()
    flash("Permanently deleted.", "success")
    return redirect(url_for("email.inbox", folder="trash"))

@email_bp.route("/restore/<int:email_id>", methods=["POST"])
@login_required
def restore(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    em.folder_status = "inbox"
    db.session.commit()
    flash("Restored to Inbox.", "success")
    return redirect(url_for("email.inbox"))

@email_bp.route("/refresh")
@login_required
def refresh():
    try:
        from app.services.email_ingestion import fetch_and_process_emails
        fetch_and_process_emails(current_app._get_current_object())
        flash("Inbox refreshed!", "success")
    except Exception as e:
        flash(f"Refresh failed: {e}", "danger")
    return redirect(url_for("email.inbox"))

@email_bp.route("/feedback/<int:email_id>", methods=["POST"])
@login_required
def submit_feedback(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    user_label = request.form.get("label", "").lower()
    if user_label not in ("safe", "phishing"):
        flash("Invalid label.", "danger")
        return redirect(url_for("email.view", email_id=email_id))
    clf = em.classification
    FeedbackLabel.query.filter_by(
        email_id=email_id, user_id=current_user.user_id
    ).delete()
    db.session.add(FeedbackLabel(
        email_id=email_id, user_id=current_user.user_id,
        user_label=user_label,
        original_label=clf.label if clf else "unknown",
        misclassification_flag=(user_label != (clf.label if clf else "unknown")),
    ))
    db.session.commit()
    flash("Feedback saved!", "success")
    return redirect(url_for("email.view", email_id=email_id))

@email_bp.route("/api/count")
@login_required
def api_count():
    return jsonify({
        "inbox":      _inbox_query().count(),
        "spam":       _base_query().filter_by(folder_status="spam").count(),
        "quarantine": _base_query().filter_by(folder_status="quarantine").count(),
        "sent":       _sent_query().count(),
        "trash":      _base_query().filter_by(folder_status="trash").count(),
        "archive":    _base_query().filter_by(folder_status="archive").count(),
        "draft":      (Email.query.filter_by(user_id=current_user.user_id, folder_status="draft").count()
                       if not current_user.is_admin
                       else Email.query.filter_by(folder_status="draft").count()),
        "starred":    _base_query().filter_by(is_starred=True).count(),
        "unread":     _inbox_query().filter_by(is_read=False).count(),
    })

@email_bp.route("/analyse/<int:email_id>")
@login_required
def analyse_now(email_id):
    em = _get_email(email_id)
    if not em:
        flash("Not found.", "danger")
        return redirect(url_for("email.inbox"))
    if em.classification:
        flash("Already analysed.", "info")
        return redirect(url_for("email.view", email_id=email_id))
    try:
        from app.services.gmail_sync import _fast_analyse
        _fast_analyse(em, db, current_app.config)
        flash("Analysis complete!", "success")
    except Exception as e:
        flash(f"Analysis failed: {e}", "danger")
    return redirect(url_for("email.view", email_id=email_id))


# ── Helpers ───────────────────────────────────────────────────────────────────
def _get_email(email_id):
    if current_user.is_admin:
        return Email.query.get(email_id)
    email = current_user.email.lower().strip()
    return Email.query.filter(
        Email.email_id == email_id,
        db.or_(
            Email.user_id == current_user.user_id,
            _email_matches(Email.sender_email,   email),
            _email_matches(Email.receiver_email, email),
        )
    ).first()


def _smtp_send(sender, recipient, subject, body) -> bool:
    try:
        cfg = current_app.config
        msg = MIMEMultipart("alternative")
        msg["From"]    = sender
        msg["To"]      = recipient
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"]) as s:
            if cfg.get("MAIL_USE_TLS"):
                s.starttls()
            s.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
            s.sendmail(sender, recipient, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"SMTP error: {e}")
        return False


# ── Bulk Action ───────────────────────────────────────────────────────────────
@email_bp.route("/bulk-action", methods=["POST"])
@login_required
def bulk_action():
    """Handle bulk actions on multiple emails."""
    action    = request.form.get("action", "")
    folder    = request.form.get("folder", "inbox")
    email_ids = request.form.getlist("email_ids", type=int)

    if not email_ids:
        flash("No emails selected.", "warning")
        return redirect(url_for("email.inbox", folder=folder))

    # Get emails user has permission to access
    emails = []
    for eid in email_ids:
        em = _get_email(eid)
        if em:
            emails.append(em)

    if not emails:
        flash("No valid emails found.", "warning")
        return redirect(url_for("email.inbox", folder=folder))

    count = len(emails)

    if action == "delete":
        for em in emails:
            em.folder_status = "trash"
        db.session.commit()
        flash(f"Moved {count} email(s) to Trash.", "success")

    elif action == "delete_permanent":
        for em in emails:
            db.session.delete(em)
        db.session.commit()
        flash(f"Permanently deleted {count} email(s).", "success")

    elif action == "archive":
        for em in emails:
            em.folder_status = "archive"
        db.session.commit()
        flash(f"Archived {count} email(s).", "success")

    elif action == "mark_read":
        for em in emails:
            em.is_read = True
        db.session.commit()
        flash(f"Marked {count} email(s) as read.", "info")

    elif action == "mark_unread":
        for em in emails:
            em.is_read = False
        db.session.commit()
        flash(f"Marked {count} email(s) as unread.", "info")

    else:
        flash("Unknown action.", "danger")

    return redirect(url_for("email.inbox", folder=folder))
