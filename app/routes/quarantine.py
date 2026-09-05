from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models.email_model import Email
from app.models.quarantine import QuarantineItem, AuditLog
import secrets

quarantine_bp = Blueprint("quarantine", __name__)


def _exact_match(column, email):
    return db.or_(
        db.func.lower(column) == email,
        column.ilike(f"%<{email}>%"),
        column.ilike(f"{email},%"),
        column.ilike(f"%, {email}"),
    )


@quarantine_bp.route("/")
@login_required
def index():
    if current_user.is_admin:
        quarantined = Email.query.filter_by(
            folder_status="quarantine"
        ).order_by(Email.received_time.desc()).all()
    else:
        uid   = current_user.user_id
        email = current_user.email.lower().strip()
        quarantined = Email.query.filter(
            Email.folder_status == "quarantine",
            db.or_(
                Email.user_id == uid,
                Email.user_id == None,
                _exact_match(Email.receiver_email, email),
            )
        ).order_by(Email.received_time.desc()).all()

    for em in quarantined:
        if not em.quarantine_item:
            db.session.add(QuarantineItem(
                email_id=em.email_id, user_id=current_user.user_id,
                status="held", action_token=secrets.token_urlsafe(32),
            ))
    if quarantined:
        db.session.commit()

    return render_template(
        "quarantine/index.html",
        quarantined=quarantined,
        total=len(quarantined),
    )


@quarantine_bp.route("/release/<int:quarantine_id>", methods=["POST"])
@login_required
def release(quarantine_id):
    qi = QuarantineItem.query.get_or_404(quarantine_id)
    em = qi.email
    if not current_user.is_admin:
        email = current_user.email.lower()
        if not (em.user_id == current_user.user_id or
                email == (em.receiver_email or "").lower().strip() or
                email in (em.receiver_email or "").lower()):
            flash("Permission denied.", "danger")
            return redirect(url_for("quarantine.index"))
    em.folder_status = "inbox"
    qi.status = "released"
    db.session.commit()
    AuditLog.write("QUARANTINE_RELEASE", f"Email #{em.email_id} released",
                   actor_id=current_user.user_id, ip=request.remote_addr)
    flash("Released to Inbox.", "success")
    return redirect(url_for("quarantine.index"))


@quarantine_bp.route("/delete/<int:quarantine_id>", methods=["POST"])
@login_required
def delete(quarantine_id):
    qi = QuarantineItem.query.get_or_404(quarantine_id)
    em = qi.email
    if not current_user.is_admin:
        email = current_user.email.lower()
        if not (em.user_id == current_user.user_id or
                email == (em.receiver_email or "").lower().strip()):
            flash("Permission denied.", "danger")
            return redirect(url_for("quarantine.index"))
    em.folder_status = "trash"
    qi.status = "deleted"
    db.session.commit()
    AuditLog.write("QUARANTINE_DELETE", f"Email #{em.email_id} deleted",
                   actor_id=current_user.user_id, ip=request.remote_addr)
    flash("Email deleted.", "success")
    return redirect(url_for("quarantine.index"))
