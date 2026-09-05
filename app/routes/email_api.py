from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.email_model import Email

api_bp = Blueprint("api", __name__)


def _exact_match(column, email):
    return db.or_(
        db.func.lower(column) == email,
        column.ilike(f"%<{email}>%"),
        column.ilike(f"{email},%"),
        column.ilike(f"%, {email}"),
    )


@api_bp.route("/email/count")
@login_required
def email_count():
    if current_user.is_admin:
        base = Email.query
    else:
        uid   = current_user.user_id
        email = current_user.email.lower().strip()
        base  = Email.query.filter(
            db.or_(
                Email.user_id == uid,
                Email.user_id == None,
                _exact_match(Email.sender_email,   email),
                _exact_match(Email.receiver_email, email),
            )
        )

    # Inbox: only received emails for this user
    if current_user.is_admin:
        inbox_q = base.filter_by(folder_status="inbox")
    else:
        uid   = current_user.user_id
        email = current_user.email.lower().strip()
        inbox_q = Email.query.filter(
            Email.folder_status == "inbox",
            db.or_(
                Email.user_id == uid,
                Email.user_id == None,
                _exact_match(Email.receiver_email, email),
            )
        )

    # Sent: only emails this user sent
    if current_user.is_admin:
        sent_q = base.filter_by(folder_status="sent")
    else:
        sent_q = Email.query.filter_by(
            user_id=current_user.user_id, folder_status="sent"
        )

    return jsonify({
        "inbox":      inbox_q.count(),
        "spam":       base.filter_by(folder_status="spam").count(),
        "quarantine": base.filter_by(folder_status="quarantine").count(),
        "sent":       sent_q.count(),
        "trash":      base.filter_by(folder_status="trash").count(),
        "archive":    base.filter_by(folder_status="archive").count(),
        "draft":      (Email.query.filter_by(user_id=current_user.user_id, folder_status="draft").count()
                       if not current_user.is_admin
                       else Email.query.filter_by(folder_status="draft").count()),
        "starred":    base.filter_by(is_starred=True).count(),
        "unread":     inbox_q.filter_by(is_read=False).count(),
    })
