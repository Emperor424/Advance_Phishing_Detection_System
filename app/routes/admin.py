from datetime import datetime, timedelta
from functools import wraps

from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, jsonify, current_app)
from flask_login import login_required, current_user
from sqlalchemy import func

from app import db
from app.models.user import User
from app.models.email_model import Email, EmailMonitoring
from app.models.analysis import Classification, SenderReputation
from app.models.quarantine import (
    QuarantineItem, FeedbackLabel, SystemConfig, AuditLog
)

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ─────────────────────────────────────────────────────────────────
@admin_bp.route("/dashboard")
@login_required
@admin_required
def dashboard():
    today    = datetime.utcnow().date()
    week_ago = datetime.utcnow() - timedelta(days=7)

    total_emails_today = Email.query.filter(
        func.date(Email.received_time) == today
    ).count()

    phishing_today = (
        db.session.query(Classification)
        .join(Email)
        .filter(
            Classification.label.in_(["phishing", "suspicious"]),
            func.date(Email.received_time) == today,
        ).count()
    )

    quarantine_rate = round(
        (phishing_today / total_emails_today * 100)
        if total_emails_today > 0 else 0, 1
    )

    feedback_count  = FeedbackLabel.query.count()
    false_positives = FeedbackLabel.query.filter_by(
        original_label="phishing", user_label="safe"
    ).count()
    fp_rate = round(
        (false_positives / max(feedback_count, 1)) * 100, 1
    )

    model_version     = SystemConfig.get("active_model_version", "v1.0")
    threshold         = int(SystemConfig.get("quarantine_threshold", "65"))
    recent_quarantine = (
        QuarantineItem.query
        .filter_by(status="held")
        .order_by(QuarantineItem.quarantined_at.desc())
        .limit(10).all()
    )

    # Risk score distribution (10 buckets)
    classifications = (
        Classification.query
        .join(Email)
        .filter(Email.received_time >= week_ago)
        .all()
    )
    buckets = [0] * 10
    for c in classifications:
        bucket = min(9, int(c.risk_score // 10))
        buckets[bucket] += 1

    top_senders = (
        SenderReputation.query
        .filter(SenderReputation.phishing_rate > 0.3)
        .order_by(SenderReputation.phishing_rate.desc())
        .limit(5).all()
    )

    recent_monitoring = (
        EmailMonitoring.query
        .order_by(EmailMonitoring.start_time.desc())
        .limit(8).all()
    )

    return render_template(
        "admin/dashboard.html",
        total_emails_today = total_emails_today,
        phishing_today     = phishing_today,
        quarantine_rate    = quarantine_rate,
        fp_rate            = fp_rate,
        feedback_count     = feedback_count,
        model_version      = model_version,
        threshold          = threshold,
        recent_quarantine  = recent_quarantine,
        score_buckets      = buckets,
        top_senders        = top_senders,
        recent_monitoring  = recent_monitoring,
    )


# ── Threshold Update ──────────────────────────────────────────────────────────
@admin_bp.route("/threshold", methods=["POST"])
@login_required
@admin_required
def update_threshold():
    new_val = request.form.get("threshold", "65")
    try:
        val = int(new_val)
        assert 0 <= val <= 100
    except (ValueError, AssertionError):
        flash("Threshold must be between 0 and 100.", "danger")
        return redirect(url_for("admin.dashboard"))

    old_val = SystemConfig.get("quarantine_threshold", "65")
    SystemConfig.set("quarantine_threshold", str(val), current_user.user_id)
    AuditLog.write(
        "THRESHOLD_UPDATE",
        f"Changed from {old_val} to {val}",
        actor_id = current_user.user_id,
        ip       = request.remote_addr,
    )
    flash(f"Threshold updated to {val}.", "success")
    return redirect(url_for("admin.dashboard"))


# ── Threshold Preview (AJAX) ──────────────────────────────────────────────────
@admin_bp.route("/threshold/preview")
@login_required
@admin_required
def threshold_preview():
    candidate = request.args.get("threshold", "65", type=int)
    week_ago  = datetime.utcnow() - timedelta(days=7)
    count = (
        Classification.query
        .join(Email)
        .filter(
            Classification.risk_score >= candidate,
            Email.received_time >= week_ago,
        ).count()
    )
    return jsonify({"count": count, "threshold": candidate})


# ── Users ─────────────────────────────────────────────────────────────────────
@admin_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_time.desc()).all()
    return render_template("admin/users.html", users=all_users)


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.user_id == current_user.user_id:
        flash("You cannot modify your own account.", "warning")
        return redirect(url_for("admin.users"))
    user.account_status = "active" if user.account_status == "banned" else "banned"
    db.session.commit()
    AuditLog.write(
        f"USER_{user.account_status.upper()}",
        f"User {user.email}",
        actor_id = current_user.user_id,
        ip       = request.remote_addr,
    )
    flash(f"User {user.email} is now {user.account_status}.", "success")
    return redirect(url_for("admin.users"))


# ── Audit Log ─────────────────────────────────────────────────────────────────
@admin_bp.route("/audit")
@login_required
@admin_required
def audit_log():
    page = request.args.get("page", 1, type=int)
    logs = AuditLog.query.order_by(
        AuditLog.logged_at.desc()
    ).paginate(page=page, per_page=30, error_out=False)
    return render_template("admin/audit.html", logs=logs)


# ── Model Metrics ─────────────────────────────────────────────────────────────
@admin_bp.route("/metrics")
@login_required
@admin_required
def metrics():
    feedbacks = FeedbackLabel.query.order_by(FeedbackLabel.submitted_at.desc()).all()

    # Only feedback tied to an email that was actually classified counts
    # toward the metrics — feedback on an unclassified/"unknown" email
    # (e.g. a manually composed test email) doesn't measure the classifier.
    scored = [f for f in feedbacks if f.original_label in ("phishing", "suspicious", "safe")]
    total  = len(scored)
    if total == 0:
        return render_template("admin/metrics.html", metrics={}, total=0, feedbacks=feedbacks)

    tp = sum(1 for f in scored if f.user_label == "phishing" and f.original_label in ("phishing", "suspicious"))
    fp = sum(1 for f in scored if f.user_label == "safe"     and f.original_label in ("phishing", "suspicious"))
    fn = sum(1 for f in scored if f.user_label == "phishing" and f.original_label == "safe")
    tn = sum(1 for f in scored if f.user_label == "safe"     and f.original_label == "safe")

    precision = round(tp / max(tp + fp, 1) * 100, 1)
    recall    = round(tp / max(tp + fn, 1) * 100, 1)
    f1        = round(2 * precision * recall / max(precision + recall, 1), 1)
    accuracy  = round((tp + tn) / total * 100, 1)

    return render_template(
        "admin/metrics.html",
        metrics = {
            "precision": precision,
            "recall":    recall,
            "f1":        f1,
            "accuracy":  accuracy,
        },
        total     = total,
        feedbacks = feedbacks,
    )


# ── Retrain Model ─────────────────────────────────────────────────────────────
@admin_bp.route("/retrain", methods=["POST"])
@login_required
@admin_required
def retrain():
    feedback_count = FeedbackLabel.query.count()
    if feedback_count < 10:
        flash(
            f"Not enough feedback ({feedback_count} samples). Need at least 10.",
            "warning"
        )
        return redirect(url_for("admin.metrics"))

    import threading
    from app.services.model_trainer import retrain_model
    t = threading.Thread(
        target = retrain_model,
        args   = (current_app._get_current_object(),),
        daemon = True,
    )
    t.start()

    AuditLog.write(
        "MODEL_RETRAIN_TRIGGERED",
        f"Triggered with {feedback_count} samples",
        actor_id = current_user.user_id,
        ip       = request.remote_addr,
    )
    flash("Model retraining started in background.", "info")
    return redirect(url_for("admin.metrics"))


# ── Fix Stuck Emails ──────────────────────────────────────────────────────────
@admin_bp.route("/fix-stuck")
@login_required
@admin_required
def fix_stuck():
    """Reset emails stuck in 'analysing' status."""
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    stuck  = EmailMonitoring.query.filter_by(
        monitoring_status="analysing"
    ).filter(
        EmailMonitoring.start_time < cutoff
    ).all()

    count = len(stuck)
    for m in stuck:
        m.monitoring_status = "failed"
        m.error_message     = "Timeout — manually reset"
        m.finish_time       = datetime.utcnow()

    db.session.commit()
    AuditLog.write(
        "FIX_STUCK",
        f"Reset {count} stuck emails",
        actor_id = current_user.user_id,
        ip       = request.remote_addr,
    )
    flash(f"Fixed {count} stuck email(s).", "success")
    return redirect(url_for("admin.dashboard"))


# ── Send Digest Now (manual trigger) ─────────────────────────────────────────
@admin_bp.route("/send-digest", methods=["POST"])
@login_required
@admin_required
def send_digest_now():
    """Manually trigger quarantine digest for all users."""
    try:
        from app.models.quarantine import QuarantineItem
        from app.services.email_sender import send_digest

        base_url = request.host_url.rstrip("/")
        users    = User.query.filter_by(account_status="active").all()
        sent     = 0

        for user in users:
            items = QuarantineItem.query.filter_by(
                user_id=user.user_id, status="held"
            ).all()
            if items:
                if send_digest(user, items, base_url):
                    sent += 1

        AuditLog.write(
            "DIGEST_SENT",
            f"Manual digest sent to {sent} user(s)",
            actor_id = current_user.user_id,
            ip       = request.remote_addr,
        )
        flash(f"Digest sent to {sent} user(s).", "success")

    except Exception as e:
        flash(f"Digest send failed: {e}", "danger")

    return redirect(url_for("admin.dashboard"))
