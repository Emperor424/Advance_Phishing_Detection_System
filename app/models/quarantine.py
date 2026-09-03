from datetime import datetime
from app import db


class QuarantineItem(db.Model):
    __tablename__ = "quarantine_items"

    quarantine_id  = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id       = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False)
    user_id        = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    status         = db.Column(db.String(50), default="held")  # held | released | deleted
    action_token   = db.Column(db.String(500), nullable=True)
    quarantined_at = db.Column(db.DateTime, default=datetime.utcnow)
    actioned_at    = db.Column(db.DateTime, nullable=True)
    actioned_by    = db.Column(db.String(50), nullable=True)

    user = db.relationship("User", backref="quarantine_items")


class FeedbackLabel(db.Model):
    __tablename__ = "feedback_labels"

    feedback_id            = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id               = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False)
    user_id                = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    user_label             = db.Column(db.String(50), nullable=False)
    original_label         = db.Column(db.String(50), nullable=False)
    misclassification_flag = db.Column(db.Boolean, default=False)
    submitted_at           = db.Column(db.DateTime, default=datetime.utcnow)

    user  = db.relationship("User", backref="feedbacks")
    email = db.relationship("Email", backref="feedbacks")


class SystemConfig(db.Model):
    __tablename__ = "system_config"

    config_key   = db.Column(db.String(100), primary_key=True)
    config_value = db.Column(db.String(500), nullable=False)
    updated_by   = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)
    updated_at   = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @classmethod
    def get(cls, key: str, default=None):
        row = cls.query.filter_by(config_key=key).first()
        return row.config_value if row else default

    @classmethod
    def set(cls, key: str, value: str, user_id: int = None):
        row = cls.query.filter_by(config_key=key).first()
        if row:
            row.config_value = value
            row.updated_by = user_id
        else:
            row = cls(config_key=key, config_value=value, updated_by=user_id)
            db.session.add(row)
        db.session.commit()


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    log_id      = db.Column(db.Integer, primary_key=True, autoincrement=True)
    actor_id    = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)
    action_type = db.Column(db.String(100), nullable=False)
    detail      = db.Column(db.Text, nullable=True)
    ip_address  = db.Column(db.String(45), nullable=True)
    logged_at   = db.Column(db.DateTime, default=datetime.utcnow)

    actor = db.relationship("User", backref="audit_logs")

    @classmethod
    def write(cls, action_type: str, detail: str = None, actor_id: int = None, ip: str = None):
        entry = cls(action_type=action_type, detail=detail, actor_id=actor_id, ip_address=ip)
        db.session.add(entry)
        db.session.commit()
