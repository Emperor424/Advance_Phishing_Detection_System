from datetime import datetime
from app import db


class Email(db.Model):
    __tablename__ = "emails"

    email_id        = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="SET NULL"), nullable=True)
    sender_email    = db.Column(db.String(255), nullable=False)
    receiver_email  = db.Column(db.String(255), nullable=False)
    subject         = db.Column(db.String(500), nullable=True)
    email_body      = db.Column(db.Text, nullable=True)
    email_html      = db.Column(db.Text, nullable=True)
    raw_headers     = db.Column(db.Text, nullable=True)
    folder_status   = db.Column(db.String(50), nullable=False, default="inbox")
    email_direction = db.Column(db.String(50), nullable=False, default="received")
    message_id      = db.Column(db.String(500), nullable=True)
    sent_time       = db.Column(db.DateTime, nullable=True)
    received_time   = db.Column(db.DateTime, default=datetime.utcnow)
    is_read         = db.Column(db.Boolean, default=False)
    is_starred      = db.Column(db.Boolean, default=False)   # ← Star feature
    has_attachments = db.Column(db.Boolean, default=False)

    user            = db.relationship("User", backref="emails")
    monitoring      = db.relationship("EmailMonitoring", backref="email", uselist=False, cascade="all, delete-orphan")
    nlp_analysis    = db.relationship("NLPAnalysis", backref="email", uselist=False, cascade="all, delete-orphan")
    link_analyses   = db.relationship("LinkAnalysis", backref="email", cascade="all, delete-orphan")
    header_analysis = db.relationship("HeaderAnalysis", backref="email", uselist=False, cascade="all, delete-orphan")
    classification  = db.relationship("Classification", backref="email", uselist=False, cascade="all, delete-orphan")
    quarantine_item = db.relationship("QuarantineItem", backref="email", uselist=False, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Email {self.email_id} from={self.sender_email}>"


class EmailMonitoring(db.Model):
    __tablename__ = "email_monitoring"

    monitoring_id    = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email_id         = db.Column(db.Integer, db.ForeignKey("emails.email_id", ondelete="CASCADE"), nullable=False)
    monitoring_status= db.Column(db.String(50), default="pending")
    processing_stage = db.Column(db.String(100), default="queued")
    start_time       = db.Column(db.DateTime, default=datetime.utcnow)
    finish_time      = db.Column(db.DateTime, nullable=True)
    error_message    = db.Column(db.Text, nullable=True)


class SearchHistory(db.Model):
    __tablename__ = "search_history"

    search_id       = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id         = db.Column(db.Integer, db.ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    search_keyword  = db.Column(db.String(255), nullable=False)
    search_filter   = db.Column(db.String(255), nullable=True)
    searched_folder = db.Column(db.String(50), nullable=True)
    search_time     = db.Column(db.DateTime, default=datetime.utcnow)