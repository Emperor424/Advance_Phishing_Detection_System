from datetime import datetime, timedelta, timezone
import secrets
import bcrypt
from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    user_id          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    full_name        = db.Column(db.String(255), nullable=False)
    email            = db.Column(db.String(255), nullable=False, unique=True)
    password_hash    = db.Column(db.String(255), nullable=False)
    role             = db.Column(db.String(50), nullable=False, default="user")
    account_status   = db.Column(db.String(50), nullable=False, default="inactive")
    activation_token = db.Column(db.String(255), nullable=True)
    token_expiry     = db.Column(db.DateTime, nullable=True)
    created_time     = db.Column(db.DateTime, default=datetime.utcnow)
    last_login       = db.Column(db.DateTime, nullable=True)
    failed_attempts  = db.Column(db.Integer, default=0)
    locked_until     = db.Column(db.DateTime, nullable=True)
    digest_frequency = db.Column(db.String(50), default="daily")
    gmail_email          = db.Column(db.String(255), nullable=True)
    gmail_app_password   = db.Column(db.String(255), nullable=True)
    reset_token          = db.Column(db.String(255), nullable=True)
    reset_token_expiry   = db.Column(db.DateTime, nullable=True)

    # Flask-Login requires get_id() to return a string
    def get_id(self):
        return str(self.user_id)

    # ── Password helpers ──────────────────────────────────────────────────────
    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    # ── Activation token ──────────────────────────────────────────────────────
    def generate_activation_token(self, expiry_hours: int = 24) -> str:
        token = secrets.token_urlsafe(32)
        self.activation_token = token
        self.token_expiry = datetime.utcnow() + timedelta(hours=expiry_hours)
        return token

    def is_token_valid(self, token: str) -> bool:
        if not self.activation_token or not self.token_expiry:
            return False
        if self.activation_token != token:
            return False
        return datetime.utcnow() < self.token_expiry

    # ── Password reset token ──────────────────────────────────────────────────
    def generate_reset_token(self, expiry_minutes: int = 60) -> str:
        token = secrets.token_urlsafe(32)
        self.reset_token = token
        self.reset_token_expiry = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        return token

    def is_reset_token_valid(self, token: str) -> bool:
        if not self.reset_token or not self.reset_token_expiry:
            return False
        if self.reset_token != token:
            return False
        return datetime.utcnow() < self.reset_token_expiry

    def clear_reset_token(self):
        self.reset_token = None
        self.reset_token_expiry = None

    # ── Account lock ──────────────────────────────────────────────────────────
    def is_locked(self) -> bool:
        if self.locked_until and datetime.utcnow() < self.locked_until:
            return True
        return False

    def increment_failed_attempts(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

    def reset_failed_attempts(self):
        self.failed_attempts = 0
        self.locked_until = None

    # ── Properties ────────────────────────────────────────────────────────────
    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_active(self) -> bool:  # Flask-Login uses this
        return self.account_status == "active"

    @property
    def has_gmail_connected(self) -> bool:
        return bool(self.gmail_email and self.gmail_app_password)

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"