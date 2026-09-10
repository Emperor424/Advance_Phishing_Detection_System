import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")
    WTF_CSRF_ENABLED = True

    # ── Database ──────────────────────────────────────────────────────────────
    DB_HOST = os.environ.get("DB_HOST", "localhost")
    DB_PORT = os.environ.get("DB_PORT", "3306")
    DB_NAME = os.environ.get("DB_NAME", "phishguard")
    DB_USER = os.environ.get("DB_USER", "root")
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
        "?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 280,
        "pool_pre_ping": True,
    }

    # ── Mail (SMTP) ────────────────────────────────────────────────────────────
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "True") == "True"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "PhishGuard <noreply@phishguard.com>")

    # ── IMAP ingestion ─────────────────────────────────────────────────────────
    IMAP_HOST = os.environ.get("IMAP_HOST", "imap.gmail.com")
    IMAP_PORT = int(os.environ.get("IMAP_PORT", 993))
    IMAP_EMAIL = os.environ.get("IMAP_EMAIL", "")
    IMAP_PASSWORD = os.environ.get("IMAP_PASSWORD", "")
    IMAP_POLL_INTERVAL_MINUTES = int(os.environ.get("IMAP_POLL_INTERVAL_MINUTES", 5))

    # ── ML / Detection ─────────────────────────────────────────────────────────
    QUARANTINE_THRESHOLD = int(os.environ.get("QUARANTINE_THRESHOLD", 65))
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml", "phishguard_model.joblib")
    VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "ml", "tfidf_vectorizer.joblib")

    # ── Misc ───────────────────────────────────────────────────────────────────
    ACTIVATION_TOKEN_EXPIRY_HOURS = int(os.environ.get("ACTIVATION_TOKEN_EXPIRY_HOURS", 24))
    RESET_TOKEN_EXPIRY_MINUTES = int(os.environ.get("RESET_TOKEN_EXPIRY_MINUTES", 60))
    SAFE_BROWSING_API_KEY = os.environ.get("SAFE_BROWSING_API_KEY", "")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB upload limit


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    WTF_CSRF_ENABLED = True


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}