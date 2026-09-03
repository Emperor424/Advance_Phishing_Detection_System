# PhishGuard — Setup Guide

## Quick Start (5 steps)

### Step 1 — Copy environment file
```bash
cp .env.example .env
# Edit .env and fill in your DB + email credentials
```

### Step 2 — Create MySQL database
```bash
mysql -u root -p < database.sql
```

### Step 3 — Fix admin password hash
```bash
# Generate a real bcrypt hash for Admin@1234
python3 -c "import bcrypt; print(bcrypt.hashpw(b'Admin@1234', bcrypt.gensalt(12)).decode())"
# Copy the output and run:
mysql -u root -p phishguard -e "UPDATE users SET password_hash='<paste_hash_here>' WHERE email='admin@phishguard.com';"
```

### Step 4 — Install dependencies & train ML model
```bash
pip install -r requirements.txt
python ml/train_model.py
```

### Step 5 — Run the app
```bash
python run.py
```
Open http://localhost:5000 in your browser.

---

## Default Admin Credentials
- Email:    admin@phishguard.com
- Password: Admin@1234
  (change this after first login)

---

## Project Structure
```
phishguard/
├── run.py                      ← Flask entry point + IMAP scheduler
├── config.py                   ← App configuration
├── database.sql                ← MySQL schema (run once)
├── requirements.txt
├── .env.example                ← Copy to .env and fill credentials
├── ml/
│   └── train_model.py          ← Run once to train baseline ML model
└── app/
    ├── models/                 ← SQLAlchemy ORM models
    │   ├── user.py             ← User, login, lockout
    │   ├── email_model.py      ← Email, EmailMonitoring, SearchHistory
    │   ├── analysis.py         ← NLPAnalysis, LinkAnalysis, HeaderAnalysis, etc.
    │   └── quarantine.py       ← QuarantineItem, FeedbackLabel, SystemConfig, AuditLog
    ├── routes/                 ← Flask Blueprints
    │   ├── auth.py             ← Register, login, logout, activate
    │   ├── email_routes.py     ← Inbox, view, compose, send, feedback
    │   ├── admin.py            ← Dashboard, threshold, users, audit, metrics, retrain
    │   └── quarantine.py       ← List, release, delete
    ├── services/               ← Business logic
    │   ├── nlp_analyzer.py     ← Urgency, sentiment, grammar, impersonation
    │   ├── link_analyzer.py    ← URL mismatch, homoglyph, Safe Browsing
    │   ├── header_analyzer.py  ← SPF, DKIM, DMARC, spoofing
    │   ├── ml_classifier.py    ← Feature vector + GradientBoosting + rule fallback
    │   ├── email_ingestion.py  ← IMAP polling + full analysis pipeline
    │   ├── email_sender.py     ← SMTP send + quarantine digest
    │   └── model_trainer.py    ← Feedback-based retraining
    ├── static/
    │   ├── css/main.css        ← Full design system
    │   └── js/main.js          ← Password strength, toggle, alerts
    └── templates/
        ├── base.html           ← Sidebar layout + auth layout
        ├── auth/               ← Login, register
        ├── email/              ← Inbox, view, compose
        ├── admin/              ← Dashboard, users, metrics, audit
        └── quarantine/         ← Quarantine list
```

## Gmail IMAP/SMTP Setup
1. Enable 2-Step Verification on your Gmail account
2. Go to Security → App passwords → Generate one for "Mail"
3. Use that 16-character password in IMAP_PASSWORD and MAIL_PASSWORD in .env

## Key URLs
| URL | Description |
|-----|-------------|
| / | Redirects to login |
| /auth/login | Login page |
| /auth/register | Registration page |
| /email/inbox | User inbox |
| /email/compose | Compose email |
| /quarantine | Quarantine list |
| /admin/dashboard | Admin dashboard |
| /admin/users | User management |
| /admin/metrics | ML model metrics |
| /admin/audit | Audit log |
