-- ============================================================
--  PhishGuard — Full Database Schema
--  MySQL 9.4  |  charset utf8mb4
-- ============================================================

CREATE DATABASE IF NOT EXISTS phishguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishguard;

-- ─── Users ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    user_id          INT            NOT NULL AUTO_INCREMENT,
    full_name        VARCHAR(255)   NOT NULL,
    email            VARCHAR(255)   NOT NULL,
    password_hash    VARCHAR(255)   NOT NULL,
    role             VARCHAR(50)    NOT NULL DEFAULT 'user',   -- 'user' | 'admin'
    account_status   VARCHAR(50)    NOT NULL DEFAULT 'inactive', -- 'inactive'|'active'|'banned'
    activation_token VARCHAR(255)   NULL,
    token_expiry     DATETIME       NULL,
    created_time     DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login       DATETIME       NULL,
    failed_attempts  INT            NOT NULL DEFAULT 0,
    locked_until     DATETIME       NULL,
    digest_frequency VARCHAR(50)    NOT NULL DEFAULT 'daily',  -- 'immediate'|'daily'|'weekly'|'disabled'
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

-- Seed admin account (password: Admin@1234)
INSERT IGNORE INTO users
    (full_name, email, password_hash, role, account_status)
VALUES
    ('PhishGuard Admin',
     'admin@phishguard.com',
     '$2b$12$7B8Q1K2k3L4M5N6P7Q8R9O.aBcDeFgHiJkLmNoPqRsTuVwXyZ012',
     'admin',
     'active');

-- ─── Emails ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS emails (
    email_id        INT            NOT NULL AUTO_INCREMENT,
    user_id         INT            NULL,
    sender_email    VARCHAR(255)   NOT NULL,
    receiver_email  VARCHAR(255)   NOT NULL,
    subject         VARCHAR(500)   NULL,
    email_body      LONGTEXT       NULL,
    email_html      LONGTEXT       NULL,
    raw_headers     LONGTEXT       NULL,
    folder_status   VARCHAR(50)    NOT NULL DEFAULT 'inbox',  -- 'inbox'|'spam'|'quarantine'|'sent'|'trash'
    email_direction VARCHAR(50)    NOT NULL DEFAULT 'received', -- 'received'|'sent'
    message_id      VARCHAR(500)   NULL,
    sent_time       DATETIME       NULL,
    received_time   DATETIME       NULL DEFAULT CURRENT_TIMESTAMP,
    is_read         TINYINT(1)     NOT NULL DEFAULT 0,
    has_attachments TINYINT(1)     NOT NULL DEFAULT 0,
    PRIMARY KEY (email_id),
    KEY idx_emails_user     (user_id),
    KEY idx_emails_folder   (folder_status),
    KEY idx_emails_received (received_time),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ─── Search History ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS search_history (
    search_id       INT            NOT NULL AUTO_INCREMENT,
    user_id         INT            NOT NULL,
    search_keyword  VARCHAR(255)   NOT NULL,
    search_filter   VARCHAR(255)   NULL,
    searched_folder VARCHAR(50)    NULL,
    search_time     DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (search_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Email Monitoring ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_monitoring (
    monitoring_id    INT            NOT NULL AUTO_INCREMENT,
    email_id         INT            NOT NULL,
    monitoring_status VARCHAR(50)  NOT NULL DEFAULT 'pending', -- 'pending'|'analysing'|'completed'|'failed'
    processing_stage VARCHAR(100)  NOT NULL DEFAULT 'queued',
    start_time       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finish_time      DATETIME      NULL,
    error_message    TEXT          NULL,
    PRIMARY KEY (monitoring_id),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── NLP Analysis ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nlp_analysis (
    analysis_id          INT            NOT NULL AUTO_INCREMENT,
    email_id             INT            NOT NULL,
    urgency_score        FLOAT          NULL DEFAULT 0.0,
    sentiment_score      FLOAT          NULL DEFAULT 0.0,
    grammar_error_rate   FLOAT          NULL DEFAULT 0.0,
    impersonation_score  FLOAT          NULL DEFAULT 0.0,
    keyword_density      FLOAT          NULL DEFAULT 0.0,
    suspicious_keywords  TEXT           NULL,
    text_risk_score      FLOAT          NULL DEFAULT 0.0,
    analysed_at          DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (analysis_id),
    UNIQUE KEY uq_nlp_email (email_id),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Link Analysis ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS link_analysis (
    link_id         INT            NOT NULL AUTO_INCREMENT,
    email_id        INT            NOT NULL,
    anchor_text     TEXT           NULL,
    href_url        TEXT           NULL,
    final_url       TEXT           NULL,
    mismatch_flag   TINYINT(1)     NOT NULL DEFAULT 0,
    reputation      VARCHAR(50)    NOT NULL DEFAULT 'unknown', -- 'safe'|'suspicious'|'malicious'|'unknown'
    homoglyph_flag  TINYINT(1)     NOT NULL DEFAULT 0,
    suspicious_tld  TINYINT(1)     NOT NULL DEFAULT 0,
    link_risk_score FLOAT          NULL DEFAULT 0.0,
    PRIMARY KEY (link_id),
    KEY idx_link_email (email_id),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Header Analysis ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS header_analysis (
    header_id           INT            NOT NULL AUTO_INCREMENT,
    email_id            INT            NOT NULL,
    spf_result          VARCHAR(50)    NULL DEFAULT 'none',  -- 'pass'|'fail'|'softfail'|'neutral'|'none'
    dkim_valid          TINYINT(1)     NOT NULL DEFAULT 0,
    dmarc_policy        VARCHAR(50)    NULL DEFAULT 'none',  -- 'none'|'quarantine'|'reject'
    spoofing_flag       TINYINT(1)     NOT NULL DEFAULT 0,
    reply_to_mismatch   TINYINT(1)     NOT NULL DEFAULT 0,
    routing_anomaly     TINYINT(1)     NOT NULL DEFAULT 0,
    sender_domain       VARCHAR(255)   NULL,
    display_name        VARCHAR(255)   NULL,
    header_risk_score   FLOAT          NULL DEFAULT 0.0,
    analysed_at         DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (header_id),
    UNIQUE KEY uq_header_email (email_id),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Sender Reputation ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sender_reputation (
    rep_id          INT            NOT NULL AUTO_INCREMENT,
    sender_email    VARCHAR(255)   NOT NULL,
    sender_domain   VARCHAR(255)   NOT NULL,
    total_emails    INT            NOT NULL DEFAULT 1,
    phishing_count  INT            NOT NULL DEFAULT 0,
    phishing_rate   FLOAT          NOT NULL DEFAULT 0.0,
    rep_badge       VARCHAR(50)    NOT NULL DEFAULT 'neutral', -- 'trusted'|'neutral'|'suspicious'|'known-bad'
    last_seen       DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (rep_id),
    UNIQUE KEY uq_rep_email (sender_email)
) ENGINE=InnoDB;

-- ─── ML Classifications ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS classifications (
    classification_id INT           NOT NULL AUTO_INCREMENT,
    email_id          INT           NOT NULL,
    risk_score        FLOAT         NOT NULL DEFAULT 0.0,
    label             VARCHAR(50)   NOT NULL DEFAULT 'safe', -- 'safe'|'phishing'|'suspicious'
    top_feature_1     VARCHAR(100)  NULL,
    top_feature_2     VARCHAR(100)  NULL,
    top_feature_3     VARCHAR(100)  NULL,
    explanation_text  TEXT          NULL,
    model_version     VARCHAR(50)   NOT NULL DEFAULT 'v1.0',
    classified_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (classification_id),
    UNIQUE KEY uq_class_email (email_id),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── Quarantine ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS quarantine_items (
    quarantine_id   INT            NOT NULL AUTO_INCREMENT,
    email_id        INT            NOT NULL,
    user_id         INT            NOT NULL,
    status          VARCHAR(50)    NOT NULL DEFAULT 'held', -- 'held'|'released'|'deleted'
    action_token    VARCHAR(500)   NULL,
    quarantined_at  DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actioned_at     DATETIME       NULL,
    actioned_by     VARCHAR(50)    NULL,  -- 'user'|'admin'|'auto'
    PRIMARY KEY (quarantine_id),
    KEY idx_quarantine_user   (user_id),
    KEY idx_quarantine_status (status),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)  REFERENCES users(user_id)  ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── User Feedback ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS feedback_labels (
    feedback_id           INT           NOT NULL AUTO_INCREMENT,
    email_id              INT           NOT NULL,
    user_id               INT           NOT NULL,
    user_label            VARCHAR(50)   NOT NULL, -- 'safe'|'phishing'
    original_label        VARCHAR(50)   NOT NULL,
    misclassification_flag TINYINT(1)   NOT NULL DEFAULT 0,
    submitted_at          DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (feedback_id),
    KEY idx_feedback_email (email_id),
    FOREIGN KEY (email_id) REFERENCES emails(email_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)  REFERENCES users(user_id)  ON DELETE CASCADE
) ENGINE=InnoDB;

-- ─── System Config ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_config (
    config_key      VARCHAR(100)   NOT NULL,
    config_value    VARCHAR(500)   NOT NULL,
    updated_by      INT            NULL,
    updated_at      DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (config_key),
    FOREIGN KEY (updated_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

INSERT IGNORE INTO system_config (config_key, config_value) VALUES
    ('quarantine_threshold', '65'),
    ('active_model_version', 'v1.0'),
    ('imap_poll_interval',   '5');

-- ─── Audit Log ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    log_id          INT            NOT NULL AUTO_INCREMENT,
    actor_id        INT            NULL,
    action_type     VARCHAR(100)   NOT NULL,
    detail          TEXT           NULL,
    ip_address      VARCHAR(45)    NULL,
    logged_at       DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (log_id),
    KEY idx_audit_actor (actor_id)
) ENGINE=InnoDB;
