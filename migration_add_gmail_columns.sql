-- Run this once in phpMyAdmin (SQL tab, on the `phishguard` database)
-- before starting the app with the new code.
ALTER TABLE users
    ADD COLUMN gmail_email        VARCHAR(255) NULL AFTER digest_frequency,
    ADD COLUMN gmail_app_password VARCHAR(255) NULL AFTER gmail_email;
