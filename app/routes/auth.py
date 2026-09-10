from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message
from app import db, mail
from app.models.user import User
from app.models.quarantine import AuditLog

auth_bp = Blueprint("auth", __name__)


# ── Register ──────────────────────────────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("email.inbox"))

    if request.method == "POST":
        full_name        = request.form.get("full_name", "").strip()
        email            = request.form.get("email", "").strip().lower()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []

        # Validation
        if not full_name:
            errors.append("Full name is required.")
        if not email or "@" not in email:
            errors.append("A valid email address is required.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if User.query.filter_by(email=email).first():
            errors.append("An account with this email already exists.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/register.html", full_name=full_name, email=email)

        # Create user
        user = User(full_name=full_name, email=email)
        user.set_password(password)
        token = user.generate_activation_token(
            expiry_hours=current_app.config["ACTIVATION_TOKEN_EXPIRY_HOURS"]
        )
        db.session.add(user)
        db.session.commit()

        # Send activation email
        _send_activation_email(user, token)
        AuditLog.write("USER_REGISTERED", f"New user registered: {email}")
        flash("Account created! Please check your email to activate your account.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


# ── Activate ──────────────────────────────────────────────────────────────────
@auth_bp.route("/activate/<token>")
def activate(token):
    user = User.query.filter_by(activation_token=token).first()
    if not user:
        flash("Invalid activation link.", "danger")
        return redirect(url_for("auth.login"))
    if not user.is_token_valid(token):
        flash("Activation link has expired. Please register again.", "danger")
        return redirect(url_for("auth.register"))

    user.account_status   = "active"
    user.activation_token = None
    user.token_expiry     = None
    db.session.commit()
    AuditLog.write("ACCOUNT_ACTIVATED", f"Account activated: {user.email}")
    flash("Account activated! You can now log in.", "success")
    return redirect(url_for("auth.login"))


# ── Login ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("email.inbox"))

    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors   = []

        if not email:
            errors.append("Email is required.")
        if not password:
            errors.append("Password is required.")

        if not errors:
            user = User.query.filter_by(email=email).first()
            if not user:
                flash("Invalid email or password.", "danger")
                return render_template("auth/login.html", email=email)

            if user.is_locked():
                flash("Account is temporarily locked due to too many failed attempts. Try again in 15 minutes.", "warning")
                return render_template("auth/login.html", email=email)

            if user.account_status == "inactive":
                flash("Please activate your account via the email we sent you.", "warning")
                return render_template("auth/login.html", email=email)

            if not user.check_password(password):
                user.increment_failed_attempts()
                db.session.commit()
                attempts_left = 5 - user.failed_attempts
                if attempts_left > 0:
                    flash(f"Invalid email or password. {attempts_left} attempt(s) remaining.", "danger")
                else:
                    flash("Too many failed attempts. Account locked for 15 minutes.", "danger")
                return render_template("auth/login.html", email=email)

            # Success
            user.reset_failed_attempts()
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            AuditLog.write("USER_LOGIN", f"Login: {email}", actor_id=user.user_id, ip=request.remote_addr)

            if user.is_admin:
                return redirect(url_for("admin.dashboard"))
            return redirect(url_for("email.inbox"))

        for e in errors:
            flash(e, "danger")

    return render_template("auth/login.html")


# ── Forgot password ───────────────────────────────────────────────────────────
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("email.inbox"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if email:
            user = User.query.filter_by(email=email).first()
            if user and user.account_status == "active":
                token = user.generate_reset_token(
                    expiry_minutes=current_app.config["RESET_TOKEN_EXPIRY_MINUTES"]
                )
                db.session.commit()
                _send_reset_email(user, token)
                AuditLog.write("PASSWORD_RESET_REQUESTED", f"Password reset requested: {email}")

        # Same message whether or not the account exists, so we don't leak
        # which emails are registered.
        flash("If an account exists for that email, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


# ── Reset password ────────────────────────────────────────────────────────────
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("email.inbox"))

    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.is_reset_token_valid(token):
        flash("This password reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit.")
        if password != confirm_password:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/reset_password.html", token=token)

        user.set_password(password)
        user.clear_reset_token()
        user.reset_failed_attempts()
        db.session.commit()
        AuditLog.write("PASSWORD_RESET_COMPLETED", f"Password reset: {user.email}", actor_id=user.user_id)
        flash("Your password has been reset. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", token=token)


# ── Logout ────────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
@login_required
def logout():
    AuditLog.write("USER_LOGOUT", f"Logout: {current_user.email}", actor_id=current_user.user_id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ── Connect Gmail ─────────────────────────────────────────────────────────────
@auth_bp.route("/connect-email", methods=["GET", "POST"])
@login_required
def connect_email():
    if request.method == "POST":
        gmail_email = request.form.get("gmail_email", "").strip().lower()
        gmail_app_password = request.form.get("gmail_app_password", "").strip().replace(" ", "")
        errors = []

        if not gmail_email or "@" not in gmail_email:
            errors.append("A valid Gmail address is required.")
        if len(gmail_app_password) != 16 or not gmail_app_password.isalnum():
            errors.append("App Password must be the 16-character code Google generated (no spaces).")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/connect_email.html")

        current_user.gmail_email = gmail_email
        current_user.gmail_app_password = gmail_app_password
        db.session.commit()
        AuditLog.write("GMAIL_CONNECTED", f"Gmail connected: {gmail_email}", actor_id=current_user.user_id)
        flash("Your email is connected! New mail will start appearing within a minute.", "success")
        return redirect(url_for("auth.connect_email"))

    return render_template("auth/connect_email.html")


@auth_bp.route("/disconnect-email", methods=["POST"])
@login_required
def disconnect_email():
    current_user.gmail_email = None
    current_user.gmail_app_password = None
    db.session.commit()
    AuditLog.write("GMAIL_DISCONNECTED", "Gmail disconnected", actor_id=current_user.user_id)
    flash("Your email has been disconnected.", "info")
    return redirect(url_for("auth.connect_email"))


# ── Helper ────────────────────────────────────────────────────────────────────
def _send_activation_email(user: User, token: str):
    try:
        link = url_for("auth.activate", token=token, _external=True)
        msg = Message(
            subject="Activate your PhishGuard account",
            recipients=[user.email],
        )
        msg.html = f"""
        <h2>Welcome to PhishGuard, {user.full_name}!</h2>
        <p>Click the button below to activate your account:</p>
        <a href="{link}" style="display:inline-block;padding:12px 24px;background:#1d4ed8;
           color:#fff;border-radius:6px;text-decoration:none;font-weight:bold;">
           Activate Account
        </a>
        <p>This link expires in 24 hours.</p>
        <p>If you did not register, ignore this email.</p>
        """
        mail.send(msg)
    except Exception as ex:
        current_app.logger.error(f"Failed to send activation email: {ex}")


def _send_reset_email(user: User, token: str):
    try:
        link = url_for("auth.reset_password", token=token, _external=True)
        expiry_minutes = current_app.config["RESET_TOKEN_EXPIRY_MINUTES"]
        msg = Message(
            subject="Reset your PhishGuard password",
            recipients=[user.email],
        )
        msg.html = f"""
        <h2>Reset your password</h2>
        <p>Hi {user.full_name}, we received a request to reset your PhishGuard password.</p>
        <a href="{link}" style="display:inline-block;padding:12px 24px;background:#1d4ed8;
           color:#fff;border-radius:6px;text-decoration:none;font-weight:bold;">
           Reset Password
        </a>
        <p>This link expires in {expiry_minutes} minutes.</p>
        <p>If you did not request this, you can safely ignore this email — your password will not change.</p>
        """
        mail.send(msg)
    except Exception as ex:
        current_app.logger.error(f"Failed to send password reset email: {ex}")