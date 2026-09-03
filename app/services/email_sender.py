"""
Quarantine Digest Email Service
Project requirement:
"A user-facing quarantine digest email that clearly explains
why an email was flagged (e.g., This email creates false urgency
and contains a mismatched link.)"
"""
import logging
from datetime import datetime
from flask import render_template_string, url_for
from flask_mail import Message
from app import mail

logger = logging.getLogger(__name__)

DIGEST_HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
    background:#f3f4f6; color:#111827; padding:24px;
  }
  .container {
    max-width:620px; margin:0 auto; background:#fff;
    border-radius:12px; overflow:hidden;
    box-shadow:0 4px 20px rgba(0,0,0,.08);
  }
  /* Header */
  .header {
    background:linear-gradient(135deg, #1b2a4a 0%, #1d4ed8 100%);
    padding:28px 32px; text-align:center;
  }
  .header-icon { font-size:40px; margin-bottom:8px; }
  .header-title {
    color:#fff; font-size:22px; font-weight:800; margin-bottom:4px;
  }
  .header-sub { color:#bfdbfe; font-size:14px; }

  /* Summary bar */
  .summary {
    background:#f9fafb; border-bottom:1px solid #e5e7eb;
    padding:16px 32px; display:flex; gap:24px;
  }
  .summary-item { text-align:center; }
  .summary-num  { font-size:28px; font-weight:900; color:#dc2626; }
  .summary-label{ font-size:11px; color:#9ca3af; text-transform:uppercase;
    letter-spacing:.06em; font-weight:600; margin-top:2px; }

  /* Email cards */
  .cards { padding:20px 24px; }
  .card {
    border:1px solid #e5e7eb; border-radius:10px;
    margin-bottom:16px; overflow:hidden;
  }
  .card-header {
    padding:14px 18px; display:flex;
    justify-content:space-between; align-items:center;
  }
  .card-phishing  { background:#fef2f2; border-color:#fca5a5; }
  .card-suspicious{ background:#fffbeb; border-color:#fcd34d; }
  .card-label {
    font-size:11px; font-weight:800; letter-spacing:.06em;
    padding:3px 10px; border-radius:20px;
  }
  .label-phishing  { background:#dc2626; color:#fff; }
  .label-suspicious{ background:#f59e0b; color:#fff; }
  .card-score {
    font-size:20px; font-weight:900;
  }
  .score-red   { color:#dc2626; }
  .score-amber { color:#f59e0b; }

  .card-body { padding:14px 18px; background:#fff; }
  .email-subject {
    font-size:15px; font-weight:700; color:#111827;
    margin-bottom:4px;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  }
  .email-sender {
    font-size:12px; color:#9ca3af; margin-bottom:12px;
  }

  /* Explanation box */
  .explanation {
    background:#fef9ec; border:1px solid #fde68a;
    border-radius:8px; padding:12px 14px; margin-bottom:14px;
  }
  .explanation-label {
    font-size:10px; font-weight:800; color:#92400e;
    text-transform:uppercase; letter-spacing:.06em; margin-bottom:4px;
  }
  .explanation-text {
    font-size:13px; color:#78350f; line-height:1.5; font-weight:500;
  }

  /* Action buttons */
  .actions { display:flex; gap:10px; }
  .btn {
    display:inline-block; padding:9px 18px; border-radius:8px;
    text-decoration:none; font-size:13px; font-weight:700;
    text-align:center;
  }
  .btn-release { background:#dcfce7; color:#15803d; border:1px solid #bbf7d0; }
  .btn-delete  { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
  .btn-view    { background:#dbeafe; color:#1e40af; border:1px solid #bfdbfe; }

  /* Footer */
  .footer {
    text-align:center; padding:20px 32px;
    border-top:1px solid #e5e7eb;
    font-size:12px; color:#9ca3af;
  }
  .footer a { color:#1d4ed8; text-decoration:none; }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-icon">🛡️</div>
    <div class="header-title">PhishGuard Security Digest</div>
    <div class="header-sub">
      {{ date }} — Here is your quarantine summary
    </div>
  </div>

  <!-- Summary -->
  <div class="summary">
    <div class="summary-item">
      <div class="summary-num">{{ total }}</div>
      <div class="summary-label">Emails Quarantined</div>
    </div>
    <div class="summary-item">
      <div class="summary-num" style="color:#f59e0b;">{{ suspicious }}</div>
      <div class="summary-label">Suspicious</div>
    </div>
    <div class="summary-item">
      <div class="summary-num">{{ phishing }}</div>
      <div class="summary-label">Phishing</div>
    </div>
  </div>

  <!-- Email Cards -->
  <div class="cards">

    {% for item in items %}
    <div class="card card-{{ item.label }}">

      <!-- Card Header -->
      <div class="card-header">
        <div>
          <span class="card-label label-{{ item.label }}">
            {{ item.label|upper }}
          </span>
        </div>
        <div class="card-score {{ 'score-red' if item.risk_score >= 70 else 'score-amber' }}">
          {{ item.risk_score }}%
        </div>
      </div>

      <!-- Card Body -->
      <div class="card-body">
        <div class="email-subject">{{ item.subject }}</div>
        <div class="email-sender">From: {{ item.sender }}</div>

        <!-- WHY WAS IT FLAGGED (Project Requirement) -->
        <div class="explanation">
          <div class="explanation-label">⚠️ Why was this flagged?</div>
          <div class="explanation-text">{{ item.explanation }}</div>
        </div>

        <!-- Actions -->
        <div class="actions">
          <a href="{{ item.view_url }}" class="btn btn-view">👁 View Email</a>
          <a href="{{ item.release_url }}" class="btn btn-release">✓ Release</a>
          <a href="{{ item.delete_url }}"  class="btn btn-delete">✕ Delete</a>
        </div>
      </div>
    </div>
    {% endfor %}

    {% if overflow > 0 %}
    <div style="text-align:center;padding:12px;font-size:13px;color:#6b7280;">
      And <strong>{{ overflow }}</strong> more —
      <a href="{{ dashboard_url }}" style="color:#1d4ed8;">
        view all in dashboard →
      </a>
    </div>
    {% endif %}

  </div>

  <!-- Footer -->
  <div class="footer">
    <p>
      <strong>PhishGuard</strong> — AI-Powered Phishing Detection
    </p>
    <p style="margin-top:6px;">
      <a href="{{ dashboard_url }}">View Dashboard</a> ·
      <a href="{{ settings_url }}">Manage Notifications</a>
    </p>
    <p style="margin-top:8px;font-size:11px;">
      You can mark any email as Safe or Phishing to help improve
      detection accuracy over time.
    </p>
  </div>

</div>
</body>
</html>
"""


def send_digest(user, quarantine_items: list, base_url: str):
    """
    Send quarantine digest email with clear explanations.
    Project requirement: "clearly explains why an email was flagged
    e.g., This email creates false urgency and contains a mismatched link."
    """
    MAX_PER_DIGEST = 20
    display_items  = quarantine_items[:MAX_PER_DIGEST]
    overflow       = max(0, len(quarantine_items) - MAX_PER_DIGEST)

    phishing_count   = sum(1 for qi in quarantine_items
                           if qi.email.classification and
                           qi.email.classification.label == "phishing")
    suspicious_count = len(quarantine_items) - phishing_count

    template_items = []
    for qi in display_items:
        em  = qi.email
        clf = em.classification
        template_items.append({
            "subject":     em.subject or "(No Subject)",
            "sender":      em.sender_email,
            "label":       clf.label if clf else "phishing",
            "risk_score":  round(clf.risk_score) if clf else 100,
            "explanation": clf.explanation_text if clf and clf.explanation_text
                           else "This email was flagged based on multiple suspicious indicators.",
            "view_url":    f"{base_url}/email/view/{em.email_id}",
            "release_url": f"{base_url}/quarantine/release/{qi.quarantine_id}?token={qi.action_token}",
            "delete_url":  f"{base_url}/quarantine/delete/{qi.quarantine_id}?token={qi.action_token}",
        })

    html_body = render_template_string(
        DIGEST_HTML,
        date          = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC"),
        total         = len(quarantine_items),
        phishing      = phishing_count,
        suspicious    = suspicious_count,
        items         = template_items,
        overflow      = overflow,
        dashboard_url = f"{base_url}/quarantine",
        settings_url  = f"{base_url}/auth/settings",
    )

    try:
        msg = Message(
            subject    = f"🛡️ PhishGuard: {len(quarantine_items)} email(s) quarantined",
            recipients = [user.email],
            html       = html_body,
        )
        mail.send(msg)
        logger.info(f"Digest sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send digest to {user.email}: {e}")
        return False


def send_immediate_alert(user, email_record, classification, base_url: str):
    """
    Send immediate alert when a phishing email is detected.
    Sent instantly — no need to wait for daily digest.
    """
    explanation = (
        classification.explanation_text
        if classification and classification.explanation_text
        else "This email was flagged as suspicious."
    )

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family:Arial,sans-serif;background:#f3f4f6;padding:24px;">
    <div style="max-width:560px;margin:0 auto;background:#fff;
         border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.08);">

      <div style="background:#dc2626;padding:20px 24px;text-align:center;">
        <div style="font-size:32px;">🚨</div>
        <div style="color:#fff;font-size:18px;font-weight:800;margin-top:8px;">
          Phishing Email Detected!
        </div>
      </div>

      <div style="padding:24px;">
        <table style="font-size:13px;color:#374151;width:100%;border-collapse:collapse;">
          <tr>
            <td style="padding:6px 0;color:#9ca3af;font-weight:600;width:80px;">From</td>
            <td style="padding:6px 0;">{email_record.sender_email}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#9ca3af;font-weight:600;">Subject</td>
            <td style="padding:6px 0;font-weight:700;">{email_record.subject or '(No Subject)'}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#9ca3af;font-weight:600;">Risk Score</td>
            <td style="padding:6px 0;font-weight:900;color:#dc2626;font-size:18px;">
              {round(classification.risk_score) if classification else '?'}%
            </td>
          </tr>
        </table>

        <div style="background:#fef9ec;border:1px solid #fde68a;border-radius:8px;
             padding:14px;margin:16px 0;">
          <div style="font-size:10px;font-weight:800;color:#92400e;
               text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px;">
            ⚠️ Why was this flagged?
          </div>
          <div style="font-size:14px;color:#78350f;font-weight:500;line-height:1.6;">
            {explanation}
          </div>
        </div>

        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          <a href="{base_url}/email/view/{email_record.email_id}"
             style="display:inline-block;padding:10px 20px;background:#dbeafe;
             color:#1e40af;border-radius:8px;text-decoration:none;
             font-weight:700;font-size:13px;">👁 View Email</a>
          <a href="{base_url}/quarantine"
             style="display:inline-block;padding:10px 20px;background:#f3f4f6;
             color:#374151;border-radius:8px;text-decoration:none;
             font-weight:700;font-size:13px;">🔒 View Quarantine</a>
        </div>
      </div>

      <div style="text-align:center;padding:16px;border-top:1px solid #e5e7eb;
           font-size:12px;color:#9ca3af;">
        PhishGuard — AI-Powered Phishing Detection
      </div>
    </div>
    </body>
    </html>
    """

    try:
        msg = Message(
            subject    = f"🚨 PhishGuard Alert: Phishing email quarantined!",
            recipients = [user.email],
            html       = html,
        )
        mail.send(msg)
        logger.info(f"Immediate alert sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Alert send failed: {e}")
        return False
