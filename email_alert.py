import os
import requests
from datetime import datetime

from sql_queries import get_setting


def _get_config():
    """Resolve email config: env vars take priority over DB settings."""
    sender_email = os.environ.get("SENDER_EMAIL") or get_setting("sender_email", "ivybarchebo40@gmail.com")
    admin_email  = os.environ.get("ADMIN_EMAIL")  or get_setting("admin_email",  "ivybarchebo40@gmail.com")
    brevo_key    = os.environ.get("BREVO_API_KEY") or get_setting("brevo_api_key", "")
    return sender_email, admin_email, brevo_key


def send_alert(message: str, subject: str = None, to_email: str = None) -> bool:
    """
    Send an email alert via Brevo HTTP API (works on Render free tier).
    Returns True if successful, False otherwise.
    """
    sender_email, admin_email, brevo_key = _get_config()
    recipient     = to_email or admin_email
    email_subject = subject or "🚨 Security Alert — Employee Intrusion Detection System"

    if not brevo_key:
        print("[EMAIL ERROR] BREVO_API_KEY is not set. Cannot send email.")
        return False

    if not sender_email or not recipient:
        print("[EMAIL ERROR] Missing sender or recipient email.")
        return False

    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = (
        f"{'='*50}\n"
        f"  EMPLOYEE INTRUSION SYSTEM — {now}\n"
        f"{'='*50}\n\n"
        f"{message}\n\n"
        f"Admin Dashboard:\n"
        f"{os.environ.get('APP_URL', 'https://your-app.onrender.com')}/admin/dashboard\n"
    )

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": brevo_key,
                "content-type": "application/json"
            },
            json={
                "sender":      {"name": "Employee IDS", "email": sender_email},
                "to":          [{"email": recipient}],
                "subject":     email_subject,
                "textContent": body
            },
            timeout=15
        )

        if response.status_code in (200, 201):
            print(f"[EMAIL SUCCESS] Sent to {recipient} | Subject: {email_subject}")
            return True
        else:
            print(f"[EMAIL ERROR] Brevo returned {response.status_code}: {response.text}")
            return False

    except Exception as e:
        print(f"[EMAIL ERROR] Unexpected error sending email: {e}")
        return False


def send_intrusion_alert(username: str, reason: str, ip_address: str = None):
    """
    Convenience wrapper for intrusion-specific alerts sent to the admin.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "⚠️  INTRUSION / SECURITY EVENT DETECTED",
        "",
        f"  Employee : {username}",
        f"  Reason   : {reason}",
        f"  Time     : {now}",
    ]
    if ip_address:
        lines.append(f"  IP Addr  : {ip_address}")
    lines.append("")
    lines.append("Action taken: Account has been LOCKED automatically.")
    lines.append("Please review the intrusion log in the admin dashboard.")

    send_alert(
        message="\n".join(lines),
        subject=f"🚨 Account Locked: {username} — {reason[:50]}"
    )