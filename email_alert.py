import smtplib
import os
from email.message import EmailMessage
from datetime import datetime
from sql_queries import get_setting


def _build_message(sender_email: str, to_email: str, subject: str, body: str) -> EmailMessage:
    """Construct an EmailMessage object."""
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From']    = sender_email
    msg['To']      = to_email
    msg.set_content(body)
    return msg


def _do_send(msg: EmailMessage, sender_email: str, sender_password: str):
    """
    Send the message synchronously via Gmail SMTP TLS (port 587).
    Raises on failure so callers can handle it.
    """
    with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()
        smtp.login(sender_email, sender_password)
        smtp.send_message(msg)
        print(f"[EMAIL] Sent to {msg['To']} | Subject: {msg['Subject']}")


def send_alert(message: str, subject: str = None, to_email: str = None):
    """
    Send an email alert.

    Args:
        message:  Body text of the email.
        subject:  Subject line (defaults to generic security alert).
        to_email: Recipient address. Defaults to the admin_email in settings.
                  Pass the employee's email here for OTP / password-reset emails.
    """
    sender_email    = get_setting("sender_email",    "ivybarchebo40@gmail.com")
    sender_password = get_setting("sender_password", "oqcfpzwewjccjtgt")
    admin_email     = get_setting("admin_email",     "ivybarchebo40@gmail.com")

    recipient   = to_email or admin_email   # <-- use caller-supplied address first
    email_subject = subject or "🚨 Security Alert — Employee Intrusion Detection System"

    if not sender_email or not sender_password or not recipient:
        print("[EMAIL ERROR] Email settings not configured. Cannot send.")
        return

    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = (
        f"{'='*50}\n"
        f"  EMPLOYEE INTRUSION SYSTEM — {now}\n"
        f"{'='*50}\n\n"
        f"{message}\n\n"
        f"{'='*50}\n"
        f"Admin Dashboard:\n"
        f"{os.environ.get('APP_URL', 'http://localhost:5000')}/admin/dashboard\n"
    )

    msg = _build_message(sender_email, recipient, email_subject, body)

    # ── Send SYNCHRONOUSLY ──────────────────────────────────────────────────
    # On Render (and similar PaaS), background threads are killed when the
    # HTTP response is sent, so async email delivery silently fails.
    # Synchronous sending guarantees the email is dispatched before we return.
    try:
        _do_send(msg, sender_email, sender_password)
    except smtplib.SMTPAuthenticationError:
        print(
            "[EMAIL ERROR] Gmail authentication failed.\n"
            "  → Make sure 2-Step Verification is ON for the sender account.\n"
            "  → Use a Gmail App Password (not your normal password).\n"
            "  → Update the password in Admin Dashboard → Settings."
        )
    except smtplib.SMTPConnectError as e:
        print(f"[EMAIL ERROR] Cannot connect to smtp.gmail.com:587 — {e}")
    except smtplib.SMTPException as e:
        print(f"[EMAIL ERROR] SMTP error: {e}")
    except Exception as e:
        print(f"[EMAIL ERROR] Unexpected error sending email: {e}")


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
        # no to_email → goes to admin by default
    )