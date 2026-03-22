import smtplib
from email.message import EmailMessage
from datetime import datetime
from sql_queries import get_setting


def send_alert(message: str, subject: str = None):
    """
    Sends an email alert to the admin.
    
    Args:
        message: The body text of the alert email.
        subject: Optional subject line. Defaults to a generic intrusion alert.
    
    Uses settings stored in the database (system_settings table).
    Configured via the Admin Dashboard → Settings.
    Falls back to hardcoded defaults if DB is unavailable.
    """
    sender_email    = get_setting("sender_email", "ivybarchebo40@gmail.com")
    sender_password = get_setting("sender_password", "oqcfpzwewjccjtgt")
    admin_email     = get_setting("admin_email", "ivybarchebo40@gmail.com")

    if not sender_email or not sender_password or not admin_email:
        print("[ERROR] Email settings not configured in database.")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    email_subject = subject or "🚨 Security Alert — Employee Intrusion Detection System"

    msg = EmailMessage()
    msg['Subject'] = email_subject
    msg['From']    = sender_email
    msg['To']      = admin_email
    msg.set_content(
        f"{'='*50}\n"
        f"  SECURITY ALERT — {now}\n"
        f"{'='*50}\n\n"
        f"{message}\n\n"
        f"{'='*50}\n"
        f"Please log in to the admin dashboard to review:\n"
        f"{__import__('os').environ.get('APP_URL', 'http://localhost:5000')}/admin/dashboard\n"
    )

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
            print(f"[EMAIL] Alert sent to {admin_email} | Subject: {email_subject}")
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send alert: {e}")



def send_intrusion_alert(username: str, reason: str, ip_address: str = None):
    """
    Convenience wrapper for intrusion-specific alerts.
    Formats a structured intrusion message and calls send_alert.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"⚠️  INTRUSION / SECURITY EVENT DETECTED",
        f"",
        f"  Employee : {username}",
        f"  Reason   : {reason}",
        f"  Time     : {now}",
    ]
    if ip_address:
        lines.append(f"  IP Addr  : {ip_address}")
    lines.append(f"")
    lines.append("Action taken: Account has been LOCKED automatically.")
    lines.append("Please review the intrusion log in the admin dashboard.")

    send_alert(
        message="\n".join(lines),
        subject=f"🚨 Account Locked: {username} — {reason[:50]}"
    )