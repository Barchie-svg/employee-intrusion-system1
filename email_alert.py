import smtplib
from email.message import EmailMessage
from config import SENDER_EMAIL, SENDER_PASSWORD, ADMIN_EMAIL
from datetime import datetime

def send_alert(username, reason):
    """
    Sends an email alert to the admin when an intrusion is detected.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    msg = EmailMessage()
    msg['Subject'] = f'🚨 Intrusion Alert: {username}'
    msg['From'] = SENDER_EMAIL
    msg['To'] = ADMIN_EMAIL
    msg.set_content(
        f"⚠️  INTRUSION DETECTED\n"
        f"{'='*40}\n"
        f"Employee : {username}\n"
        f"Reason   : {reason}\n"
        f"Time     : {now}\n"
        f"{'='*40}\n\n"
        f"Please log in to the admin dashboard immediately to review and take action.\n"
        f"http://127.0.0.1:5000/admin/login\n"
    )

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
            print(f"[INFO] Alert email sent for {username}")
    except Exception as e:
        print(f"[ERROR] Failed to send alert email: {e}")