import sys
from email_alert import send_alert, send_intrusion_alert

try:
    print("Testing send_alert...")
    send_alert("Test message from python", "Test Subject")
    print("send_alert finished.")
except Exception as e:
    print(f"Exception in send_alert: {e}", file=sys.stderr)

try:
    print("\nTesting send_intrusion_alert...")
    send_intrusion_alert("testuser", "test reason", "127.0.0.1")
    print("send_intrusion_alert finished.")
except Exception as e:
    print(f"Exception in send_intrusion_alert: {e}", file=sys.stderr)
