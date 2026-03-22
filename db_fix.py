import os
import smtplib
from email.message import EmailMessage
from sql_queries import supabase, get_setting

def unlock_all():
    print("Unlocking all employees and resetting failed attempts to 0...")
    try:
        supabase.table("employees").update({
            "status": "Active",
            "failed_attempts": 0
        }).neq("status", "DOES_NOT_EXIST").execute() # dummy condition to update all
        print("Success! All accounts unlocked.")
    except Exception as e:
        # alternative to update all without condition:
        res = supabase.table("employees").select("id").execute()
        for emp in res.data:
            supabase.table("employees").update({
                "status": "Active",
                "failed_attempts": 0
            }).eq("id", emp["id"]).execute()
        print("Success! Iterated and unlocked all accounts.")

def test_email_with_settings():
    sender_email    = get_setting("sender_email", "ivybarchebo40@gmail.com")
    sender_password = get_setting("sender_password", "oqcfpzwewjccjtgt")
    admin_email     = get_setting("admin_email", "ivybarchebo40@gmail.com")
    
    print(f"Testing SMTP with Sender: {sender_email}, Admin: {admin_email}")
    msg = EmailMessage()
    msg['Subject'] = "Direct Email Test"
    msg['From']    = sender_email
    msg['To']      = admin_email
    msg.set_content("This is a direct script test to verify if the Google App Password is valid right now.")
    
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, sender_password)
            smtp.send_message(msg)
            print("EMAIL TEST SUCCESS! The password works perfectly!")
    except Exception as e:
        print(f"EMAIL TEST FAILED! Error: {e}")

if __name__ == "__main__":
    unlock_all()
    test_email_with_settings()
