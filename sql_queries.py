"""
sql_queries.py
==============
All Supabase database query helpers for the Employee Intrusion Detection System.
Import this module in app.py instead of writing inline queries.
"""

from database import supabase
from datetime import datetime
from typing import Optional
import uuid

# ─────────────────────────────────────────────
#  Company & SaaS Queries
# ─────────────────────────────────────────────

def get_company_by_api_key(api_key: str):
    res = supabase.table("companies").select("*").eq("api_key", api_key).execute()
    return res.data[0] if res.data else None

def get_company_by_email(email: str):
    res = supabase.table("companies").select("*").eq("contact_email", email).execute()
    return res.data[0] if res.data else None

def get_company_settings(company_id: str):
    res = supabase.table("company_settings").select("*").eq("company_id", company_id).execute()
    return res.data[0] if res.data else None

def get_all_companies():
    """SuperAdmin only: Get all registered companies."""
    res = supabase.table("companies").select("*").order("created_at", desc=True).execute()
    return res.data or []

def create_company(name: str, contact_email: Optional[str] = None, password_hash: Optional[str] = None):
    """SuperAdmin only: Register a new company and generate their API key."""
    import secrets
    import string
    
    # Generate a secure 'sk_live_' prefix random key (32 chars)
    alphabet = string.ascii_letters + string.digits
    rand_str = ''.join(secrets.choice(alphabet) for _ in range(32))
    api_key = f"sk_live_{rand_str}"
    
    company_id = str(uuid.uuid4())
    data = {
        "id": company_id,
        "name": name,
        "api_key": api_key,
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }
    if contact_email:
        data["contact_email"] = contact_email
    if password_hash:
        data["password_hash"] = password_hash

    supabase.table("companies").insert(data).execute()
    
    # Create default company settings
    settings_data = {
        "company_id": company_id,
        "working_hours_start": "05:00:00",
        "working_hours_end": "23:00:00",
        "max_failed_attempts": 3,
        "lockout_duration_minutes": 30
    }
    supabase.table("company_settings").insert(settings_data).execute()
    
    # Auto-provision a demo employee so the integration sandbox works out-of-the-box
    try:
        import re
        import bcrypt
        clean_name = re.sub(r'[^a-zA-Z0-9]', '', name).lower() or "demo"
        demo_email = f"demo@{clean_name}.com"
        demo_username = f"demo_{clean_name}"
        hashed = bcrypt.hashpw("demo123".encode(), bcrypt.gensalt()).decode()
        
        demo_user_id = str(uuid.uuid4())
        demo_data = {
            "id": demo_user_id,
            "company_id": company_id,
            "name": f"{name} Demo Account",
            "email": demo_email,
            "employee_number": f"DEMO-{company_id[:4].upper()}",
            "username": demo_username,
            "password": hashed,
            "role": "Employee",
            "status": "Active",
            "failed_attempts": 0,
            "created_at": datetime.utcnow().isoformat()
        }
        supabase.table("employees").insert(demo_data).execute()
    except Exception as e:
        print(f"[WARN] Could not auto-provision demo employee for company {name}: {e}")

    return data
def get_company_by_id(company_id: str):
    """Get a single company by its UUID."""
    res = supabase.table("companies").select("*").eq("id", company_id).execute()
    return res.data[0] if res.data else None

def delete_company(company_id: str):
    """Admin only: Delete a company and its settings."""
    try:
        supabase.table("company_settings").delete().eq("company_id", company_id).execute()
    except Exception:
        pass
    supabase.table("companies").delete().eq("id", company_id).execute()

def regenerate_company_api_key(company_id: str) -> str:
    """Admin only: Generate a new API key for an existing company."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    rand_str = ''.join(secrets.choice(alphabet) for _ in range(32))
    new_key = f"sk_live_{rand_str}"
    supabase.table("companies").update({"api_key": new_key}).eq("id", company_id).execute()
    return new_key

def update_company_failed_attempts(company_id: str, attempts: int):
    supabase.table("companies").update({"failed_attempts": attempts}).eq("id", company_id).execute()

def lock_company(company_id: str):
    supabase.table("companies").update({"status": "Locked"}).eq("id", company_id).execute()

def reset_company_failed_attempts(company_id: str, ip_address=None):
    now = datetime.utcnow().isoformat()
    try:
        supabase.table("companies").update({
            "failed_attempts": 0,
            "last_login": now,
            "last_ip_address": ip_address
        }).eq("id", company_id).execute()
    except Exception:
        pass

def update_company_password(company_id: str, password_hash: str):
    supabase.table("companies").update({"password_hash": password_hash}).eq("id", company_id).execute()

def update_company_hours(company_id: str, working_hours_start: str, working_hours_end: str):
    """Admin only: Update specific company's working hours."""
    data = {
        "working_hours_start": working_hours_start,
        "working_hours_end": working_hours_end
    }
    supabase.table("company_settings").update(data).eq("company_id", company_id).execute()

# ─────────────────────────────────────────────
#  Profile Queries
# ─────────────────────────────────────────────

def get_employee_by_username(username: str):
    res = supabase.table("employees").select("*").eq("username", username).execute()
    return res.data[0] if res.data else None

def get_employee_by_email(email: str):
    res = supabase.table("employees").select("*").eq("email", email).execute()
    return res.data[0] if res.data else None

def get_user_by_email_or_username(identifier: str):
    # Try username match first
    res = supabase.table("employees").select("*").eq("username", identifier).execute()
    if res.data: return res.data[0]
    
    # Try email match
    res = supabase.table("employees").select("*").eq("email", identifier).execute()
    if res.data: return res.data[0]
    
    # Try employee_number match
    res = supabase.table("employees").select("*").eq("employee_number", identifier).execute()
    return res.data[0] if res.data else None


def get_employee_by_id(user_id: str):
    res = supabase.table("employees").select("*").eq("id", user_id).execute()
    return res.data[0] if res.data else None

def get_all_employees(company_id: str = "00000000-0000-0000-0000-000000000000"):
    """Return list of all employee profile dicts for a given company."""
    res = supabase.table("employees").select("*").eq("role", "Employee").eq("company_id", company_id).execute()
    return res.data or []

def employee_username_exists(username: str) -> bool:
    res = supabase.table("employees").select("id").eq("username", username).execute()
    return bool(res.data)

def employee_number_exists(employee_number: str) -> bool:
    res = supabase.table("employees").select("id").eq("employee_number", employee_number).execute()
    return bool(res.data)

def update_failed_attempts(user_id: str, attempts: int):
    supabase.table("employees").update({"failed_attempts": attempts}).eq("id", user_id).execute()

def reset_failed_attempts(user_id: str, ip_address=None):
    now = datetime.utcnow().isoformat()
    try:
        supabase.table("employees").update({
            "failed_attempts": 0,
            "last_login": now,
            "last_ip_address": ip_address
        }).eq("id", user_id).execute()
        return
    except Exception:
        pass
    try:
        supabase.table("employees").update({"failed_attempts": 0, "last_login": now}).eq("id", user_id).execute()
        return
    except Exception:
        pass
    try:
        supabase.table("employees").update({"failed_attempts": 0}).eq("id", user_id).execute()
    except Exception as e:
        print(f"[DB ERROR] Critical failure in reset_failed_attempts: {e}")

def lock_employee(user_id: str):
    supabase.table("employees").update({"status": "Locked"}).eq("id", user_id).execute()

def unlock_employee(user_id: str):
    supabase.table("employees").update({
        "status": "Active",
        "failed_attempts": 0,
    }).eq("id", user_id).execute()

def update_employee_after_hours(user_id: str, allow: bool):
    """Admin only: Toggle whether an employee can bypass the suspicious hours check."""
    # Since allow is boolean, we update it in the employees table
    supabase.table("employees").update({"allow_after_hours": allow}).eq("id", user_id).execute()

def get_employee_username_by_id(user_id: str):
    res = supabase.table("employees").select("username").eq("id", user_id).execute()
    return res.data[0]["username"] if res.data else None

def create_employee(name, email, employee_number, username, password_hash, role="Employee", company_id="00000000-0000-0000-0000-000000000000"):
    user_id = str(uuid.uuid4())
    data = {
        "id": user_id,
        "company_id": company_id,
        "name": name,
        "email": email,
        "employee_number": employee_number,
        "username": username,
        "password": password_hash,
        "role": role,
        "status": "Active",
        "failed_attempts": 0,
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.table("employees").insert(data).execute()

def update_employee_password(user_id: str, hashed_password: str):
    supabase.table("employees").update({"password": hashed_password}).eq("id", user_id).execute()

def delete_employee(user_id: str):
    supabase.table("employees").delete().eq("id", user_id).execute()

def get_employee_by_email_only(email: str):
    res = supabase.table("employees").select("*").eq("email", email).execute()
    return res.data[0] if res.data else None

# ─────────────────────────────────────────────
#  Password Reset Token Queries
# ─────────────────────────────────────────────

def create_password_reset_token(user_id: str, token: str, expires_at: str):
    try:
        supabase.table("password_reset_tokens").delete().eq("user_id", user_id).execute()
    except Exception:
        pass
    data = {"user_id": user_id, "token": token, "expires_at": expires_at}
    supabase.table("password_reset_tokens").insert(data).execute()

def get_password_reset_token(token: str):
    try:
        res = supabase.table("password_reset_tokens").select("*").eq("token", token).execute()
        return res.data[0] if res.data else None
    except Exception:
        return None

def delete_password_reset_token(token: str):
    try:
        supabase.table("password_reset_tokens").delete().eq("token", token).execute()
    except Exception:
        pass

# ─────────────────────────────────────────────
#  Admin Queries
# ─────────────────────────────────────────────

def get_admin_by_username(username: str):
    res = supabase.table("employees").select("*").eq("username", username).eq("role", "Admin").execute()
    return res.data[0] if res.data else None

def admin_exists() -> bool:
    res = supabase.table("employees").select("id").eq("role", "SuperAdmin").limit(1).execute()
    return bool(res.data)

def create_admin(username, password_hash):
    user_id = str(uuid.uuid4())
    data = {
        "id": user_id,
        "company_id": None,
        "username": username,
        "email": f"{username}@system.local",
        "password": password_hash,
        "role": "SuperAdmin",
        "status": "Active",
        "created_at": datetime.utcnow().isoformat()
    }
    supabase.table("employees").insert(data).execute()

# ─────────────────────────────────────────────
#  Intrusion Log Queries
# ─────────────────────────────────────────────

def log_intrusion(username: str, reason: str, ip_address=None, device_info=None, company_id=None):
    data = {"username": username, "reason": reason}
    if company_id: data["company_id"] = company_id
    if ip_address: data["ip_address"] = ip_address
    if device_info: data["device_info"] = device_info
    
    try:
        supabase.table("intrusion_logs").insert(data).execute()
    except Exception:
        fallback_data = {"username": username, "reason": reason}
        if company_id: fallback_data["company_id"] = company_id
        supabase.table("intrusion_logs").insert(fallback_data).execute()

def get_recent_intrusion_logs(limit: int = 50, company_id=None):
    try:
        query = supabase.table("intrusion_logs").select("*").order("timestamp", desc=True).limit(limit)
        if company_id:
            query = query.eq("company_id", company_id)
        res = query.execute()
        return res.data or []
    except Exception:
        return []

def log_audit_action(admin_username: str, action: str, target: str, ip_address=None, company_id=None):
    data = {
        "admin_username": admin_username,
        "action": action,
        "target": target,
        "ip_address": ip_address
    }
    if company_id: data["company_id"] = company_id
    try:
        supabase.table("audit_logs").insert(data).execute()
    except Exception:
        fallback_data = {"admin_username": admin_username, "action": action, "target": target}
        if company_id: fallback_data["company_id"] = company_id
        supabase.table("audit_logs").insert(fallback_data).execute()

def get_recent_audit_logs(limit: int = 50, company_id=None):
    try:
        query = supabase.table("audit_logs").select("*").order("timestamp", desc=True).limit(limit)
        if company_id:
            query = query.eq("company_id", company_id)
        res = query.execute()
        return res.data or []
    except Exception:
        return []

# ─────────────────────────────────────────────
#  System Settings Queries
# ─────────────────────────────────────────────

def get_setting(key: str, default: str = "") -> str:
    try:
        res = supabase.table("system_settings").select("value").eq("key", key).execute()
        if res.data:
            return res.data[0]["value"]
    except Exception:
        pass
    return default

def update_setting(key: str, value: str):
    res = supabase.table("system_settings").select("id").eq("key", key).execute()
    if res.data:
        supabase.table("system_settings").update({"value": value}).eq("key", key).execute()
    else:
        supabase.table("system_settings").insert({"key": key, "value": value}).execute()

def get_system_settings() -> dict:
    return {
        "admin_email": get_setting("admin_email", "ivybarchebo40@gmail.com"),
        "sender_email": get_setting("sender_email", "ivybarchebo40@gmail.com"),
        "sender_password": get_setting("sender_password", "oqcfpzwewjccjtgt"),
    }

def update_system_settings(admin_email: str, sender_email: str, sender_password=None):
    if admin_email: update_setting("admin_email", admin_email)
    if sender_email: update_setting("sender_email", sender_email)
    if sender_password is not None: update_setting("sender_password", sender_password)

