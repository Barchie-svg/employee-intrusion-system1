from dotenv import load_dotenv
load_dotenv()  # loads .env file for local dev (ignored on Render where env vars are set directly)

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_session import Session
import bcrypt
import re
import random
from datetime import datetime, timedelta, timezone
from config import SECRET_KEY
from intrusion import is_suspicious_time
from email_alert import send_alert, send_intrusion_alert
from types import SimpleNamespace

# from intrusion import is_suspicious_time # This was changed to os_suspicious_time in the instruction, but the original code uses 'intrusion'. I will keep 'intrusion' as it's not explicitly removed, only 'os_suspicious_time' was added in the diff, which is not in the original code.
# from datetime import datetime # Redundant, already imported with timedelta
# from types import SimpleNamespace # Already imported
# import bcrypt # Already imported

from sql_queries import (
    # Employee
    get_user_by_email_or_username,
    get_employee_by_username, get_employee_by_id, get_all_employees,
    get_employee_username_by_id, get_employee_by_email_only,
    employee_username_exists, employee_number_exists, create_employee,
    update_failed_attempts, reset_failed_attempts,
    lock_employee, unlock_employee, delete_employee,
    update_employee_password,
    # Password Reset Tokens
    create_password_reset_token, get_password_reset_token, delete_password_reset_token,
    # Admin
    get_admin_by_username, admin_exists, create_admin,
    # Logs
    log_intrusion, get_recent_intrusion_logs,
    log_audit_action, get_recent_audit_logs,
    # Settings
    get_setting, update_setting, get_system_settings, update_system_settings,
    # SaaS Companies
    get_all_companies, create_company, get_company_by_id,
    delete_company, regenerate_company_api_key
)

# ─────────────────────────────────────────────
#  Flask Setup
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
Session(app)


# ─────────────────────────────────────────────
#  Utilities — convert Supabase dicts → objects
#  so Jinja2 templates work unchanged (emp.name etc.)
# ─────────────────────────────────────────────
def _parse_ts(val):
    """Convert an ISO timestamp string from Supabase to a datetime object."""
    if not val:
        return None
    if isinstance(val, datetime):
        return val
    try:
        return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def to_emp(d):
    obj = SimpleNamespace(**d)
    obj.last_login = _parse_ts(d.get("last_login"))
    # Ensure mandatory fields have defaults for template safety
    if not hasattr(obj, 'name') or not obj.name:
        # Safely get username/email without raising AttributeError
        u = getattr(obj, 'username', None)
        e = getattr(obj, 'email', None)
        obj.name = u or e or "Unknown Employee"
    
    # Ensure other safe defaults
    if not hasattr(obj, 'status'): obj.status = "Active"
    if not hasattr(obj, 'failed_attempts'): obj.failed_attempts = 0
    if not hasattr(obj, 'last_ip_address'): obj.last_ip_address = None
    if not hasattr(obj, 'employee_number'): obj.employee_number = "N/A"
    if not hasattr(obj, 'role'): obj.role = "Employee"
    
    return obj


def to_log(d):
    obj = SimpleNamespace(**d)
    obj.timestamp = _parse_ts(d.get("timestamp"))
    if not hasattr(obj, "username") or not obj.username:
        obj.username = "Unknown"
    # Ensure reason is present for template safety
    if not hasattr(obj, "reason"):
        obj.reason = "N/A"
    return obj


# ─────────────────────────────────────────────
#  Seed default data on first run
# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
#  Seed default data on first run
# ─────────────────────────────────────────────
def seed_defaults():
    """Insert default employee and admin if tables are empty."""
    try:
        if not get_all_employees():
            hashed = bcrypt.hashpw(b"1234", bcrypt.gensalt()).decode()
            create_employee("John Doe", "john@email.com", "EMP001", "john", hashed, "Employee")
            print("[SEED] Default employee 'john' created (password: 1234)")
    except Exception as e:
        print(f"[WARN] Employee seed skipped: {e}")

    try:
        if not admin_exists():
            hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
            create_admin("admin", hashed)
            print("[SEED] Default admin created (password: admin123)")
    except Exception as e:
        print(f"[WARN] Admin seed skipped: {e}")


with app.app_context():
    seed_defaults()



# ─────────────────────────────────────────────
#  Routes — Login (unified: works for both employees and admins)
# ─────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect("/admin/dashboard")
    if session.get("employee_logged_in"):
        return redirect("/employee/dashboard")

    if request.method == "POST":
        # Accept email OR username in the same field
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "").encode()
        
        ip_address = request.remote_addr
        device_info = request.user_agent.string

        # ── Lookup by email OR username from the employees/profiles table ──
        user = get_user_by_email_or_username(identifier)

        if user:
            # ── Branch A: Employee ──
            if user.get("role", "Employee") not in ("Admin", "SuperAdmin"):
                if not user.get("password"):
                    flash("Password not set. Contact admin.", "danger")
                    return redirect("/")

                if user["status"] == "Locked":
                    flash("Your account is locked. Please contact the administrator.", "danger")
                    return redirect("/")

                display_name = user.get("username") or user.get("email", identifier)
                try:
                    if bcrypt.checkpw(password, user["password"].encode()):
                        # ... (is_suspicious_time check remains)
                        if not user.get("allow_after_hours") and is_suspicious_time():
                            reason = "Login attempt at suspicious hours (11 PM – 5 AM)"
                            log_intrusion(display_name, reason, ip_address, device_info)
                            lock_employee(user["id"])
                            send_intrusion_alert(display_name, reason, ip_address)
                            flash("Account locked: login attempted at suspicious hours. Admin has been notified by email.", "danger")
                            return redirect("/")

                        reset_failed_attempts(user["id"], ip_address)
                        session["employee_logged_in"] = True
                        session["employee_id"] = user["id"]
                        session.permanent = True
                        flash(f"Welcome back, {user.get('name', display_name)}!", "success")
                        return redirect("/employee/dashboard")

                    else:
                        stored_hash = user.get("password", "")
                        print(f"[AUTH DIAGNOSTIC] Password mismatch for '{display_name}'. Stored hash starts with: {stored_hash[:10]}...")
                        
                        new_attempts = (user.get("failed_attempts") or 0) + 1
                        update_failed_attempts(user["id"], new_attempts)

                        if new_attempts >= 3:
                            reason = "Multiple failed login attempts (>=3 attempts)"
                            log_intrusion(display_name, reason, ip_address, device_info)
                            lock_employee(user["id"])
                            send_intrusion_alert(display_name, reason, ip_address)
                            flash("Account locked due to too many failed attempts. Admin has been notified by email.", "danger")
                            return redirect("/")

                        remaining = 3 - new_attempts
                        log_intrusion(display_name, f"Failed password attempt (count: {new_attempts})", ip_address, device_info)
                        flash(f"Incorrect password. {remaining} attempt(s) remaining before lockout.", "danger")
                        return redirect("/")

                except Exception as e:
                    print(f"[ERROR] Exception during login logic: {e}")
                    flash(f"Login failed due to a system error. {e}", "danger")
                    return redirect("/")

            # ── Branch B: Admin ──
            else:
                if not user.get("password"):
                    flash("Admin password not set. Contact system administrator.", "danger")
                    return redirect("/")
                try:
                    if bcrypt.checkpw(password, user["password"].encode()):
                        session["admin_logged_in"] = True
                        session["admin_username"] = user.get("username", identifier)
                        session.permanent = True
                        reset_failed_attempts(user["id"], ip_address)
                        flash(f"Welcome, {user.get('username', identifier)}!", "success")
                        return redirect("/admin/dashboard")
                    else:
                        log_intrusion(user.get("username", identifier), "Failed admin login attempt", ip_address, device_info)
                        flash("Invalid credentials.", "danger")
                        return redirect("/")
                except ValueError:
                    flash("Authentication error. Please contact admin.", "danger")
                    return redirect("/")

        # ── Not found ──
        log_intrusion(identifier, "Login attempt with non-existent username/email", ip_address, device_info)
        flash("Invalid credentials.", "danger")
        return redirect("/")

    return render_template("login.html")


# ─────────────────────────────────────────────
#  Employee Dashboard
# ─────────────────────────────────────────────
@app.route("/employee/dashboard")
def employee_dashboard():
    if not session.get("employee_logged_in"):
        flash("Please log in first.", "warning")
        return redirect("/")

    emp = get_employee_by_id(session["employee_id"])
    if not emp:
        session.clear()
        return redirect("/")

    employee = to_emp(emp)
    return render_template("employee.html", employee=employee)


@app.route("/logout")
def logout():
    session.pop("employee_logged_in", None)
    session.pop("employee_id", None)
    flash("You have been logged out successfully.", "success")
    return redirect("/")


# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
#  Forgot Password (Employee) — 6-digit OTP flow
# ─────────────────────────────────────────────
@app.route("/employee/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Send a 6-digit OTP to the employee's registered email."""
    if session.get("employee_logged_in") or session.get("admin_logged_in"):
        return redirect("/")

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your registered email address.", "danger")
            return redirect("/employee/forgot-password")

        user = get_employee_by_email_only(email)

        if user and user.get("role") != "Admin":
            # Generate a 6-digit numeric OTP (stored as the "token" field)
            otp = str(random.randint(100000, 999999))
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

            try:
                # create_password_reset_token already deletes old tokens internally
                create_password_reset_token(user["id"], otp, expires_at)

                print(f"[OTP RESET] Generated OTP for {email}: {otp} (expires: {expires_at})")

                email_sent = False
                try:
                    send_alert(
                        message=(
                            f"Hello,\n\n"
                            f"A password reset was requested for your account ({email}).\n\n"
                            f"Your One-Time Password (OTP) is:\n\n"
                            f"    {otp}\n\n"
                            f"Enter this code on the Reset Password page along with your email address.\n"
                            f"This code expires in 15 minutes.\n\n"
                            f"If you did not request this, please ignore this email — your password will not change."
                        ),
                        subject="Your Password Reset Code — Employee System",
                        to_email=email   # send directly to the employee, NOT the admin
                    )
                    email_sent = True
                except Exception as mail_err:
                    print(f"[WARN] OTP email not sent: {mail_err}")

                if email_sent:
                    flash("A 6-digit reset code has been sent to your email address. Enter it below.", "success")
                else:
                    flash("Could not send the reset code email. Please contact your administrator.", "danger")
                    return redirect("/employee/forgot-password")

            except Exception as e:
                print(f"[ERROR] Could not create OTP token: {e}")
                flash("Could not process your reset request at this time. Please try again.", "danger")
                return redirect("/employee/forgot-password")
        else:
            # Always show same message to prevent email enumeration
            flash("If that email is registered, a reset code has been sent.", "info")

        # Redirect to reset page so user can enter email + OTP
        return redirect("/employee/reset-password")

    return render_template("forgot_password.html")


@app.route("/employee/reset-password", methods=["GET", "POST"])
def reset_password():
    """Verify email + 6-digit OTP then set a new password."""
    if request.method == "POST":
        email        = request.form.get("email", "").strip().lower()
        otp          = request.form.get("token", "").strip()
        new_password = request.form.get("password", "")
        confirm      = request.form.get("confirm_password", "")

        # Validate OTP is 6 digits
        if not otp.isdigit() or len(otp) != 6:
            flash("Please enter the 6-digit code sent to your email.", "danger")
            return redirect("/employee/reset-password")

        # Look up the OTP in the DB
        token_record = get_password_reset_token(otp)

        if not token_record:
            flash("Incorrect code. Please check your email and try again.", "danger")
            return redirect("/employee/reset-password")

        # Verify the email matches the OTP owner
        user = get_employee_by_email_only(email)
        if not user or str(user["id"]) != str(token_record["user_id"]):
            flash("This code does not match the provided email address.", "danger")
            return redirect("/employee/reset-password")

        # Check expiry
        try:
            expires_at = datetime.fromisoformat(token_record["expires_at"].replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expires_at:
                delete_password_reset_token(otp)
                flash("This code has expired. Please request a new one.", "danger")
                return redirect("/employee/forgot-password")
        except Exception:
            delete_password_reset_token(otp)
            flash("Invalid verification code. Please request a new one.", "danger")
            return redirect("/employee/forgot-password")

        if new_password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect("/employee/reset-password")

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$', new_password):
            flash("Password must be at least 8 characters and include a letter, a number, and a special character.", "danger")
            return redirect("/employee/reset-password")

        try:
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            update_employee_password(token_record["user_id"], hashed)
            unlock_employee(token_record["user_id"])
            delete_password_reset_token(otp)
            flash("✅ Your password has been reset successfully. You can now log in.", "success")
            return redirect("/")
        except Exception as e:
            flash(f"Failed to reset password: {e}", "danger")
            return redirect("/employee/reset-password")

    return render_template("reset_password.html")


# ─────────────────────────────────────────────
#  Admin Routes
# ─────────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return redirect("/")


# ... (Redundant imports removed)

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        flash("Please log in as an administrator.", "warning")
        return redirect("/")

    employees_data = get_all_employees()
    employees = [to_emp(e) for e in employees_data]

    logs_data = get_recent_intrusion_logs(50)
    logs = [to_log(l) for l in logs_data]

    audit_logs_data = get_recent_audit_logs(50)
    audit_logs = [to_log(a) for a in audit_logs_data]
    
    # Calculate stats
    total_employees = len(employees)
    locked_accounts = sum(1 for e in employees_data if e["status"] == "Locked")
    total_intrusions = len(logs)

    stats = {
        "total_employees": total_employees,
        "locked_accounts": locked_accounts,
        "total_intrusions": total_intrusions
    }

    settings = get_system_settings()
    companies = get_all_companies()

    return render_template(
        "admin_dashboard.html",
        employees=employees,
        logs=logs,
        audit_logs=audit_logs,
        stats=stats,
        settings=settings,
        companies=companies
    )


@app.route("/admin/settings/update", methods=["POST"])
def admin_settings_update():
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")

    admin_email = request.form.get("admin_email", "").strip()
    sender_email = request.form.get("sender_email", "").strip()
    sender_password = request.form.get("sender_password", "").strip()

    if admin_email or sender_email or sender_password:
        update_system_settings(admin_email, sender_email, sender_password)
        flash("System settings saved successfully.", "success")
        log_audit_action(session.get("admin_username"), "Update Settings", "System Notifications", request.remote_addr)
    else:
        flash("No settings provided to update.", "info")
    
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/companies/add", methods=["POST"])
def admin_add_company():
    """Admin-only: register a new company/tenant."""
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")

    name = request.form.get("name", "").strip()
    contact_email = request.form.get("contact_email", "").strip() or None
    password = request.form.get("password", "")

    if not name:
        flash("Company name is required.", "danger")
        return redirect(url_for('admin_dashboard'))
    if not password:
        flash("Tenant password is required.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    if len(password) < 6:
        flash("Tenant password must be at least 6 characters.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        import bcrypt
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        company = create_company(name, contact_email=contact_email, password_hash=hashed)
        flash(f"✅ Company '{name}' registered! API Key: {company['api_key'][:20]}...", "success")
        log_audit_action(session.get("admin_username"), "Add Company", name, request.remote_addr)
    except Exception as e:
        flash(f"Error registering company: {e}", "danger")
        
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/register", methods=["POST"])
def admin_register():
    """Admin-only: create a new employee account."""
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")

    name            = request.form.get("name", "").strip()
    email           = request.form.get("email", "").strip()
    employee_number = request.form.get("employee_number", "").strip()
    username        = request.form.get("username", "").strip()
    password        = request.form.get("password", "")
    role            = request.form.get("role", "Employee").strip()

    if not all([name, email, employee_number, username, password]):
        flash("All fields are required.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Password Complexity Check
    if len(password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for('admin_dashboard'))

    if employee_username_exists(username):
        flash(f"Username '{username}' is already taken.", "warning")
        return redirect(url_for('admin_dashboard'))

    if employee_number_exists(employee_number):
        flash(f"Employee number '{employee_number}' is already registered.", "warning")
        return redirect(url_for('admin_dashboard'))

    if get_employee_by_email_only(email):
        flash(f"Email '{email}' is already registered to another account.", "warning")
        return redirect(url_for('admin_dashboard'))

    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        create_employee(name, email, employee_number, username, hashed, role)
        flash(f"✅ Employee '{name}' registered successfully.", "success")
    except Exception as e:
        flash(f"Error registering employee: {e}", "danger")
        
    admin_usr = session.get("admin_username", "Unknown")
    log_audit_action(admin_usr, "Register Employee", username, request.remote_addr)

    return redirect(url_for('admin_dashboard'))


@app.route("/admin/reset_password/<user_id>", methods=["POST"])
def admin_reset_password(user_id):
    """Admin-only: reset an employee's password."""
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")

    new_password = request.form.get("password", "")
    username = get_employee_username_by_id(user_id)

    if not new_password:
        flash("Password cannot be empty.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Password Complexity Check
    if len(new_password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for('admin_dashboard'))

    try:
        from sql_queries import update_employee_password
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        update_employee_password(user_id, hashed)
        flash(f"✅ Password for '{username}' has been reset successfully.", "success")
        log_audit_action(session.get("admin_username"), "Reset Password", username, request.remote_addr)
    except Exception as e:
        flash(f"Error resetting password: {e}", "danger")

    return redirect(url_for('admin_dashboard'))


@app.route("/admin/unlock/<user_id>")
def unlock_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/")
    username = get_employee_username_by_id(user_id)
    if username:
        unlock_employee(user_id)
        flash(f"✅ Account for '{username}' has been unlocked.", "success")
        log_audit_action(session.get("admin_username"), "Unlock Account", username, request.remote_addr)
    else:
        flash(f"Employee with ID {user_id} not found.", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/lock/<user_id>")
def lock_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/")
    username = get_employee_username_by_id(user_id)
    if username:
        lock_employee(user_id)
        flash(f"🔒 Account for '{username}' has been locked.", "warning")
        log_audit_action(session.get("admin_username"), "Lock Account", username, request.remote_addr)
    else:
        flash(f"Employee with ID {user_id} not found.", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/delete/<user_id>")
def delete_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/")
    username = get_employee_username_by_id(user_id)
    if username:
        delete_employee(user_id)
        flash(f"🗑️ Employee '{username}' has been deleted.", "info")
        log_audit_action(session.get("admin_username"), "Delete Account", username, request.remote_addr)
    else:
        flash(f"Employee with ID {user_id} not found.", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/employee/<user_id>/toggle-after-hours", methods=["POST"])
def toggle_after_hours(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/")
    allow = request.form.get("allow") == "true"
    from sql_queries import update_employee_after_hours, get_employee_username_by_id
    update_employee_after_hours(user_id, allow)
    username = get_employee_username_by_id(user_id)
    state = "allowed" if allow else "restricted"
    flash(f"After-hours access {state} for {username}.", "info")
    log_audit_action(session.get("admin_username"), f"Toggle After-Hours ({state})", username, request.remote_addr)
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/companies/<company_id>/hours", methods=["POST"])
def update_company_hours_route(company_id):
    if not session.get("admin_logged_in"):
        return redirect("/")
    start = request.form.get("start")
    end = request.form.get("end")
    if start and end:
        from sql_queries import update_company_hours
        update_company_hours(company_id, start, end)
        flash("Company working hours updated successfully.", "success")
        log_audit_action(session.get("admin_username"), "Update Company Hours", company_id, request.remote_addr)
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/companies/<company_id>/delete", methods=["POST"])
def admin_delete_company(company_id):
    """Admin-only: permanently delete a company tenant and its settings."""
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")
    try:
        company = get_company_by_id(company_id)
        name = company["name"] if company else company_id
        delete_company(company_id)
        flash(f"🗑️ Company '{name}' and its settings have been deleted.", "info")
        log_audit_action(session.get("admin_username"), "Delete Company", name, request.remote_addr)
    except Exception as e:
        flash(f"Error deleting company: {e}", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route("/admin/companies/<company_id>/regenerate-key", methods=["POST"])
def admin_regenerate_company_key(company_id):
    """Admin-only: generate a fresh API key for a company (invalidates the old one)."""
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")
    try:
        company = get_company_by_id(company_id)
        name = company["name"] if company else company_id
        new_key = regenerate_company_api_key(company_id)
        flash(f"🔑 New API key for '{name}': {new_key[:20]}... — update your integration snippet!", "success")
        log_audit_action(session.get("admin_username"), "Regenerate API Key", name, request.remote_addr)
    except Exception as e:
        flash(f"Error regenerating key: {e}", "danger")
    return redirect(url_for('admin_dashboard'))


@app.route("/api/v1/health", methods=["GET"])
def api_health():
    """Public health check endpoint — used by integration guide's 'Test Connection' button."""
    return jsonify({"status": "ok", "service": "SecureIDS", "version": "2.0"}), 200


@app.route("/register-company", methods=["POST"])
def public_register_company():
    """Public self-service registration: creates a company & emails the API key."""
    company_name  = request.form.get("company_name", "").strip()
    contact_email = request.form.get("contact_email", "").strip()
    password      = request.form.get("password", "")

    if not company_name or not contact_email or not password:
        flash("Company name, contact email, and password are required.", "danger")
        return redirect("/integration#register")

    if len(password) < 6:
        flash("Password must be at least 6 characters.", "danger")
        return redirect("/integration#register")

    # Basic email validation
    import re as _re
    if not _re.match(r'^[^@]+@[^@]+\.[^@]+$', contact_email):
        flash("Please enter a valid email address.", "danger")
        return redirect("/integration#register")

    try:
        import bcrypt
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        company = create_company(company_name, contact_email=contact_email, password_hash=hashed)
        api_key = company["api_key"]
        host = request.host_url.rstrip("/")
        snippet = f'<script src="{host}/static/ids-shield.js" data-api-key="{api_key}"></script>'

        # Send API key via email
        try:
            send_alert(
                message=(
                    f"Hello,\n\n"
                    f"Welcome to SecureIDS! Your company '{company_name}' has been registered.\n\n"
                    f"Your API Key is:\n\n    {api_key}\n\n"
                    f"Integration snippet (paste before </body> on your login page):\n\n    {snippet}\n\n"
                    f"Visit {host}/integration/login to log in to your Tenant Portal.\n\n"
                    f"— SecureIDS Team"
                ),
                subject=f"Your SecureIDS API Key — {company_name}",
                to_email=contact_email
            )
            email_sent = True
        except Exception as mail_err:
            print(f"[WARN] Registration email not sent: {mail_err}")
            email_sent = False

        session["new_company_key"] = api_key
        session["new_company_name"] = company_name
        session["new_company_snippet"] = snippet
        session["new_company_email_sent"] = email_sent
        log_audit_action("public", "Self-Service Registration", company_name, request.remote_addr)
        return redirect("/integration/success")
    except Exception as e:
        flash(f"Registration failed: {e}", "danger")
        return redirect("/integration#register")


@app.route("/integration/success")
def integration_success():
    """Show the success page after self-service company registration."""
    api_key = session.pop("new_company_key", None)
    company_name = session.pop("new_company_name", "Your Company")
    snippet = session.pop("new_company_snippet", "")
    email_sent = session.pop("new_company_email_sent", False)
    if not api_key:
        return redirect("/integration")
    host = request.host_url.rstrip("/")
    return render_template(
        "integration_success.html",
        api_key=api_key,
        company_name=company_name,
        snippet=snippet,
        email_sent=email_sent,
        ids_host=host
    )


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    flash("Logged out from admin panel.", "success")
    return redirect("/")


# ─────────────────────────────────────────────
#  Run
# ─────────────────────────────────────────────
@app.route("/admin/export/logs")
def export_logs():
    if not session.get("admin_logged_in"):
        return redirect("/")
    
    logs = get_recent_intrusion_logs(100)
    
    import csv
    from io import StringIO
    from flask import Response
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID', 'Username', 'Reason', 'IP', 'Device', 'Timestamp'])
    for log in logs:
        cw.writerow([
            log.get("id", ""),
            log.get("username", ""),
            log.get("reason", ""),
            log.get("ip_address", ""),
            log.get("device_info", ""),
            log.get("timestamp", "")
        ])
        
    output = si.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=intrusion_logs.csv"}
    )

@app.route("/admin/test-email")
def test_email():
    """Diagnostic route to test email connectivity."""
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/")
    
    success = send_alert("This is a diagnostic test email to verify your Render/Gmail connection.", "Test Email")
    if success:
        flash("✅ Test email sent! Check your inbox (and spam).", "success")
    else:
        flash("❌ Email failed! Check the Render 'Logs' tab for more details.", "danger")
    
    return redirect(url_for('admin_dashboard'))

# ─────────────────────────────────────────────
#  Widget & Integration Routes
# ─────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    # Allow widget to be embedded in iframes on any customer site
    response.headers.pop('X-Frame-Options', None)
    # Allow Cross-Origin AJAX requests from the invisible shield script
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route("/api/v1/auth/verify", methods=["POST", "OPTIONS"])
@app.route("/api/evaluate_login", methods=["POST", "OPTIONS"]) # Legacy Support
def evaluate_login():
    """Pre-screen API: checks hours and account status WITHOUT verifying the password.
    The widget uses this to intercept the form and block suspicious attempts before submission."""
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # 1. API Key Authentication
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    if not api_key:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            api_key = auth_header.split("Bearer ")[1]

    if not api_key:
        return jsonify({"status": "deny", "reason": "Missing API Key"}), 401

    from sql_queries import get_company_by_api_key, get_company_settings
    company = get_company_by_api_key(api_key)
    if not company:
        return jsonify({"status": "deny", "reason": "Invalid API Key"}), 401

    company_id = company["id"]
    identifier = data.get("identifier", "unknown")
    url = data.get("url", "unknown_site")
    ip_address = request.remote_addr
    device_info = request.user_agent.string

    # Rule 1: Get user
    user = get_user_by_email_or_username(identifier)

    # Rule 2: Suspicious Hours
    settings = get_company_settings(company_id) or {}
    start_time_str = settings.get("working_hours_start", "05:00:00")
    end_time_str = settings.get("working_hours_end", "23:00:00")
    
    allow_after_hours = user.get("allow_after_hours", False) if user else False

    if not allow_after_hours and is_suspicious_time(start_time_str, end_time_str):
        reason = f"Login attempt outside of {company['name']} working hours ({start_time_str}–{end_time_str})"
        log_intrusion(identifier, reason, ip_address, device_info, company_id)
        return jsonify({
            "status": "deny",
            "reason": f"Access denied: Outside allowed working hours ({start_time_str}–{end_time_str})."
        }), 403

    # Rule 3: Account Status
    if user and str(user.get("company_id")) == str(company_id):
        if user.get("status") == "Locked":
            log_intrusion(identifier, "Attempted login on locked account", ip_address, device_info, company_id)
            return jsonify({
                "status": "deny",
                "reason": "Account is locked. Please contact your administrator."
            }), 403

    # All pre-checks passed — allow the form to proceed
    return jsonify({"status": "allow", "company": company["name"]}), 200


@app.route("/api/v1/auth/login", methods=["POST", "OPTIONS"])
def api_full_login():
    """Full-authentication API endpoint.
    Companies call this instead of their own login system.
    Returns: allow / deny / lock_account with a descriptive reason.
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    # 1. API Key
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key")
    if not api_key:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            api_key = auth_header.split("Bearer ")[1]

    if not api_key:
        return jsonify({"status": "deny", "reason": "Missing API key. Include it in the Authorization header as 'Bearer <key>'."}), 401

    from sql_queries import get_company_by_api_key, get_company_settings
    company = get_company_by_api_key(api_key)
    if not company:
        return jsonify({"status": "deny", "reason": "Invalid API key."}), 401

    company_id = company["id"]

    # 2. Extract credentials
    identifier = data.get("identifier", "").strip()
    password_raw = data.get("password", "")
    ip_address = request.remote_addr
    device_info = request.user_agent.string

    if not identifier or not password_raw:
        return jsonify({"status": "deny", "reason": "Both 'identifier' and 'password' are required."}), 400

    # 3. Look up user
    user = get_user_by_email_or_username(identifier)
    if not user:
        log_intrusion(identifier, "Login attempt with unknown identifier (API)", ip_address, device_info, company_id)
        return jsonify({"status": "deny", "reason": "Invalid credentials."}), 401

    # 4. Suspicious hours check
    settings = get_company_settings(company_id) or {}
    start_time_str = settings.get("working_hours_start", "05:00:00")
    end_time_str = settings.get("working_hours_end", "23:00:00")
    max_attempts = int(settings.get("max_failed_attempts", 3))

    if not user.get("allow_after_hours") and is_suspicious_time(start_time_str, end_time_str):
        reason = f"Login attempt outside of {company['name']} working hours ({start_time_str}–{end_time_str})"
        log_intrusion(identifier, reason, ip_address, device_info, company_id)
        return jsonify({
            "status": "deny",
            "reason": f"Access denied: login is only allowed between {start_time_str} and {end_time_str}."
        }), 403

    # 5. Account locked?
    if user.get("status") == "Locked":
        log_intrusion(identifier, "Login attempted on locked account (API)", ip_address, device_info, company_id)
        return jsonify({
            "status": "deny",
            "reason": "Account is locked due to multiple failed login attempts. Contact your administrator."
        }), 403

    # 6. Password check
    try:
        stored_hash = user.get("password", "")
        password_ok = bcrypt.checkpw(password_raw.encode(), stored_hash.encode())
    except Exception:
        return jsonify({"status": "deny", "reason": "Authentication error. Please try again."}), 500

    if not password_ok:
        new_attempts = (user.get("failed_attempts") or 0) + 1
        update_failed_attempts(user["id"], new_attempts)

        if new_attempts >= max_attempts:
            lock_employee(user["id"])
            reason = f"Account locked after {new_attempts} failed login attempts (API)"
            log_intrusion(identifier, reason, ip_address, device_info, company_id)
            send_intrusion_alert(identifier, reason, ip_address)
            return jsonify({
                "status": "lock_account",
                "reason": f"Account locked after {max_attempts} failed attempts. Administrator has been notified.",
                "failed_attempts": new_attempts
            }), 403

        remaining = max_attempts - new_attempts
        log_intrusion(identifier, f"Failed password (via API, attempt {new_attempts})", ip_address, device_info, company_id)
        return jsonify({
            "status": "deny",
            "reason": f"Incorrect credentials. {remaining} attempt(s) remaining before lockout.",
            "failed_attempts": new_attempts
        }), 401

    # 7. Success
    display_name = user.get("name") or user.get("username") or identifier
    reset_failed_attempts(user["id"], ip_address)
    return jsonify({
        "status": "allow",
        "reason": "Login successful.",
        "user": {
            "id": user["id"],
            "name": display_name,
            "username": user.get("username"),
            "email": user.get("email"),
            "role": user.get("role", "Employee")
        }
    }), 200


# ─────────────────────────────────────────────
#  Integration Developer Portal
# ─────────────────────────────────────────────
@app.route("/integration", methods=["GET", "POST"])
def integration_portal():
    """SaaS Tenant Login Portal."""
    if session.get("company_logged_in"):
        return redirect("/integration/dashboard")

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect("/integration")

        from sql_queries import get_company_by_email, update_company_failed_attempts, lock_company, reset_company_failed_attempts, get_company_settings
        company = get_company_by_email(email)

        if not company:
            flash("Invalid email or password.", "danger")
            return redirect("/integration")

        if company.get("status") == "Locked":
            flash("Your company account is locked due to too many failed attempts. Please contact support.", "danger")
            return redirect("/integration")
            
        # Check if outside working hours for login portal access
        settings = get_company_settings(company["id"]) or {}
        start_time_str = settings.get("working_hours_start", "05:00:00")
        end_time_str = settings.get("working_hours_end", "23:00:00")
        
        if is_suspicious_time(start_time_str, end_time_str):
            flash(f"Access Denied: You can only access the portal during your configured working hours ({start_time_str} - {end_time_str}).", "warning")
            return redirect("/integration")

        import bcrypt
        try:
            stored_hash = company.get("password_hash")
            if not stored_hash:
                flash("Your account does not have a password set. Please contact support.", "danger")
                return redirect("/integration")

            if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                reset_company_failed_attempts(company["id"], ip_address)
                session["company_logged_in"] = True
                session["company_id"] = company["id"]
                session.permanent = True
                flash(f"Welcome to the Tenant Portal, {company['name']}!", "success")
                return redirect("/integration/dashboard")
            else:
                attempts = company.get("failed_attempts", 0) + 1
                update_company_failed_attempts(company["id"], attempts)
                if attempts >= 3:
                    lock_company(company["id"])
                    flash("Account locked due to too many failed attempts.", "danger")
                else:
                    flash(f"Invalid password. {3 - attempts} attempt(s) remaining.", "danger")
                return redirect("/integration")
        except Exception as e:
            flash(f"Authentication error: {e}", "danger")
            return redirect("/integration")

    return render_template("tenant_login.html")

@app.route("/integration/dashboard")
def integration_dashboard():
    """SaaS Tenant Dashboard showing API Key and configuration."""
    if not session.get("company_logged_in"):
        flash("Please log in to access the Tenant Portal.", "warning")
        return redirect("/integration")
        
    company_id = session.get("company_id")
    from sql_queries import get_company_by_id, get_company_settings
    company = get_company_by_id(company_id)
    if not company:
        session.pop("company_logged_in", None)
        return redirect("/integration")
        
    settings = get_company_settings(company_id) or {}
    host = request.host_url.rstrip("/")
    return render_template("integration.html", company=company, settings=settings, ids_host=host)

@app.route("/integration/settings", methods=["POST"])
def integration_settings():
    if not session.get("company_logged_in"):
        return redirect("/integration")
        
    company_id = session.get("company_id")
    start = request.form.get("start")
    end = request.form.get("end")
    if start and end:
        from sql_queries import update_company_hours
        update_company_hours(company_id, start, end)
        flash("Your working hours have been updated successfully.", "success")
    return redirect("/integration/dashboard")

@app.route("/integration/logout")
def integration_logout():
    session.pop("company_logged_in", None)
    session.pop("company_id", None)
    flash("You have securely logged out.", "success")
    return redirect("/integration")

@app.route("/embed/login", methods=["GET", "POST"])
def embed_login():
    if session.get("admin_logged_in"):
        return "<script>window.top.location.href = '/admin/dashboard';</script>"
    if session.get("employee_logged_in"):
        return "<script>window.top.location.href = '/employee/dashboard';</script>"

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "").encode()
        
        ip_address = request.remote_addr
        device_info = request.user_agent.string

        user = get_user_by_email_or_username(identifier)

        if user:
            if user.get("role", "Employee") not in ("Admin", "SuperAdmin"):
                if not user.get("password"):
                    flash("Password not set. Contact admin.", "danger")
                    return redirect("/embed/login")

                if user["status"] == "Locked":
                    flash("Your account is locked. Please contact the administrator.", "danger")
                    return redirect("/embed/login")

                display_name = user.get("username") or user.get("email", identifier)
                try:
                    if bcrypt.checkpw(password, user["password"].encode()):
                        if not user.get("allow_after_hours") and is_suspicious_time():
                            reason = "Login attempt at suspicious hours (11 PM \u2013 5 AM)"
                            log_intrusion(display_name, reason, ip_address, device_info)
                            lock_employee(user["id"])
                            send_intrusion_alert(display_name, reason, ip_address)
                            flash("Account locked: login attempted at suspicious hours. Admin has been notified by email.", "danger")
                            return redirect("/embed/login")

                        reset_failed_attempts(user["id"], ip_address)
                        session["employee_logged_in"] = True
                        session["employee_id"] = user["id"]
                        session.permanent = True
                        flash(f"Welcome back, {user.get('name', display_name)}!", "success")
                        return "<script>window.top.location.href = '/employee/dashboard';</script>"

                    else:
                        new_attempts = (user.get("failed_attempts") or 0) + 1
                        update_failed_attempts(user["id"], new_attempts)

                        if new_attempts >= 3:
                            reason = "Multiple failed login attempts (>=3 attempts)"
                            log_intrusion(display_name, reason, ip_address, device_info)
                            lock_employee(user["id"])
                            send_intrusion_alert(display_name, reason, ip_address)
                            flash("Account locked due to too many failed attempts. Admin has been notified by email.", "danger")
                            return redirect("/embed/login")

                        remaining = 3 - new_attempts
                        log_intrusion(display_name, f"Failed password attempt (count: {new_attempts})", ip_address, device_info)
                        flash(f"Incorrect password. {remaining} attempt(s) remaining before lockout.", "danger")
                        return redirect("/embed/login")

                except Exception as e:
                    flash(f"Login failed due to a system error. {e}", "danger")
                    return redirect("/embed/login")

            else:
                if not user.get("password"):
                    flash("Admin password not set. Contact system administrator.", "danger")
                    return redirect("/embed/login")
                try:
                    if bcrypt.checkpw(password, user["password"].encode()):
                        session["admin_logged_in"] = True
                        session["admin_username"] = user.get("username", identifier)
                        session.permanent = True
                        reset_failed_attempts(user["id"], ip_address)
                        flash(f"Welcome, {user.get('username', identifier)}!", "success")
                        return "<script>window.top.location.href = '/admin/dashboard';</script>"
                    else:
                        log_intrusion(user.get("username", identifier), "Failed admin login attempt", ip_address, device_info)
                        flash("Invalid credentials.", "danger")
                        return redirect("/embed/login")
                except ValueError:
                    flash("Authentication error. Please contact admin.", "danger")
                    return redirect("/embed/login")

        log_intrusion(identifier, "Login attempt with non-existent username/email", ip_address, device_info)
        flash("Invalid credentials.", "danger")
        return redirect("/embed/login")

    return render_template("embed_login.html")

@app.route("/test-customer")
def test_customer():
    from sql_queries import get_all_companies
    companies = get_all_companies()
    
    # Use the most recent company's API key, or a fallback if none exist
    if companies:
        api_key = companies[0].get("api_key", "sk_test_12345abcde")
        company_name = companies[0].get("name", "Demo Company")
    else:
        api_key = "sk_test_12345abcde"
        company_name = "Demo Company"
        
    return render_template("test_customer.html", api_key=api_key, company_name=company_name)

@app.route("/test-customer-dashboard")
def test_customer_dashboard():
    return render_template("test_customer_dashboard.html")

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)