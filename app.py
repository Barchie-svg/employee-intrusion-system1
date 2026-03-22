from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_session import Session
import bcrypt
import re
import secrets
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
    get_setting, update_setting, get_system_settings, update_system_settings
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
            if user.get("role", "Employee") != "Admin":
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
                        if is_suspicious_time():
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
#  Forgot Password (Employee)
# ─────────────────────────────────────────────
@app.route("/employee/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Request a password reset link."""
    if session.get("employee_logged_in") or session.get("admin_logged_in"):
        return redirect("/")

    reset_url_for_display = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Please enter your registered email address.", "danger")
            return redirect("/employee/forgot-password")

        user = get_employee_by_email_only(email)

        if user and user.get("role") != "Admin":
            token = secrets.token_urlsafe(32)
            expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

            try:
                create_password_reset_token(user["id"], token, expires_at)
                reset_url = url_for("reset_password", token=token, _external=True)
                reset_url_for_display = reset_url

                print(f"\n[PASSWORD RESET] User: {email}")
                print(f"[PASSWORD RESET] Reset URL: {reset_url}")
                print(f"[PASSWORD RESET] Expires at: {expires_at}\n")

                email_sent = False
                try:
                    send_alert(
                        message=(
                            f"Password reset requested for: {email}\n\n"
                            f"Reset link (valid 1 hour):\n{reset_url}\n\n"
                            f"If you did not request this, please ignore this email."
                        ),
                        subject="Password Reset Request — Employee System"
                    )
                    email_sent = True
                except Exception as mail_err:
                    print(f"[WARN] Email not sent: {mail_err}")

                if email_sent:
                    flash("A password reset link has been sent to your email. It expires in 1 hour.", "success")
                else:
                    flash("Email delivery is not configured. Use the reset link shown below — it expires in 1 hour.", "warning")

            except Exception as e:
                print(f"[ERROR] Could not create reset token: {e}")
                flash(
                    "Could not generate a reset link. Make sure the password_reset_tokens "
                    "table exists in Supabase (run supabase_fix.sql).",
                    "danger"
                )
                return render_template("forgot_password.html", reset_url=None)
        else:
            flash("If that email is registered, a password reset link has been generated.", "info")

        return render_template("forgot_password.html", reset_url=reset_url_for_display)

    return render_template("forgot_password.html", reset_url=None)


@app.route("/employee/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Use a reset token to set a new password."""
    token_record = get_password_reset_token(token)

    if not token_record:
        flash("This reset link is invalid or has already been used.", "danger")
        return redirect("/")

    # Check expiry
    try:
        expires_at = datetime.fromisoformat(token_record["expires_at"].replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expires_at:
            delete_password_reset_token(token)
            flash("This reset link has expired. Please request a new one.", "danger")
            return redirect("/employee/forgot-password")
    except Exception:
        delete_password_reset_token(token)
        flash("Invalid reset link.", "danger")
        return redirect("/")

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm      = request.form.get("confirm_password", "")

        if new_password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", token=token)

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$', new_password):
            flash("Password must be at least 8 characters and include a letter, a number, and a special character.", "danger")
            return render_template("reset_password.html", token=token)

        try:
            hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
            update_employee_password(token_record["user_id"], hashed)
            # Also unlock account in case it was locked
            unlock_employee(token_record["user_id"])
            delete_password_reset_token(token)
            flash("✅ Your password has been reset successfully. You can now log in.", "success")
            return redirect("/")
        except Exception as e:
            flash(f"Failed to reset password: {e}", "danger")
            return render_template("reset_password.html", token=token)

    return render_template("reset_password.html", token=token)


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

    return render_template(
        "admin_dashboard.html",
        employees=employees,
        logs=logs,
        audit_logs=audit_logs,
        stats=stats,
        settings=settings
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
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$', password):
        flash("Password must be at least 8 characters long, contain a number, and a special character.", "danger")
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
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$', new_password):
        flash("Password must be at least 8 characters long, contain a number, and a special character.", "danger")
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

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)