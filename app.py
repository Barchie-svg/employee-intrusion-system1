from flask import Flask, render_template, request, redirect, session, flash
from config import SECRET_KEY, ADMIN_EMAIL, SENDER_EMAIL, SENDER_PASSWORD
from database import supabase
from intrusion import is_suspicious_time
from email_alert import send_alert
from datetime import datetime, timezone
from types import SimpleNamespace
import bcrypt

# ─────────────────────────────────────────────
#  Flask Setup
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY


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
        # Supabase returns strings like "2026-02-24T14:00:00+00:00"
        return datetime.fromisoformat(val.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return None


def to_emp(d):
    """Convert an employee dict to a SimpleNamespace with parsed dates."""
    obj = SimpleNamespace(**d)
    obj.last_login = _parse_ts(d.get("last_login"))
    return obj


def to_log(d):
    """Convert an intrusion_log dict to a SimpleNamespace with parsed timestamp."""
    obj = SimpleNamespace(**d)
    obj.timestamp = _parse_ts(d.get("timestamp"))
    return obj


# ─────────────────────────────────────────────
#  Seed default data on first run
# ─────────────────────────────────────────────
def seed_defaults():
    """Insert default employee and admin if tables are empty."""
    # Default employee
    emp_res = supabase.table("employees").select("id").limit(1).execute()
    if not emp_res.data:
        hashed = bcrypt.hashpw(b"1234", bcrypt.gensalt()).decode()
        supabase.table("employees").insert({
            "employee_number": "EMP001",
            "name": "John Doe",
            "email": "john@email.com",
            "username": "john",
            "password": hashed,
            "status": "Active",
            "failed_attempts": 0,
        }).execute()
        print("[SEED] Default employee 'john' created (password: 1234)")

    # Default admin
    adm_res = supabase.table("admins").select("id").limit(1).execute()
    if not adm_res.data:
        hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
        supabase.table("admins").insert({
            "username": "admin",
            "password": hashed,
        }).execute()
        print("[SEED] Default admin created (password: admin123)")


with app.app_context():
    try:
        seed_defaults()
    except Exception as e:
        print(f"[WARN] Seed skipped (tables may not exist yet): {e}")


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────
def log_intrusion(username, reason):
    """Write an intrusion event to the intrusion_logs table."""
    supabase.table("intrusion_logs").insert({
        "username": username,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
    }).execute()


def lock_account(user_id):
    """Set employee status to Locked."""
    supabase.table("employees").update({"status": "Locked"}).eq("id", user_id).execute()


# ─────────────────────────────────────────────
#  Employee Routes
# ─────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").encode()

        res = supabase.table("employees").select("*").eq("username", username).execute()
        if not res.data:
            flash("No account found with that username.", "danger")
            return redirect("/")

        user = res.data[0]

        if not user.get("password"):
            flash("Password not set. Contact admin.", "danger")
            return redirect("/")

        if user["status"] == "Locked":
            flash("Your account is locked. Please contact the administrator.", "danger")
            return redirect("/")

        try:
            if bcrypt.checkpw(password, user["password"].encode()):
                if is_suspicious_time():
                    reason = "Login attempt at suspicious hours (10 PM – 5 AM)"
                    log_intrusion(username, reason)
                    lock_account(user["id"])
                    send_alert(username, reason)
                    flash("Account locked: login attempted at suspicious hours. Admin notified.", "danger")
                    return redirect("/")

                # Successful login
                supabase.table("employees").update({
                    "failed_attempts": 0,
                    "last_login": datetime.utcnow().isoformat(),
                }).eq("id", user["id"]).execute()

                session["employee_logged_in"] = True
                session["employee_id"] = user["id"]
                flash(f"Welcome back, {user['name']}!", "success")
                return redirect("/employee/dashboard")

            else:
                new_attempts = user["failed_attempts"] + 1
                supabase.table("employees").update({"failed_attempts": new_attempts}).eq("id", user["id"]).execute()

                if new_attempts >= 3:
                    reason = "Multiple failed login attempts (≥3)"
                    log_intrusion(username, reason)
                    lock_account(user["id"])
                    send_alert(username, reason)
                    flash("Account locked due to too many failed attempts. Admin has been notified.", "danger")
                    return redirect("/")

                remaining = 3 - new_attempts
                flash(f"Incorrect password. {remaining} attempt(s) remaining before lockout.", "danger")
                return redirect("/")

        except ValueError:
            flash("Authentication error. Please contact admin.", "danger")
            return redirect("/")

    return render_template("login.html")


@app.route("/employee/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name            = request.form.get("name", "").strip()
        email           = request.form.get("email", "").strip()
        employee_number = request.form.get("employee_number", "").strip()
        username        = request.form.get("username", "").strip()
        password        = request.form.get("password", "")
        confirm         = request.form.get("confirm_password", "")

        if not all([name, email, employee_number, username, password]):
            flash("All fields are required.", "danger")
            return redirect("/employee/register")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect("/employee/register")

        # Check uniqueness
        if supabase.table("employees").select("id").eq("username", username).execute().data:
            flash("Username already taken.", "warning")
            return redirect("/employee/register")

        if supabase.table("employees").select("id").eq("employee_number", employee_number).execute().data:
            flash("Employee number already registered.", "warning")
            return redirect("/employee/register")

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        supabase.table("employees").insert({
            "name": name,
            "email": email,
            "employee_number": employee_number,
            "username": username,
            "password": hashed,
            "status": "Active",
            "failed_attempts": 0,
        }).execute()

        flash("Registration successful! You can now log in.", "success")
        return redirect("/")

    return render_template("register.html")


@app.route("/employee/dashboard")
def employee_dashboard():
    if not session.get("employee_logged_in"):
        flash("Please log in first.", "warning")
        return redirect("/")

    res = supabase.table("employees").select("*").eq("id", session["employee_id"]).execute()
    if not res.data:
        session.clear()
        return redirect("/")

    employee = to_emp(res.data[0])
    return render_template("employee.html", employee=employee)


@app.route("/logout")
def logout():
    session.pop("employee_logged_in", None)
    session.pop("employee_id", None)
    flash("You have been logged out successfully.", "success")
    return redirect("/")


# ─────────────────────────────────────────────
#  Admin Routes
# ─────────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").encode()

        res = supabase.table("admins").select("*").eq("username", username).execute()
        if not res.data:
            flash("Invalid admin credentials.", "danger")
            return redirect("/admin/login")

        admin = res.data[0]
        if not bcrypt.checkpw(password, admin["password"].encode()):
            flash("Invalid admin credentials.", "danger")
            return redirect("/admin/login")

        session["admin_logged_in"] = True
        session["admin_username"] = admin["username"]
        flash(f"Welcome, {admin['username']}!", "success")
        return redirect("/admin/dashboard")

    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        flash("Admin access required.", "warning")
        return redirect("/admin/login")

    emp_res  = supabase.table("employees").select("*").execute()
    logs_res = supabase.table("intrusion_logs").select("*").order("timestamp", desc=True).execute()

    employees = [to_emp(e) for e in (emp_res.data or [])]
    logs      = [to_log(l) for l in (logs_res.data or [])]

    all_emps = emp_res.data or []
    stats = {
        "total_employees":  len(all_emps),
        "locked_accounts":  sum(1 for e in all_emps if e["status"] == "Locked"),
        "total_intrusions": len(logs_res.data or []),
        "total_failed":     sum(e.get("failed_attempts", 0) for e in all_emps),
    }

    return render_template("admin_dashboard.html", employees=employees, logs=logs, stats=stats)


@app.route("/admin/unlock/<int:user_id>")
def unlock_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin/login")
    res = supabase.table("employees").select("username").eq("id", user_id).execute()
    if res.data:
        uname = res.data[0]["username"]
        supabase.table("employees").update({"status": "Active", "failed_attempts": 0}).eq("id", user_id).execute()
        flash(f"✅ Account for '{uname}' has been unlocked.", "success")
    return redirect("/admin/dashboard")


@app.route("/admin/lock/<int:user_id>")
def lock_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin/login")
    res = supabase.table("employees").select("username").eq("id", user_id).execute()
    if res.data:
        uname = res.data[0]["username"]
        supabase.table("employees").update({"status": "Locked"}).eq("id", user_id).execute()
        flash(f"🔒 Account for '{uname}' has been locked.", "warning")
    return redirect("/admin/dashboard")


@app.route("/admin/delete/<int:user_id>")
def delete_user(user_id):
    if not session.get("admin_logged_in"):
        return redirect("/admin/login")
    res = supabase.table("employees").select("username").eq("id", user_id).execute()
    if res.data:
        uname = res.data[0]["username"]
        supabase.table("employees").delete().eq("id", user_id).execute()
        flash(f"🗑️ Employee '{uname}' has been deleted.", "info")
    return redirect("/admin/dashboard")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    flash("Logged out from admin panel.", "success")
    return redirect("/admin/login")


# ─────────────────────────────────────────────
#  Run
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)