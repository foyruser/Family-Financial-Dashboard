from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

import os
import sys
import functools
import secrets
import smtplib
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from email.message import EmailMessage
from datetime import datetime, timedelta
from urllib.parse import urljoin

from cryptography.fernet import Fernet

# -------------------------------------------------
# App & Config
# -------------------------------------------------
app = Flask(__name__)

# Secret keys (provide via Render env)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY", "a_long_random_fallback_key")

# Secure cookies in prod
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
)

# Respect proxy headers for real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # sensible defaults
)

DATABASE_URL = os.environ.get("DATABASE_URL")
EXCHANGE_RATE_API_KEY = os.environ.get("EXCHANGE_RATE_API_KEY", "")
FERNET_KEY = os.environ.get("FERNET_KEY")  # must be stable in prod

MAIL_SERVER = os.environ.get("MAIL_SERVER")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_USE_TLS = (os.environ.get("MAIL_USE_TLS", "true").lower() == "true")
MAIL_SENDER = os.environ.get("MAIL_SENDER", MAIL_USERNAME or "no-reply@example.com")

# -------------------------------------------------
# Encryption helper
# -------------------------------------------------
class Encryptor:
    def __init__(self, key: str | None):
        if not key:
            print("WARNING: FERNET_KEY not set; generating ephemeral key (NOT for production).", file=sys.stderr)
            key = Fernet.generate_key().decode()
        self.f = Fernet(key.encode())

    def encrypt(self, data):
        if data is None or data == "":
            return None
        return self.f.encrypt(str(data).encode()).decode()

    def decrypt(self, data):
        if data is None or data == "":
            return ""
        try:
            return self.f.decrypt(data.encode()).decode()
        except Exception:
            # caller decides what to do; we don't spam logs here
            return "[unreadable]"

encryptor = Encryptor(FERNET_KEY)

def looks_encrypted(value: str) -> bool:
    """Heuristic to avoid decrypting legacy plaintext."""
    if not isinstance(value, str):
        return False
    if len(value) < 60:
        return False
    if not value.startswith("gAAAA"):
        return False
    return True

def enc(v):
    return encryptor.encrypt(v) if v not in (None, "") else None

def dec(v):
    if v in (None, ""):
        return ""
    s = str(v)
    if looks_encrypted(s):
        out = encryptor.decrypt(s)
        return out if out != "[unreadable]" else "[unreadable]"
    # legacy plaintext kept as-is
    return s

# -------------------------------------------------
# Template helpers
# -------------------------------------------------
@app.context_processor
def inject_csrf_token():
    try:
        from flask_wtf.csrf import generate_csrf
        return dict(csrf_token=generate_csrf)
    except Exception:
        return dict(csrf_token=None)

# -------------------------------------------------
# DB helpers
# -------------------------------------------------
def get_db_connection():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set")
    return psycopg2.connect(DATABASE_URL)

# Single, consistent auth decorator (no Flask-Login)
def auth_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "info")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            flash("Please log in.", "info")
            return redirect(url_for("login"))
        if g.user_role != "Admin":
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return view(**kwargs)
    return wrapped_view

def get_group_filter_clause(user_role, group_id, table_alias=""):
    if table_alias and not table_alias.endswith("."):
        table_alias += "."
    if user_role == "Admin":
        return "", ()
    if group_id:
        return f"AND {table_alias}group_id = %s", (group_id,)
    return "AND 1=0", ()

# -------------------------------------------------
# User Context
# -------------------------------------------------
@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user_id = None
    g.user_role = None
    g.group_id = None
    g.username = None
    g.user_name = None  # for older templates

    if user_id is None:
        return

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT username, email, user_role, group_id, activate FROM users WHERE id=%s;",
            (user_id,),
        )
        user = cur.fetchone()
        if not user:
            session.clear()
            return
        if not user["activate"]:
            # Allow hitting pending page
            session["username"] = user["username"]
            return
        g.user_id = user_id
        g.user_role = user["user_role"]
        g.group_id = user["group_id"]
        g.username = user["username"]
        g.user_name = user["username"]
    except Exception as e:
        print(f"before_request DB error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

# -------------------------------------------------
# Utility: Exchange rates
# -------------------------------------------------
def get_exchange_rate(from_currency: str, to_currency: str = "USD") -> float:
    """
    Returns the rate for: 1 {from_currency} = ? {to_currency}
    Uses API first; if it fails, falls back to 83 for USD<->INR and 1.0 otherwise.
    """
    if from_currency == to_currency:
        return 1.0

    # Preferred API: Exchangerate-API (v6)
    try:
        if EXCHANGE_RATE_API_KEY:
            url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/latest/{from_currency}"
            resp = requests.get(url, timeout=5)
            resp.raise_for_status()
            data = resp.json()
            if data.get("result") == "success":
                rate = data["conversion_rates"].get(to_currency)
                if rate and rate > 0:
                    return float(rate)
        else:
            # Fallback public endpoint (USD base); limited but fine for USD/INR pair
            if from_currency.upper() == "USD":
                r = requests.get("https://api.exchangerate-api.com/v4/latest/USD", timeout=5).json()
                rate = r.get("rates", {}).get(to_currency.upper())
                if rate and rate > 0:
                    return float(rate)
    except Exception as e:
        print(f"Exchange API error: {e}", file=sys.stderr)

    # Hard fallbacks
    if from_currency.upper() == "USD" and to_currency.upper() == "INR":
        return 83.0
    if from_currency.upper() == "INR" and to_currency.upper() == "USD":
        return 1.0 / 83.0

    return 1.0

def convert_to_usd(amount, currency: str) -> float:
    """
    Convert an amount in {currency} to USD.
    Correct behavior: amount * (rate for 1 currency -> USD).
    """
    if amount is None:
        return 0.0
    try:
        amt = float(amount)
    except Exception:
        return 0.0

    if (currency or "").upper() == "USD":
        return amt

    rate = get_exchange_rate((currency or "").upper(), "USD")
    return amt * (rate if rate else 0.0)

# -------------------------------------------------
# Common choice lists
# -------------------------------------------------
def get_common_lists():
    return {
        "currencies": ["USD", "EUR", "INR", "GBP", "JPY", "CAD"],
        "expense_categories": ["Travel", "Food", "Utilities", "Software", "Salary", "Misc"],
        "asset_types": ["Bank Account", "Brokerage", "Mutual Fund", "Stock", "Bond", "Insurance", "Real Estate", "Crypto", "Other"],
        "countries": ["USA", "India", "UK", "Canada", "Germany", "Japan", "Australia"],
        "owners": [{"id": 1, "name": "Primary"}, {"id": 2, "name": "Spouse"}, {"id": 3, "name": "Child"}],
    }

# -------------------------------------------------
# Health check
# -------------------------------------------------
@app.route("/healthz")
def healthz():
    return "ok", 200

# -------------------------------------------------
# Home / Dashboard
# -------------------------------------------------
@app.route("/")
@auth_required
def home():
    summary = {
        "total_assets_usd": 0.0,
        "total_expenses_usd": 0.0,
        "total_assets_inr": "N/A",
        "total_expenses_inr": "N/A",
        "net_balance_usd": 0.0,
        "net_balance_inr": "N/A",
    }
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        usd_to_inr = get_exchange_rate("USD", "INR")
        gf, gp = get_group_filter_clause(g.user_role, g.group_id)

        cur.execute(f"SELECT COALESCE(current_value, value) AS amount, currency FROM assets WHERE activate=TRUE {gf};", gp)
        assets = cur.fetchall()

        cur.execute(f"SELECT amount, currency FROM expenses WHERE activate=TRUE {gf};", gp)
        expenses = cur.fetchall()

        a_total = sum(convert_to_usd(a["amount"], a["currency"]) for a in assets)
        e_total = sum(convert_to_usd(e["amount"], e["currency"]) for e in expenses)
        summary["total_assets_usd"] = a_total
        summary["total_expenses_usd"] = e_total
        summary["net_balance_usd"] = a_total - e_total

        if usd_to_inr and usd_to_inr > 0:
            summary["total_assets_inr"] = a_total * usd_to_inr
            summary["total_expenses_inr"] = e_total * usd_to_inr
            summary["net_balance_inr"] = summary["net_balance_usd"] * usd_to_inr
    except Exception as e:
        flash(f"Error loading dashboard: {e}", "error")
        print(f"home error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

    return render_template("home.html", summary=summary, user_role=g.user_role, group_id=g.group_id)

# Keep /dashboard but reuse the working home
@app.route("/dashboard")
@auth_required
def dashboard():
    return redirect(url_for("home"))

# -------------------------------------------------
# Auth
# -------------------------------------------------
@limiter.limit("5 per minute")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, username, password_hash, activate FROM users WHERE lower(username)=lower(%s);", (username,))
            user = cur.fetchone()
            if user and bcrypt.check_password_hash(user["password_hash"], password):
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                if not user["activate"]:
                    return redirect(url_for("pending_approval"))
                flash("Login successful.", "success")
                return redirect(url_for("home"))
            flash("Invalid username or password.", "error")
        except Exception as e:
            print(f"login error: {e}", file=sys.stderr)
            flash("Login failed.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template("login.html")

@limiter.limit("3 per minute")
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        email = username  # treat username as email
        phash = bcrypt.generate_password_hash(password).decode("utf-8")
        role = "Member"
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)

            # pre-check for better UX
            cur.execute("SELECT id, activate FROM users WHERE lower(username)=lower(%s);", (username,))
            existing = cur.fetchone()
            if existing:
                if not existing["activate"]:
                    flash("This account exists but is pending approval.", "warning")
                    session["user_id"] = existing["id"]
                    session["username"] = username
                    return redirect(url_for("pending_approval"))
                flash("That username already exists. Try Forgot Password.", "error")
                return render_template("register.html")

            cur2 = conn.cursor()
            cur2.execute("""
                INSERT INTO users (username, email, password_hash, user_role, group_id, activate)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (username, email, phash, role, None, False))
            new_id_row = cur2.fetchone()
            conn.commit()

            # store session
            new_id = new_id_row["id"] if isinstance(new_id_row, dict) else new_id_row[0]
            session["user_id"] = new_id
            session["username"] = username

            # 🔔 notify admins (best-effort; do not block flow)
            try:
                notify_admin_new_user(username=username, email=email)
            except Exception as e:
                print(f"notify_admin_new_user error: {e}", file=sys.stderr)

            return redirect(url_for("pending_approval"))

        except psycopg2.IntegrityError:
            flash("That username already exists.", "error")
        except Exception as e:
            print(f"register error: {e}", file=sys.stderr)
            flash("Registration failed.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template("register.html")


@app.route("/pending_approval")
@auth_required
def pending_approval():
    return render_template("pending_approval.html")

@app.route("/logout")
@auth_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# -------------------------------------------------
# Password reset via email
# -------------------------------------------------
def send_email(to_email, subject, html_body):
    if not (MAIL_SERVER and MAIL_USERNAME and MAIL_PASSWORD):
        print("SMTP not configured; email skipped.", file=sys.stderr)
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_SENDER
    msg["To"] = to_email
    msg.set_content("Please view this message in an HTML-capable client.")
    msg.add_alternative(html_body, subtype="html")
    try:
        if MAIL_USE_TLS:
            server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email send failed: {e}", file=sys.stderr)
        return False

@limiter.limit("5 per hour")
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username") or ""
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, email FROM users WHERE lower(username)=lower(%s);", (username,))
            user = cur.fetchone()
            if not user:
                flash("If the account exists, a reset link has been sent.", "success")
                return render_template("forgot_password.html")

            token = secrets.token_urlsafe(32)
            expiration = datetime.now() + timedelta(hours=1)
            cur2 = conn.cursor()
            cur2.execute("UPDATE users SET reset_token=%s, token_expiration=%s WHERE id=%s;", (token, expiration, user["id"]))
            conn.commit()

            reset_url = urljoin(request.url_root, url_for("reset_password", token=token))
            html = f"""
                <h3>Password Reset</h3>
                <p>Click to reset your password (valid for 1 hour):</p>
                <p><a href="{reset_url}">{reset_url}</a></p>
            """
            ok = send_email(user["email"] or username, "Password Reset", html)
            flash("Password reset link sent!" if ok else "Email send failed (SMTP not configured).", "success" if ok else "error")
        except Exception as e:
            print(f"forgot_password error: {e}", file=sys.stderr)
            flash("Error generating reset link.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template("forgot_password.html")

@limiter.limit("5 per hour")
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE reset_token=%s AND token_expiration > NOW();", (token,))
        user = cur.fetchone()
        if not user:
            flash("Invalid or expired token.", "error")
            return redirect(url_for("login"))
        if request.method == "POST":
            password = request.form.get("password") or ""
            phash = bcrypt.generate_password_hash(password).decode("utf-8")
            cur2 = conn.cursor()
            cur2.execute("UPDATE users SET password_hash=%s, reset_token=NULL, token_expiration=NULL WHERE id=%s;", (phash, user["id"]))
            conn.commit()
            flash("Password reset successful.", "success")
            return redirect(url_for("login"))
    except Exception as e:
        print(f"reset_password error: {e}", file=sys.stderr)
        flash("Password reset failed.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template("reset_password.html")

# -------------------------------------------------
# Profile & Change password
# -------------------------------------------------
@app.route("/profile")
@auth_required
def profile():
    conn = None
    user = {"username": g.username, "email": None, "group_id": g.group_id}
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT username, email, group_id FROM users WHERE id=%s;", (g.user_id,))
        row = cur.fetchone()
        if row:
            user = row
    except Exception as e:
        print(f"profile error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template("profile.html", user=user)

@app.route("/change_password", methods=["GET", "POST"])
@auth_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if new != confirm:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html")
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT password_hash FROM users WHERE id=%s;", (g.user_id,))
            row = cur.fetchone()
            if not row or not bcrypt.check_password_hash(row["password_hash"], current):
                flash("Current password is incorrect.", "error")
                return render_template("change_password.html")
            new_hash = bcrypt.generate_password_hash(new).decode("utf-8")
            cur2 = conn.cursor()
            cur2.execute("UPDATE users SET password_hash=%s WHERE id=%s;", (new_hash, g.user_id))
            conn.commit()
            flash("Password updated.", "success")
            return redirect(url_for("profile"))
        except Exception as e:
            print(f"change_password error: {e}", file=sys.stderr)
            flash("Password change failed.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template("change_password.html")

# -------------------------------------------------
# Group management
# -------------------------------------------------
@app.route("/group")
@auth_required
def group_management():
    is_default = g.group_id is None
    return render_template("group_management.html", username=g.username, group_id=g.group_id, is_default_group=is_default)

@limiter.limit("10 per hour")
@app.route("/create_group", methods=["POST"])
@auth_required
def create_group():
    new_gid = f"family-{secrets.token_urlsafe(4)}"
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET group_id=%s WHERE id=%s;", (new_gid, g.user_id))
        conn.commit()
        flash("New group created.", "success")
    except Exception as e:
        print(f"create_group error: {e}", file=sys.stderr)
        flash("Failed to create group.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for("group_management"))

@limiter.limit("10 per hour")
@app.route("/join_group", methods=["POST"])
@auth_required
def join_group():
    target_gid = request.form.get("target_group_id")
    if not target_gid:
        flash("Group ID required.", "error")
        return redirect(url_for("group_management"))
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET group_id=%s WHERE id=%s;", (target_gid, g.user_id))
        conn.commit()
        flash("Joined group.", "success")
    except Exception as e:
        print(f"join_group error: {e}", file=sys.stderr)
        flash("Failed to join group.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for("group_management"))

# -------------------------------------------------
# Admin approval
# -------------------------------------------------
@limiter.limit("10 per hour")
@app.route("/admin/approve_users", methods=["GET", "POST"])
@auth_required
@admin_required
def admin_approve_users():
    conn = None
    try:
        conn = get_db_connection()
        if request.method == "POST":
            user_id = request.form.get("user_id")
            group_id = request.form.get("group_id")
            cur = conn.cursor()
            cur.execute("UPDATE users SET activate=TRUE, group_id=%s WHERE id=%s;", (group_id, user_id))
            conn.commit()
            flash("User approved and group assigned.", "success")
            return redirect(url_for("admin_approve_users"))

        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username FROM users WHERE activate=FALSE;")
        pending = cur.fetchall()
        return render_template("admin_approve_users.html", pending_users=pending)
    except Exception as e:
        print(f"admin_approve_users error: {e}", file=sys.stderr)
        flash("Admin action failed.", "error")
        return redirect(url_for("home"))
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

# -------------------------------------------------
# Expenses
# -------------------------------------------------
@app.route("/expenses")
@auth_required
def expenses():
    conn = None
    rows = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        gf, gp = get_group_filter_clause(g.user_role, g.group_id, table_alias="e")
        cur.execute(f"""
            SELECT e.id, e.description, e.amount, e.currency, e.category, e.date_incurred AS expense_date, e.activate
            FROM expenses e
            WHERE e.activate=TRUE {gf}
            ORDER BY e.date_incurred DESC;
        """, gp)
        for r in cur.fetchall():
            rows.append({
                "id": r["id"],
                "description": dec(r["description"]) if r["description"] else "",
                "amount": float(r["amount"]) if r["amount"] is not None else None,
                "currency": r["currency"],
                "category": r["category"],
                "expense_date": r["expense_date"].strftime("%Y-%m-%d") if r["expense_date"] else "",
            })
    except Exception as e:
        print(f"expenses load error: {e}", file=sys.stderr)
        flash(f"Error loading expenses: {e}", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template("expenses.html", expenses=rows)

@app.route("/add_expense", methods=["GET", "POST"])
@auth_required
def add_expense():
    lists = get_common_lists()
    if request.method == "POST":
        description = request.form.get("description")
        amount = request.form.get("amount")
        currency = request.form.get("currency")
        category = request.form.get("category")
        expense_date = request.form.get("expense_date")
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by, activate)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE);
            """, (g.group_id, enc(description), amount, currency, category, expense_date, g.user_id))
            conn.commit()
            flash("Expense successfully added.", "success")
            return redirect(url_for("expenses"))
        except Exception as e:
            print(f"add_expense error: {e}", file=sys.stderr)
            flash(f"Error adding expense: {e}", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template("add_expense.html", categories=lists["expense_categories"], currencies=lists["currencies"])

@app.route("/edit_expense/<int:expense_id>", methods=["GET", "POST"])
@auth_required
def edit_expense(expense_id):
    lists = get_common_lists()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        gf, gp = get_group_filter_clause(g.user_role, g.group_id, table_alias="e")
        cur.execute(f"""
            SELECT e.id, e.description, e.amount, e.currency, e.category, e.date_incurred AS expense_date
            FROM expenses e
            WHERE e.id=%s AND e.activate=TRUE {gf};
        """, (expense_id,) + gp)
        expense = cur.fetchone()
        if not expense:
            flash("Expense not found or unauthorized.", "error")
            return redirect(url_for("expenses"))

        if request.method == "POST":
            description = request.form.get("description")
            amount = request.form.get("amount")
            currency = request.form.get("currency")
            category = request.form.get("category")
            expense_date = request.form.get("expense_date")
            cur2 = conn.cursor()
            cur2.execute(f"""
                UPDATE expenses
                SET description=%s, amount=%s, currency=%s, category=%s, date_incurred=%s
                WHERE id=%s AND activate=TRUE {gf};
            """, (enc(description), amount, currency, category, expense_date, expense_id) + gp)
            if cur2.rowcount == 0:
                flash("Update failed: not found or unauthorized.", "error")
            else:
                conn.commit()
                flash("Expense successfully updated.", "success")
                return redirect(url_for("expenses"))

        expense["description"] = dec(expense["description"])
        expense["amount"] = float(expense["amount"]) if expense["amount"] is not None else None
        expense["expense_date"] = expense["expense_date"].strftime("%Y-%m-%d") if expense["expense_date"] else ""
        return render_template("edit_expense.html", expense=expense, categories=lists["expense_categories"], currencies=lists["currencies"])
    except Exception as e:
        print(f"edit_expense error: {e}", file=sys.stderr)
        flash(f"Error editing expense: {e}", "error")
        return redirect(url_for("expenses"))
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

@app.route("/delete_expense/<int:expense_id>", methods=["POST"])
@auth_required
def delete_expense(expense_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        gf, gp = get_group_filter_clause(g.user_role, g.group_id)
        cur.execute(f"UPDATE expenses SET activate=FALSE WHERE id=%s {gf};", (expense_id,) + gp)
        if cur.rowcount == 0:
            flash("Delete failed: not found or unauthorized.", "error")
        else:
            conn.commit()
            flash("Expense removed.", "success")
    except Exception as e:
        print(f"delete_expense error: {e}", file=sys.stderr)
        flash(f"Error deleting expense: {e}", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for("expenses"))

# -------------------------------------------------
# Assets
# -------------------------------------------------
SENSITIVE_ASSET_FIELDS = ["account_no", "beneficiary_name", "contact_phone", "document_location", "description"]

@app.route("/assets")
@auth_required
def assets():
    conn = None
    rows = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        gf, gp = get_group_filter_clause(g.user_role, g.group_id, table_alias="a")
        cur.execute(f"""
            SELECT a.id, a.user_id, a.type, a.name, a.country, a.currency, a.value, a.account_no,
                   a.last_updated, a.notes, a.activate, a.owner, a.owner_id, a.financial_institution,
                   a.beneficiary_name, a.policy_or_plan_type, a.contact_phone, a.document_location,
                   a.investment_strategy, a.current_value, a.description, a.added_date, a.group_id
            FROM assets a
            WHERE a.activate=TRUE {gf}
            ORDER BY a.last_updated DESC NULLS LAST, a.added_date DESC NULLS LAST, a.id DESC;
        """, gp)
        rows = cur.fetchall()

        # Decrypt and format dates
        for r in rows:
            r["account_no"] = dec(r["account_no"])
            r["beneficiary_name"] = dec(r["beneficiary_name"])
            r["contact_phone"] = dec(r["contact_phone"])
            r["document_location"] = dec(r["document_location"])
            r["description"] = dec(r["description"])
            if r.get("last_updated"):
                r["last_updated"] = r["last_updated"].strftime("%Y-%m-%d")
            if r.get("added_date"):
                r["added_date"] = r["added_date"].strftime("%Y-%m-%d")
    except Exception as e:
        print(f"assets load error: {e}", file=sys.stderr)
        flash(f"Error loading assets: {e}", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

    # -------- USD equivalent (API with INR fallback to 83) --------
    inr_to_usd = None
    try:
        # Prefer your configured API key if present
        if EXCHANGE_RATE_API_KEY:
            usd_to_inr = get_exchange_rate("USD", "INR")  # this already uses API if available
            inr_to_usd = 1.0 / float(usd_to_inr) if usd_to_inr else 1.0 / 83.0
        else:
            res = requests.get("https://api.exchangerate-api.com/v4/latest/USD", timeout=5)
            data = res.json()
            usd_to_inr = data["rates"]["INR"]  # 1 USD = X INR
            inr_to_usd = 1.0 / float(usd_to_inr)
    except Exception as e:
        print("FX fetch failed; using fallback 1 USD = ₹83. Error:", e, file=sys.stderr)
        inr_to_usd = 1.0 / 83.0

    for r in rows:
        curr = (r.get("currency") or "").upper()
        try:
            val = float(r.get("current_value") or r.get("value") or 0.0)
        except Exception:
            val = 0.0

        if curr == "USD":
            r["usd_value"] = round(val, 2)
        elif curr == "INR":
            r["usd_value"] = round(val * inr_to_usd, 2)
        else:
            r["usd_value"] = None

    # -------- Sorting --------
    # ?sort=<field>&order=asc|desc
    sortable_fields = {
        "name", "type", "country", "currency", "last_updated",
        "usd_value", "current_value", "added_date"
    }
    sort_by = request.args.get("sort", "usd_value")
    order = request.args.get("order", "desc").lower()
    if sort_by not in sortable_fields:
        sort_by = "usd_value"
    if order not in ("asc", "desc"):
        order = "desc"

    reverse = (order == "desc")

    def sort_key(r):
        v = r.get(sort_by)
        if sort_by in ("usd_value", "current_value"):
            try:
                return float(v or 0.0)
            except Exception:
                return 0.0
        if sort_by in ("last_updated", "added_date"):
            return v or ""
        return (str(v or "")).lower()

    rows = sorted(rows, key=sort_key, reverse=reverse)

    return render_template("assets.html", assets=rows, sort_by=sort_by, order=order)

@app.route("/add_asset", methods=["GET", "POST"])
@auth_required
def add_asset():
    lists = get_common_lists()
    if request.method == "POST":
        owner_id = request.form.get("owner_id")
        atype = request.form.get("type")
        name = request.form.get("name")
        account_no = request.form.get("account_no")
        value = request.form.get("value")
        currency = request.form.get("currency")
        country = request.form.get("country")
        financial_institution = request.form.get("financial_institution")
        policy_or_plan_type = request.form.get("policy_or_plan_type")
        beneficiary_name = request.form.get("beneficiary_name")
        contact_phone = request.form.get("contact_phone")
        document_location = request.form.get("document_location")
        investment_strategy = request.form.get("investment_strategy")
        notes = request.form.get("notes")
        now = datetime.now()
        added_date = now.date()
        last_updated = now

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO assets
                    (user_id, type, name, country, currency, value, account_no, last_updated, notes, activate,
                     owner, owner_id, financial_institution, beneficiary_name, policy_or_plan_type, contact_phone,
                     document_location, investment_strategy, current_value, description, added_date, group_id)
                VALUES
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE,
                     %s, %s, %s, %s, %s, %s,
                     %s, %s, %s, %s, %s, %s);
            """, (
                g.user_id, atype, name, country, currency, value, enc(account_no), last_updated, notes,
                None, owner_id, enc(financial_institution), enc(beneficiary_name), policy_or_plan_type, enc(contact_phone),
                enc(document_location), investment_strategy, value, enc(""), added_date, g.group_id
            ))
            conn.commit()
            flash("Asset saved.", "success")
            return redirect(url_for("assets"))
        except Exception as e:
            print(f"add_asset error: {e}", file=sys.stderr)
            flash("Failed to save asset.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()

    return render_template(
        "add_asset.html",
        owners=lists["owners"],
        asset_types=lists["asset_types"],
        currencies=lists["currencies"],
        countries=lists["countries"],
    )

@app.route("/edit_asset/<int:asset_id>", methods=["GET", "POST"])
@auth_required
def edit_asset(asset_id):
    lists = get_common_lists()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        gf, gp = get_group_filter_clause(g.user_role, g.group_id, table_alias="a")
        cur.execute(f"""
            SELECT a.*
            FROM assets a
            WHERE a.id=%s AND a.activate=TRUE {gf};
        """, (asset_id,) + gp)
        asset = cur.fetchone()
        if not asset:
            flash("Asset not found or unauthorized.", "error")
            return redirect(url_for("assets"))

        if request.method == "POST":
            owner_id = request.form.get("owner_id")
            atype = request.form.get("type")
            name = request.form.get("name")
            account_no = request.form.get("account_no")
            value = request.form.get("value")
            currency = request.form.get("currency")
            country = request.form.get("country")
            financial_institution = request.form.get("financial_institution")
            policy_or_plan_type = request.form.get("policy_or_plan_type")
            beneficiary_name = request.form.get("beneficiary_name")
            contact_phone = request.form.get("contact_phone")
            document_location = request.form.get("document_location")
            investment_strategy = request.form.get("investment_strategy")
            notes = request.form.get("notes")
            last_updated = datetime.now()

            cur2 = conn.cursor()
            cur2.execute(f"""
                UPDATE assets
                SET owner_id=%s, type=%s, name=%s, account_no=%s, value=%s, currency=%s, country=%s,
                    financial_institution=%s, policy_or_plan_type=%s, beneficiary_name=%s, contact_phone=%s,
                    document_location=%s, investment_strategy=%s, notes=%s, last_updated=%s
                WHERE id=%s AND activate=TRUE {gf};
            """, (
                owner_id, atype, name, enc(account_no), value, currency, country,
                enc(financial_institution), policy_or_plan_type, enc(beneficiary_name), enc(contact_phone),
                enc(document_location), investment_strategy, notes, last_updated, asset_id
            ) + gp)
            if cur2.rowcount == 0:
                flash("Update failed: not found or unauthorized.", "error")
            else:
                conn.commit()
                flash("Asset updated.", "success")
                return redirect(url_for("assets"))

        # decrypt for form display
        for f in SENSITIVE_ASSET_FIELDS:
            asset[f] = dec(asset.get(f))
        return render_template(
            "edit_asset.html",
            asset=asset,
            owners=lists["owners"],
            asset_types=lists["asset_types"],
            currencies=lists["currencies"],
            countries=lists["countries"],
        )
    except Exception as e:
        print(f"edit_asset error: {e}", file=sys.stderr)
        flash("Failed to load asset.", "error")
        return redirect(url_for("assets"))
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

@app.route("/delete_asset/<int:asset_id>", methods=["POST"])
@auth_required
def delete_asset(asset_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        gf, gp = get_group_filter_clause(g.user_role, g.group_id)
        cur.execute(f"UPDATE assets SET activate=FALSE WHERE id=%s {gf};", (asset_id,) + gp)
        if cur.rowcount == 0:
            flash("Delete failed: not found or unauthorized.", "error")
        else:
            conn.commit()
            flash("Asset removed.", "success")
    except Exception as e:
        print(f"delete_asset error: {e}", file=sys.stderr)
        flash("Failed to delete asset.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for("assets"))

# comma-separated list of admin emails to notify
ADMIN_NOTIFY_EMAILS = [
    e.strip() for e in os.environ.get("ADMIN_NOTIFY_EMAILS", "").split(",")
    if e.strip()
]

def notify_admin_new_user(username: str, email: str | None):
    """Email all admins when a new user registers."""
    if not ADMIN_NOTIFY_EMAILS:
        return  # nothing to do

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    ua = request.headers.get("User-Agent", "unknown")
    when = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    subject = f"[Family Finance] New user registration: {username}"
    html = f"""
        <h2>New User Registration</h2>
        <p><strong>Username:</strong> {username}</p>
        <p><strong>Email:</strong> {email or username}</p>
        <p><strong>When (UTC):</strong> {when}</p>
        <p><strong>IP:</strong> {ip}</p>
        <p><strong>User-Agent:</strong> {ua}</p>
        <hr>
        <p>This user is pending approval. You can approve and assign a group in the Admin page.</p>
    """
    for admin_addr in ADMIN_NOTIFY_EMAILS:
        try:
            send_email(admin_addr, subject, html)
        except Exception as e:
            print(f"admin notify failed to {admin_addr}: {e}", file=sys.stderr)

# -------------------------------------------------
# Dev helper: init_db (optional, dangerous in prod)
# -------------------------------------------------
@app.route("/init_db")
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
        DROP TABLE IF EXISTS expenses;
        DROP TABLE IF EXISTS assets;
        DROP TABLE IF EXISTS users;

        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(100),
            password_hash VARCHAR(128) NOT NULL,
            user_role VARCHAR(50) NOT NULL DEFAULT 'Member',
            group_id VARCHAR(100),
            reset_token TEXT,
            token_expiration TIMESTAMP,
            activate BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE expenses (
            id SERIAL PRIMARY KEY,
            group_id VARCHAR(100),
            description TEXT NOT NULL,
            amount NUMERIC(15, 2) NOT NULL,
            currency VARCHAR(10) NOT NULL,
            category VARCHAR(50) NOT NULL,
            date_incurred DATE NOT NULL,
            created_by INTEGER REFERENCES users(id),
            activate BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE assets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            type VARCHAR(100),
            name VARCHAR(255),
            country VARCHAR(100),
            currency VARCHAR(10),
            value NUMERIC(15,2),
            account_no TEXT,
            last_updated TIMESTAMP,
            notes TEXT,
            activate BOOLEAN NOT NULL DEFAULT TRUE,
            owner VARCHAR(100),
            owner_id INTEGER,
            financial_institution TEXT,
            beneficiary_name TEXT,
            policy_or_plan_type VARCHAR(100),
            contact_phone TEXT,
            document_location TEXT,
            investment_strategy TEXT,
            current_value NUMERIC(15,2),
            description TEXT,
            added_date DATE,
            group_id VARCHAR(100)
        );
        """)

        # seed admin
        sample_hash = bcrypt.generate_password_hash("password").decode("utf-8")
        cur.execute("""
            INSERT INTO users (username, email, password_hash, user_role, group_id, activate)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id;
        """, ("admin", "admin@example.com", sample_hash, "Admin", "family-demo", True))
        admin_id = cur.fetchone()[0]

        # sample expense
        cur.execute("""
            INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """, ("family-demo", enc("Office Rental Payment"), 1200.00, "USD", "Utilities", datetime.now().date(), admin_id))

        # sample asset
        cur.execute("""
            INSERT INTO assets (user_id, type, name, country, currency, value, account_no, last_updated, notes, owner, owner_id,
                                financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location,
                                investment_strategy, current_value, description, added_date, group_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s);
        """, (admin_id, "Bank Account", "Checking - Demo", "USA", "USD", 5000.00, enc("****1234"),
              "Sample notes", "Admin User", 1, enc("Demo Bank"), enc("Spouse"),
              "Checking", enc("+1-800-111-2222"), enc("Locker A1"),
              "Keep $3k buffer", 5000.00, enc("Main household account"),
              datetime.now().date(), "family-demo"))

        conn.commit()
        return "Initialized. Admin login: admin / password"
    except Exception as e:
        print(f"init_db error: {e}", file=sys.stderr)
        return f"init_db failed: {e}", 500
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

# -------------------------------------------------
# Entrypoint
# -------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)

