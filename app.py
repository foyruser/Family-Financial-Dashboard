from flask import Flask, render_template, request, redirect, url_for, session, g, flash, abort
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
import json
from psycopg2.extras import RealDictCursor
from email.message import EmailMessage
from datetime import datetime, timedelta
from urllib.parse import urljoin

from cryptography.fernet import Fernet

# -------------------------------------------------
# App & Config
# -------------------------------------------------
app = Flask(__name__)

# Require secret keys (no fallback in production)
secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY")
if not secret_key:
    if os.environ.get("FLASK_ENV") == "development":
        secret_key = "dev_secret_key_change_in_production"
    else:
        raise RuntimeError("SECRET_KEY environment variable must be set in production")
app.secret_key = secret_key

# Secure cookies (always secure except explicit dev mode)
is_dev = os.environ.get("FLASK_ENV") == "development"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=not is_dev,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

# Respect proxy headers for real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

DATABASE_URL = os.environ.get("DATABASE_URL")
EXCHANGE_RATE_API_KEY = os.environ.get("EXCHANGE_RATE_API_KEY", "")

# Require FERNET_KEY in production
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    if is_dev:
        print("WARNING: Using dev FERNET_KEY. Generate production key with:", file=sys.stderr)
        print("  python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'", file=sys.stderr)
        FERNET_KEY = Fernet.generate_key().decode()
    else:
        raise RuntimeError("FERNET_KEY environment variable must be set in production")

MAIL_SERVER = os.environ.get("MAIL_SERVER")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_USE_TLS = (os.environ.get("MAIL_USE_TLS", "true").lower() == "true")
MAIL_SENDER = os.environ.get("MAIL_SENDER", MAIL_USERNAME or "no-reply@example.com")

ADMIN_NOTIFY_EMAILS = [
    e.strip() for e in os.environ.get("ADMIN_NOTIFY_EMAILS", "").split(",")
    if e.strip()
]

# -------------------------------------------------
# Security Headers
# -------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    if not is_dev:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# -------------------------------------------------
# Audit Logging
# -------------------------------------------------
def audit_log(action, resource_type, resource_id=None, details=None, success=True):
    """Log security-relevant events"""
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'user_id': getattr(g, 'user_id', None),
        'username': getattr(g, 'username', None),
        'action': action,
        'resource_type': resource_type,
        'resource_id': resource_id,
        'ip': request.headers.get('X-Forwarded-For', request.remote_addr),
        'user_agent': request.headers.get('User-Agent', '')[:200],
        'success': success,
        'details': details
    }
    print(json.dumps(log_entry), file=sys.stderr)

# -------------------------------------------------
# Encryption helper
# -------------------------------------------------
class Encryptor:
    def __init__(self, key: str):
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
    return s

# -------------------------------------------------
# Input Validation
# -------------------------------------------------
def validate_currency(currency):
    """Validate currency code"""
    valid = ["USD", "EUR", "INR", "GBP", "JPY", "CAD"]
    if not currency or currency not in valid:
        raise ValueError(f"Invalid currency. Must be one of: {', '.join(valid)}")
    return currency

def validate_amount(amount):
    """Validate monetary amount"""
    try:
        val = float(amount)
        if val < 0:
            raise ValueError("Amount cannot be negative")
        if val > 999999999.99:
            raise ValueError("Amount exceeds maximum allowed value")
        return val
    except (TypeError, ValueError) as e:
        raise ValueError(f"Invalid amount: {e}")

def validate_category(category):
    """Validate expense category"""
    valid = ["Travel", "Food", "Utilities", "Software", "Salary", "Misc"]
    if not category or category not in valid:
        raise ValueError(f"Invalid category. Must be one of: {', '.join(valid)}")
    return category

def validate_asset_type(asset_type):
    """Validate asset type"""
    valid = ["Bank Account", "Brokerage", "Mutual Fund", "Stock", "Bond", 
             "Insurance", "Real Estate", "Crypto", "Other"]
    if not asset_type or asset_type not in valid:
        raise ValueError(f"Invalid asset type. Must be one of: {', '.join(valid)}")
    return asset_type

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

# Improved auth decorators
def auth_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            audit_log("unauthorized_access_attempt", "endpoint", details=request.endpoint, success=False)
            flash("Please log in to access this page.", "info")
            return redirect(url_for("login"))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            audit_log("unauthorized_access_attempt", "admin_endpoint", details=request.endpoint, success=False)
            flash("Please log in.", "info")
            return redirect(url_for("login"))
        if g.user_role != "Admin":
            audit_log("unauthorized_admin_access", "admin_endpoint", details=request.endpoint, success=False)
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return view(**kwargs)
    return wrapped_view

def build_query_with_filters(base_query, user_role, group_id, additional_conditions=""):
    """
    Safely build queries with group filtering.
    Returns tuple of (query, params)
    """
    if user_role == "Admin":
        # Admin sees everything
        query = f"{base_query} {additional_conditions}"
        params = []
    elif group_id:
        # Member sees only their group
        query = f"{base_query} AND group_id = %s {additional_conditions}"
        params = [group_id]
    else:
        # No group = no access
        query = f"{base_query} AND 1=0 {additional_conditions}"
        params = []
    
    return query, tuple(params)

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
    g.user_name = None

    if user_id is None:
        return

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT username, email, user_role, group_id, activate FROM users WHERE id=%s;",
                (user_id,),
            )
            user = cur.fetchone()
            if not user:
                session.clear()
                return
            if not user["activate"]:
                session["username"] = user["username"]
                return
            g.user_id = user_id
            g.user_role = user["user_role"]
            g.group_id = user["group_id"]
            g.username = user["username"]
            g.user_name = user["username"]
    except Exception as e:
        print(f"before_request DB error: {e}", file=sys.stderr)
        session.clear()
    finally:
        if conn:
            conn.close()

# -------------------------------------------------
# Utility: Exchange rates
# -------------------------------------------------
def get_exchange_rate(from_currency: str, to_currency: str = "USD") -> float:
    """Returns the rate for: 1 {from_currency} = ? {to_currency}"""
    if from_currency == to_currency:
        return 1.0

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
    """Convert an amount in {currency} to USD."""
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
# Email utilities
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

def notify_user_approved(username: str, email: str | None, group_id: str | None):
    """Send confirmation email when admin approves account."""
    to_addr = (email or username or "").strip()
    if not to_addr:
        return False

    subject = "[Family Finance] Your account has been approved"
    html = f"""
        <h2>Welcome!</h2>
        <p>Hi <strong>{username}</strong>,</p>
        <p>Your account has been <strong>approved</strong> and activated.</p>
        <p>{'You were assigned to group: <strong>' + group_id + '</strong>.' if group_id else ''}</p>
        <p>You can now sign in here:</p>
        <p><a href="{request.url_root.rstrip('/')}">{request.url_root.rstrip('/')}</a></p>
        <hr>
        <p>This is an automated message. If you didn't request this, please ignore.</p>
    """
    return send_email(to_addr, subject, html)

def notify_admin_new_user(username: str, email: str | None):
    """Email all admins when a new user registers."""
    if not ADMIN_NOTIFY_EMAILS:
        return

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
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            usd_to_inr = get_exchange_rate("USD", "INR")
            
            # Build safe queries
            asset_query, asset_params = build_query_with_filters(
                "SELECT COALESCE(current_value, value) AS amount, currency FROM assets WHERE activate=TRUE",
                g.user_role, g.group_id
            )
            expense_query, expense_params = build_query_with_filters(
                "SELECT amount, currency FROM expenses WHERE activate=TRUE",
                g.user_role, g.group_id
            )

            cur.execute(asset_query, asset_params)
            assets = cur.fetchall()

            cur.execute(expense_query, expense_params)
            expenses = cur.fetchall()

            a_total = sum(convert_to_usd(a["amount"], a["currency"]) for a in assets)
            e_total = sum(convert_to_usd(e["amount"], e["currency"]) for e in expenses)
            
            summary["total_assets_usd"] = round(a_total, 2)
            summary["total_expenses_usd"] = round(e_total, 2)
            summary["net_balance_usd"] = round(a_total - e_total, 2)

            if usd_to_inr and usd_to_inr > 0:
                summary["total_assets_inr"] = round(a_total * usd_to_inr, 2)
                summary["total_expenses_inr"] = round(e_total * usd_to_inr, 2)
                summary["net_balance_inr"] = round(summary["net_balance_usd"] * usd_to_inr, 2)
    except Exception as e:
        audit_log("dashboard_load_error", "dashboard", success=False)
        flash("Error loading dashboard. Please try again.", "error")
        print(f"home error: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()

    return render_template("home.html", summary=summary, user_role=g.user_role, group_id=g.group_id)

@app.route("/dashboard")
@auth_required
def dashboard():
    return redirect(url_for("home"))

# -------------------------------------------------
# Auth
# -------------------------------------------------
@limiter.limit("3 per minute;10 per hour;50 per day")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT id, username, password_hash, activate FROM users WHERE lower(username)=lower(%s);",
                    (username,)
                )
                user = cur.fetchone()
                
                if user and bcrypt.check_password_hash(user["password_hash"], password):
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session.permanent = True
                    
                    if not user["activate"]:
                        audit_log("login_pending_approval", "user", user["id"])
                        return redirect(url_for("pending_approval"))
                    
                    audit_log("login_success", "user", user["id"])
                    flash("Login successful.", "success")
                    return redirect(url_for("home"))
                
                audit_log("login_failed", "user", details=f"username: {username}", success=False)
                flash("Invalid username or password.", "error")
        except Exception as e:
            print(f"login error: {e}", file=sys.stderr)
            flash("Login failed. Please try again.", "error")
        finally:
            if conn:
                conn.close()
    
    return render_template("login.html")

@limiter.limit("2 per minute;5 per hour;10 per day")
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""
        
        # Validate input
        if len(username) < 3 or len(username) > 100:
            flash("Username must be between 3 and 100 characters.", "error")
            return render_template("register.html")
        
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")
        
        email = username
        phash = bcrypt.generate_password_hash(password).decode("utf-8")
        role = "Member"
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Try to insert directly (atomic operation)
                try:
                    cur.execute("""
                        INSERT INTO users (username, email, password_hash, user_role, group_id, activate)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id;
                    """, (username, email, phash, role, None, False))
                    new_user = cur.fetchone()
                    conn.commit()
                    
                    new_id = new_user["id"]
                    session["user_id"] = new_id
                    session["username"] = username
                    
                    audit_log("user_registered", "user", new_id)
                    
                    # Notify admins (best-effort)
                    try:
                        notify_admin_new_user(username=username, email=email)
                    except Exception as e:
                        print(f"notify_admin_new_user error: {e}", file=sys.stderr)
                    
                    return redirect(url_for("pending_approval"))
                    
                except psycopg2.IntegrityError:
                    conn.rollback()
                    # Check if user exists and is pending
                    cur.execute(
                        "SELECT id, activate FROM users WHERE lower(username)=lower(%s);",
                        (username,)
                    )
                    existing = cur.fetchone()
                    if existing and not existing["activate"]:
                        flash("This account exists but is pending approval.", "warning")
                        session["user_id"] = existing["id"]
                        session["username"] = username
                        return redirect(url_for("pending_approval"))
                    flash("That username already exists. Try Forgot Password if this is your account.", "error")
                    
        except Exception as e:
            print(f"register error: {e}", file=sys.stderr)
            flash("Registration failed. Please try again.", "error")
        finally:
            if conn:
                conn.close()
    
    return render_template("register.html")

@app.route("/pending_approval")
@auth_required
def pending_approval():
    return render_template("pending_approval.html")

@app.route("/logout")
@auth_required
def logout():
    user_id = g.user_id
    session.clear()
    audit_log("logout", "user", user_id)
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# -------------------------------------------------
# Password reset
# -------------------------------------------------
@limiter.limit("3 per hour")
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username") or ""
        
        # Always perform hash operation to prevent timing attacks
        dummy_hash = bcrypt.generate_password_hash("dummy_password_for_timing")
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT id, email FROM users WHERE lower(username)=lower(%s);",
                    (username,)
                )
                user = cur.fetchone()
                
                if user:
                    token = secrets.token_urlsafe(32)
                    expiration = datetime.now() + timedelta(hours=1)
                    cur.execute(
                        "UPDATE users SET reset_token=%s, token_expiration=%s WHERE id=%s;",
                        (token, expiration, user["id"])
                    )
                    conn.commit()
                    
                    reset_url = urljoin(request.url_root, url_for("reset_password", token=token))
                    html = f"""
                        <h3>Password Reset</h3>
                        <p>Click to reset your password (valid for 1 hour):</p>
                        <p><a href="{reset_url}">{reset_url}</a></p>
                    """
                    send_email(user["email"] or username, "Password Reset", html)
                    audit_log("password_reset_requested", "user", user["id"])
                else:
                    # Generate dummy token for timing consistency
                    _ = secrets.token_urlsafe(32)
                    audit_log("password_reset_failed", "user", details=f"username: {username}", success=False)
                
                # Always show same message
                flash("If the account exists, a reset link has been sent to your email.", "success")
        except Exception as e:
            print(f"forgot_password error: {e}", file=sys.stderr)
            flash("Error processing request. Please try again.", "error")
        finally:
            if conn:
                conn.close()
    
    return render_template("forgot_password.html")

@limiter.limit("5 per hour")
@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id FROM users WHERE reset_token=%s AND token_expiration > NOW();",
                (token,)
            )
            user = cur.fetchone()
            
            if not user:
                flash("Invalid or expired reset link.", "error")
                return redirect(url_for("login"))
            
            if request.method == "POST":
                password = request.form.get("password") or ""
                
                if len(password) < 8:
                    flash("Password must be at least 8 characters.", "error")
                    return render_template("reset_password.html")
                
                phash = bcrypt.generate_password_hash(password).decode("utf-8")
                cur.execute(
                    "UPDATE users SET password_hash=%s, reset_token=NULL, token_expiration=NULL WHERE id=%s;",
                    (phash, user["id"])
                )
                conn.commit()
                
                audit_log("password_reset_completed", "user", user["id"])
                flash("Password reset successful. Please log in.", "success")
                return redirect(url_for("login"))
    except Exception as e:
        print(f"reset_password error: {e}", file=sys.stderr)
        flash("Password reset failed. Please try again.", "error")
    finally:
        if conn:
            conn.close()
    
    return render_template("reset_password.html")

# -------------------------------------------------
# Profile
# -------------------------------------------------
@app.route("/profile")
@auth_required
def profile():
    conn = None
    user = {"username": g.username, "email": None, "group_id": g.group_id}
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT username, email, group_id FROM users WHERE id=%s;",
                (g.user_id,)
            )
            row = cur.fetchone()
            if row:
                user = row
    except Exception as e:
        print(f"profile error: {e}", file=sys.stderr)
    finally:
        if conn:
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
        
        if len(new) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("change_password.html")
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT password_hash FROM users WHERE id=%s;",
                    (g.user_id,)
                )
                row = cur.fetchone()
                
                if not row or not bcrypt.check_password_hash(row["password_hash"], current):
                    flash("Current password is incorrect.", "error")
                    return render_template("change_password.html")
                
                new_hash = bcrypt.generate_password_hash(new).decode("utf-8")
                cur.execute(
                    "UPDATE users SET password_hash=%s WHERE id=%s;",
                    (new_hash, g.user_id)
                )
                conn.commit()
                
                audit_log("password_changed", "user", g.user_id)
                flash("Password updated successfully.", "success")
                return redirect(url_for("profile"))
        except Exception as e:
            print(f"change_password error: {e}", file=sys.stderr)
            flash("Password change failed. Please try again.", "error")
        finally:
            if conn:
                conn.close()
    
    return render_template("change_password.html")

# -------------------------------------------------
# Group management
# -------------------------------------------------
@app.route("/group")
@auth_required
def group_management():
    is_default = g.group_id is None
    return render_template("group_management.html", username=g.username, 
                         group_id=g.group_id, is_default_group=is_default)

@limiter.limit("5 per hour")
@app.route("/create_group", methods=["POST"])
@auth_required
def create_group():
    new_gid = f"family-{secrets.token_urlsafe(8)}"
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET group_id=%s WHERE id=%s;",
                (new_gid, g.user_id)
            )
            conn.commit()
        
        audit_log("group_created", "group", details=new_gid)
        flash(f"New group created: {new_gid}", "success")
    except Exception as e:
        print(f"create_group error: {e}", file=sys.stderr)
        flash("Failed to create group. Please try again.", "error")
    finally:
        if conn:
            conn.close()
    
    return redirect(url_for("group_management"))

@limiter.limit("5 per hour")
@app.route("/join_group", methods=["POST"])
@auth_required
def join_group():
    target_gid = (request.form.get("target_group_id") or "").strip()
    
    if not target_gid:
        flash("Group ID required.", "error")
        return redirect(url_for("group_management"))
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET group_id=%s WHERE id=%s;",
                (target_gid, g.user_id)
            )
            conn.commit()
        
        audit_log("group_joined", "group", details=target_gid)
        flash(f"Joined group: {target_gid}", "success")
    except Exception as e:
        print(f"join_group error: {e}", file=sys.stderr)
        flash("Failed to join group. Please try again.", "error")
    finally:
        if conn:
            conn.close()
    
    return redirect(url_for("group_management"))

# -------------------------------------------------
# Admin
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
            group_id = (request.form.get("group_id") or "").strip() or None
            
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    UPDATE users
                       SET activate = TRUE,
                           group_id = %s
                     WHERE id = %s
                 RETURNING id, username, email, group_id;
                """, (group_id, user_id))
                updated = cur.fetchone()
                conn.commit()
                
                if not updated:
                    flash("User not found.", "error")
                    return redirect(url_for("admin_approve_users"))
                
                audit_log("user_approved", "user", user_id, details=f"group: {group_id}")
                
                # Email notification (best-effort)
                try:
                    sent = notify_user_approved(
                        username=updated.get("username"),
                        email=updated.get("email"),
                        group_id=updated.get("group_id"),
                    )
                    if sent:
                        flash(f"User {updated.get('username')} approved and notified.", "success")
                    else:
                        flash(f"User {updated.get('username')} approved (email not sent).", "warning")
                except Exception as e:
                    print(f"notify_user_approved error: {e}", file=sys.stderr)
                    flash("User approved, but notification failed.", "warning")
                
                return redirect(url_for("admin_approve_users"))
        
        # GET: list pending users
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, email, created_at FROM users WHERE activate = FALSE ORDER BY created_at ASC;"
            )
            pending = cur.fetchall()
        
        return render_template("admin_approve_users.html", pending_users=pending)
    
    except Exception as e:
        print(f"admin_approve_users error: {e}", file=sys.stderr)
        flash("Admin action failed. Please try again.", "error")
        return redirect(url_for("home"))
    finally:
        if conn:
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
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query, params = build_query_with_filters(
                """SELECT e.id, e.description, e.amount, e.currency, e.category, 
                          e.date_incurred AS expense_date, e.created_by, e.activate
                   FROM expenses e
                   WHERE e.activate=TRUE""",
                g.user_role, g.group_id,
                "ORDER BY e.date_incurred DESC"
            )
            
            cur.execute(query, params)
            for r in cur.fetchall():
                rows.append({
                    "id": r["id"],
                    "description": dec(r["description"]) if r["description"] else "",
                    "amount": float(r["amount"]) if r["amount"] is not None else 0.0,
                    "currency": r["currency"],
                    "category": r["category"],
                    "expense_date": r["expense_date"].strftime("%Y-%m-%d") if r["expense_date"] else "",
                })
    except Exception as e:
        print(f"expenses load error: {e}", file=sys.stderr)
        flash("Error loading expenses. Please try again.", "error")
    finally:
        if conn:
            conn.close()
    
    return render_template("expenses.html", expenses=rows)

@app.route("/add_expense", methods=["GET", "POST"])
@auth_required
def add_expense():
    lists = get_common_lists()
    
    if request.method == "POST":
        try:
            description = (request.form.get("description") or "").strip()
            amount = validate_amount(request.form.get("amount"))
            currency = validate_currency(request.form.get("currency"))
            category = validate_category(request.form.get("category"))
            expense_date = request.form.get("expense_date")
            notes = (request.form.get("notes") or "").strip() or None
            
            if not description:
                flash("Description is required.", "error")
                return render_template("add_expense.html", 
                                     categories=lists["expense_categories"],
                                     currencies=lists["currencies"])
            
            if not expense_date:
                flash("Expense date is required.", "error")
                return render_template("add_expense.html",
                                     categories=lists["expense_categories"],
                                     currencies=lists["currencies"])
            
            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO expenses (
                            created_by, group_id, description, amount, currency, 
                            category, date_incurred, notes, activate
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, TRUE)
                        RETURNING id;
                    """, (
                        g.user_id,
                        g.group_id,
                        enc(description),
                        amount,
                        currency,
                        category,
                        expense_date,
                        enc(notes) if notes else None
                    ))
                    new_id = cur.fetchone()[0]
                    conn.commit()
                
                audit_log("expense_created", "expense", new_id)
                flash("Expense added successfully.", "success")
                return redirect(url_for("expenses"))
            
            except Exception as e:
                print(f"add_expense DB error: {e}", file=sys.stderr)
                flash("Failed to add expense. Please try again.", "error")
            finally:
                if conn:
                    conn.close()
        
        except ValueError as e:
            flash(str(e), "error")
    
    return render_template(
        "add_expense.html",
        categories=lists["expense_categories"],
        currencies=lists["currencies"]
    )

@app.route("/edit_expense/<int:expense_id>", methods=["GET", "POST"])
@auth_required
def edit_expense(expense_id):
    lists = get_common_lists()
    conn = None
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Verify ownership/access
            query, params = build_query_with_filters(
                """SELECT e.id, e.description, e.amount, e.currency, e.category, 
                          e.date_incurred AS expense_date, e.created_by
                   FROM expenses e
                   WHERE e.id=%s AND e.activate=TRUE""",
                g.user_role, g.group_id
            )
            params = (expense_id,) + params
            
            cur.execute(query, params)
            expense = cur.fetchone()
            
            if not expense:
                flash("Expense not found or unauthorized.", "error")
                return redirect(url_for("expenses"))
            
            # Additional check: only creator or admin can edit
            if g.user_role != "Admin" and expense["created_by"] != g.user_id:
                audit_log("unauthorized_expense_edit_attempt", "expense", expense_id, success=False)
                flash("You can only edit your own expenses.", "error")
                return redirect(url_for("expenses"))
            
            if request.method == "POST":
                try:
                    description = (request.form.get("description") or "").strip()
                    amount = validate_amount(request.form.get("amount"))
                    currency = validate_currency(request.form.get("currency"))
                    category = validate_category(request.form.get("category"))
                    expense_date = request.form.get("expense_date")
                    
                    if not description or not expense_date:
                        flash("Description and date are required.", "error")
                        return render_template("edit_expense.html", expense=expense,
                                             categories=lists["expense_categories"],
                                             currencies=lists["currencies"])
                    
                    update_query, update_params = build_query_with_filters(
                        """UPDATE expenses
                           SET description=%s, amount=%s, currency=%s, category=%s, date_incurred=%s
                           WHERE id=%s AND activate=TRUE""",
                        g.user_role, g.group_id
                    )
                    update_params = (enc(description), amount, currency, category, expense_date, expense_id) + update_params
                    
                    cur.execute(update_query, update_params)
                    conn.commit()
                    
                    if cur.rowcount == 0:
                        flash("Update failed. Please try again.", "error")
                    else:
                        audit_log("expense_updated", "expense", expense_id)
                        flash("Expense updated successfully.", "success")
                        return redirect(url_for("expenses"))
                
                except ValueError as e:
                    flash(str(e), "error")
            
            # Decrypt for display
            expense["description"] = dec(expense["description"])
            expense["amount"] = float(expense["amount"]) if expense["amount"] is not None else 0.0
            expense["expense_date"] = expense["expense_date"].strftime("%Y-%m-%d") if expense["expense_date"] else ""
            
            return render_template("edit_expense.html", expense=expense,
                                 categories=lists["expense_categories"],
                                 currencies=lists["currencies"])
    
    except Exception as e:
        print(f"edit_expense error: {e}", file=sys.stderr)
        flash("Error loading expense. Please try again.", "error")
        return redirect(url_for("expenses"))
    finally:
        if conn:
            conn.close()

@app.route("/delete_expense/<int:expense_id>", methods=["POST"])
@auth_required
def delete_expense(expense_id):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # First verify ownership
            query, params = build_query_with_filters(
                "SELECT created_by FROM expenses WHERE id=%s AND activate=TRUE",
                g.user_role, g.group_id
            )
            params = (expense_id,) + params
            
            cur.execute(query, params)
            expense = cur.fetchone()
            
            if not expense:
                flash("Expense not found or unauthorized.", "error")
                return redirect(url_for("expenses"))
            
            # Only creator or admin can delete
            if g.user_role != "Admin" and expense["created_by"] != g.user_id:
                audit_log("unauthorized_expense_delete_attempt", "expense", expense_id, success=False)
                flash("You can only delete your own expenses.", "error")
                return redirect(url_for("expenses"))
            
            # Perform deletion
            delete_query, delete_params = build_query_with_filters(
                "UPDATE expenses SET activate=FALSE WHERE id=%s",
                g.user_role, g.group_id
            )
            delete_params = (expense_id,) + delete_params
            
            cur.execute(delete_query, delete_params)
            conn.commit()
            
            audit_log("expense_deleted", "expense", expense_id)
            flash("Expense deleted successfully.", "success")
    
    except Exception as e:
        print(f"delete_expense error: {e}", file=sys.stderr)
        flash("Failed to delete expense. Please try again.", "error")
    finally:
        if conn:
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
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            query, params = build_query_with_filters(
                """SELECT a.id, a.user_id, a.type, a.name, a.country, a.currency, a.value, a.account_no,
                          a.last_updated, a.notes, a.activate, a.owner, a.owner_id, a.financial_institution,
                          a.beneficiary_name, a.policy_or_plan_type, a.contact_phone, a.document_location,
                          a.investment_strategy, a.current_value, a.description, a.added_date, a.group_id
                   FROM assets a
                   WHERE a.activate=TRUE""",
                g.user_role, g.group_id,
                "ORDER BY a.last_updated DESC NULLS LAST, a.added_date DESC NULLS LAST, a.id DESC"
            )
            
            cur.execute(query, params)
            rows = cur.fetchall()
            
            # Decrypt sensitive fields
            for r in rows:
                r["account_no"] = dec(r["account_no"])
                r["beneficiary_name"] = dec(r["beneficiary_name"])
                r["contact_phone"] = dec(r["contact_phone"])
                r["document_location"] = dec(r["document_location"])
                r["description"] = dec(r["description"])
                r["financial_institution"] = dec(r.get("financial_institution"))
                
                if r.get("last_updated"):
                    r["last_updated"] = r["last_updated"].strftime("%Y-%m-%d")
                if r.get("added_date"):
                    r["added_date"] = r["added_date"].strftime("%Y-%m-%d")
    
    except Exception as e:
        print(f"assets load error: {e}", file=sys.stderr)
        flash("Error loading assets. Please try again.", "error")
    finally:
        if conn:
            conn.close()
    
    # Calculate USD equivalents
    inr_to_usd = 1.0 / 83.0
    try:
        if EXCHANGE_RATE_API_KEY:
            usd_to_inr = get_exchange_rate("USD", "INR")
            inr_to_usd = 1.0 / float(usd_to_inr) if usd_to_inr else 1.0 / 83.0
        else:
            res = requests.get("https://api.exchangerate-api.com/v4/latest/USD", timeout=5)
            data = res.json()
            usd_to_inr = data["rates"]["INR"]
            inr_to_usd = 1.0 / float(usd_to_inr)
    except Exception as e:
        print(f"FX fetch failed, using fallback: {e}", file=sys.stderr)
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
    
    # Sorting
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
        try:
            owner_id = request.form.get("owner_id")
            atype = validate_asset_type(request.form.get("type"))
            name = (request.form.get("name") or "").strip()
            account_no = (request.form.get("account_no") or "").strip()
            value = validate_amount(request.form.get("value"))
            currency = validate_currency(request.form.get("currency"))
            country = request.form.get("country")
            financial_institution = (request.form.get("financial_institution") or "").strip()
            policy_or_plan_type = (request.form.get("policy_or_plan_type") or "").strip()
            beneficiary_name = (request.form.get("beneficiary_name") or "").strip()
            contact_phone = (request.form.get("contact_phone") or "").strip()
            document_location = (request.form.get("document_location") or "").strip()
            investment_strategy = (request.form.get("investment_strategy") or "").strip()
            notes = (request.form.get("notes") or "").strip()
            
            if not name:
                flash("Asset name is required.", "error")
                return render_template("add_asset.html",
                                     owners=lists["owners"],
                                     asset_types=lists["asset_types"],
                                     currencies=lists["currencies"],
                                     countries=lists["countries"])
            
            now = datetime.now()
            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO assets
                            (user_id, type, name, country, currency, value, account_no, last_updated, notes, activate,
                             owner, owner_id, financial_institution, beneficiary_name, policy_or_plan_type, contact_phone,
                             document_location, investment_strategy, current_value, description, added_date, group_id)
                        VALUES
                            (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE,
                             %s, %s, %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s)
                        RETURNING id;
                    """, (
                        g.user_id, atype, name, country, currency, value, enc(account_no), now, notes,
                        None, owner_id, enc(financial_institution), enc(beneficiary_name), policy_or_plan_type, enc(contact_phone),
                        enc(document_location), investment_strategy, value, enc(""), now.date(), g.group_id
                    ))
                    new_id = cur.fetchone()[0]
                    conn.commit()
                
                audit_log("asset_created", "asset", new_id)
                flash("Asset added successfully.", "success")
                return redirect(url_for("assets"))
            
            except Exception as e:
                print(f"add_asset DB error: {e}", file=sys.stderr)
                flash("Failed to add asset. Please try again.", "error")
            finally:
                if conn:
                    conn.close()
        
        except ValueError as e:
            flash(str(e), "error")
    
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
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Verify ownership/access
            query, params = build_query_with_filters(
                "SELECT a.* FROM assets a WHERE a.id=%s AND a.activate=TRUE",
                g.user_role, g.group_id
            )
            params = (asset_id,) + params
            
            cur.execute(query, params)
            asset = cur.fetchone()
            
            if not asset:
                flash("Asset not found or unauthorized.", "error")
                return redirect(url_for("assets"))
            
            # Additional check: only creator or admin can edit
            if g.user_role != "Admin" and asset["user_id"] != g.user_id:
                audit_log("unauthorized_asset_edit_attempt", "asset", asset_id, success=False)
                flash("You can only edit your own assets.", "error")
                return redirect(url_for("assets"))
            
            if request.method == "POST":
                try:
                    owner_id = request.form.get("owner_id")
                    atype = validate_asset_type(request.form.get("type"))
                    name = (request.form.get("name") or "").strip()
                    account_no = (request.form.get("account_no") or "").strip()
                    value = validate_amount(request.form.get("value"))
                    currency = validate_currency(request.form.get("currency"))
                    country = request.form.get("country")
                    financial_institution = (request.form.get("financial_institution") or "").strip()
                    policy_or_plan_type = (request.form.get("policy_or_plan_type") or "").strip()
                    beneficiary_name = (request.form.get("beneficiary_name") or "").strip()
                    contact_phone = (request.form.get("contact_phone") or "").strip()
                    document_location = (request.form.get("document_location") or "").strip()
                    investment_strategy = (request.form.get("investment_strategy") or "").strip()
                    notes = (request.form.get("notes") or "").strip()
                    
                    if not name:
                        flash("Asset name is required.", "error")
                        return render_template("edit_asset.html", asset=asset,
                                             owners=lists["owners"],
                                             asset_types=lists["asset_types"],
                                             currencies=lists["currencies"],
                                             countries=lists["countries"])
                    
                    update_query, update_params = build_query_with_filters(
                        """UPDATE assets
                           SET owner_id=%s, type=%s, name=%s, account_no=%s, value=%s, currency=%s, country=%s,
                               financial_institution=%s, policy_or_plan_type=%s, beneficiary_name=%s, contact_phone=%s,
                               document_location=%s, investment_strategy=%s, notes=%s, last_updated=%s, current_value=%s
                           WHERE id=%s AND activate=TRUE""",
                        g.user_role, g.group_id
                    )
                    update_params = (
                        owner_id, atype, name, enc(account_no), value, currency, country,
                        enc(financial_institution), policy_or_plan_type, enc(beneficiary_name), enc(contact_phone),
                        enc(document_location), investment_strategy, notes, datetime.now(), value, asset_id
                    ) + update_params
                    
                    cur.execute(update_query, update_params)
                    conn.commit()
                    
                    if cur.rowcount == 0:
                        flash("Update failed. Please try again.", "error")
                    else:
                        audit_log("asset_updated", "asset", asset_id)
                        flash("Asset updated successfully.", "success")
                        return redirect(url_for("assets"))
                
                except ValueError as e:
                    flash(str(e), "error")
            
            # Decrypt for display
            for f in SENSITIVE_ASSET_FIELDS:
                if f in asset:
                    asset[f] = dec(asset.get(f))
            asset["financial_institution"] = dec(asset.get("financial_institution"))
            
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
        flash("Error loading asset. Please try again.", "error")
        return redirect(url_for("assets"))
    finally:
        if conn:
            conn.close()

@app.route("/delete_asset/<int:asset_id>", methods=["POST"])
@auth_required
def delete_asset(asset_id):
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # First verify ownership
            query, params = build_query_with_filters(
                "SELECT user_id FROM assets WHERE id=%s AND activate=TRUE",
                g.user_role, g.group_id
            )
            params = (asset_id,) + params
            
            cur.execute(query, params)
            asset = cur.fetchone()
            
            if not asset:
                flash("Asset not found or unauthorized.", "error")
                return redirect(url_for("assets"))
            
            # Only creator or admin can delete
            if g.user_role != "Admin" and asset["user_id"] != g.user_id:
                audit_log("unauthorized_asset_delete_attempt", "asset", asset_id, success=False)
                flash("You can only delete your own assets.", "error")
                return redirect(url_for("assets"))
            
            # Perform deletion
            delete_query, delete_params = build_query_with_filters(
                "UPDATE assets SET activate=FALSE WHERE id=%s",
                g.user_role, g.group_id
            )
            delete_params = (asset_id,) + delete_params
            
            cur.execute(delete_query, delete_params)
            conn.commit()
            
            audit_log("asset_deleted", "asset", asset_id)
            flash("Asset deleted successfully.", "success")
    
    except Exception as e:
        print(f"delete_asset error: {e}", file=sys.stderr)
        flash("Failed to delete asset. Please try again.", "error")
    finally:
        if conn:
            conn.close()
    
    return redirect(url_for("assets"))

# -------------------------------------------------
# Init DB (DANGEROUS - Development only)
# -------------------------------------------------
@app.route("/init_db", methods=["POST"])
@limiter.limit("1 per day")
def init_db():
