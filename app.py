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

# Rate Limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Email configuration
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
ADMIN_NOTIFY_EMAILS = [e.strip() for e in os.environ.get("ADMIN_NOTIFY_EMAILS", "").split(',') if e.strip()]
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000") # Required for email links

# -------------------------------------------------
# Security & Encryption Configuration
# -------------------------------------------------

# Get the encryption key from environment variables
FERNET_KEY = os.environ.get("FERNET_KEY", "A_FALLBACK_KEY_MUST_BE_32_URL_SAFE_BASE64_BYTES")
try:
    if len(FERNET_KEY) < 44: # Check if key is long enough for base64 decoding
        # This will fail on purpose if not set correctly to force user to set it
        raise ValueError("FERNET_KEY is missing or too short. Check environment variable.")
    F = Fernet(FERNET_KEY.encode())
except Exception as e:
    print(f"ERROR: Could not initialize Fernet. Encryption will fail. Check FERNET_KEY environment variable. Error: {e}", file=sys.stderr)
    # Use a dummy Fernet if initialization fails to prevent crash
    F = Fernet(Fernet.generate_key())


# -------------------------------------------------
# Sensitive Field Definition
# -------------------------------------------------

# NEW: List of database fields that hold encrypted data
SENSITIVE_ASSET_FIELDS = [
    'account_no',
    'financial_institution',
    'beneficiary_name',
    'contact_phone',
    'document_location',
]
# -------------------------------------------------


def enc(text):
    """Encrypts a string, handling None or empty strings."""
    if not text:
        return None
    try:
        # PostgreSQL doesn't like null characters, but Fernet should handle this
        return F.encrypt(str(text).encode()).decode()
    except Exception as e:
        print(f"Encryption error: {e}", file=sys.stderr)
        return text

def dec(token):
    """Decrypts a token, handling None or non-encrypted data."""
    if not token or not isinstance(token, str):
        return token
    try:
        # Check for Fernet token prefix (gAAAAA) before attempting decryption
        if token.startswith('gAAAAA'):
            return F.decrypt(token.encode()).decode()
        else:
            # Not a Fernet token, return as-is (e.g., if it was already cleartext)
            return token
    except Exception as e:
        # If decryption fails (wrong key, corrupted data), return the original token
        print(f"Decryption error on token {token[:15]}...: {e}", file=sys.stderr)
        return token

# -------------------------------------------------
# Database Connection
# -------------------------------------------------
def get_db_connection():
    DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@host/dbname")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}", file=sys.stderr)
        flash("Database connection failed. Check connection string.", "error")
        raise

# -------------------------------------------------
# Helper Functions
# -------------------------------------------------

@app.before_request
def load_user():
    g.user_id = session.get("user_id")
    g.username = session.get("username")
    g.user_role = session.get("user_role")
    g.group_id = session.get("group_id")
    g.is_authenticated = bool(g.user_id)
    g.is_admin = g.user_role == 'Admin'
    g.is_pending = session.get("is_pending", False)

def auth_required(func):
    """Decorator to enforce authentication."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not g.is_authenticated:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    """Decorator to enforce admin privileges."""
    @functools.wraps(func)
    @auth_required
    def wrapper(*args, **kwargs):
        if not g.is_admin:
            flash("You do not have permission to view this page.", "error")
            return redirect(url_for('assets')) # Redirect to a safe page
        return func(*args, **kwargs)
    return wrapper

def pending_check(func):
    """Decorator to check if user is pending approval."""
    @functools.wraps(func)
    @auth_required
    def wrapper(*args, **kwargs):
        if g.is_pending and g.user_role == 'Pending':
            return render_template('pending.html')
        return func(*args, **kwargs)
    return wrapper

def get_group_filter_clause(role, group_id, table_alias="a"):
    """
    Returns a SQL WHERE clause fragment and parameters to filter by group_id,
    unless the user is an Admin.
    """
    if role == 'Admin':
        return "", ()
    # Non-admins can only see assets belonging to their group
    return f"AND {table_alias}.group_id=%s", (group_id,)

def get_common_lists():
    """Fetches common list data for forms (owners, types, currencies, etc.)."""
    conn = None
    lists = {
        "owners": [],
        "asset_types": [],
        "currencies": [],
        "countries": [],
    }
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Fetch owners (users in the same group or all users if Admin)
        if g.is_admin:
            cur.execute("SELECT id, username FROM users WHERE activate=TRUE ORDER BY username;")
        else:
            cur.execute("SELECT id, username FROM users WHERE group_id=%s AND activate=TRUE ORDER BY username;", (g.group_id,))
        lists["owners"] = [{"id": user["id"], "name": user["username"]} for user in cur.fetchall()]

        # Fetch distinct lists for types, currencies, and countries
        # These are generally not user-specific, but can be customized
        for list_name, table_name in [("asset_types", "asset_types_list"),
                                       ("currencies", "currencies_list"),
                                       ("countries", "countries_list")]:
            cur.execute(f"SELECT name FROM {table_name} ORDER BY name;")
            lists[list_name] = [item["name"] for item in cur.fetchall()]

    except Exception as e:
        print(f"get_common_lists error: {e}", file=sys.stderr)
        # Continue with empty lists if there's a DB issue
    finally:
        if conn:
            conn.close()
    return lists

def send_email(to_addr, subject, html_content):
    if not (SMTP_SERVER and SMTP_USER and SMTP_PASSWORD):
        print("WARNING: SMTP credentials not set. Email not sent.")
        return

    msg = EmailMessage()
    msg.set_content(html_content, subtype='html')
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = to_addr

    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"SMTP error sending email to {to_addr}: {e}", file=sys.stderr)
        raise

def notify_admin_new_user(email: str, username: str, ip: str, ua: str):
    if not ADMIN_NOTIFY_EMAILS:
        return
    when = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')
    subject = f"[Family Finance] New User Signup: {username}"
    html = f"""
        <h2>New User Pending Approval</h2>
        <p>A new user has signed up and is awaiting admin approval.</p>
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

def notify_admin_user_approved(username: str, approver: str | None, group_id: str | None):
    if not ADMIN_NOTIFY_EMAILS:
        return
    subject = f"[Family Finance] User approved: {username}"
    html = f"""
        <h2>User Approved</h2>
        <p><strong>User:</strong> {username}</p>
        <p><strong>Group:</strong> {group_id or '(none)'}</p>
        <p><strong>Approved by:</strong> {approver or 'Admin'}</p>
        <p><strong>When (UTC):</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}</p>
    """
    for admin_addr in ADMIN_NOTIFY_EMAILS:
        try:
            send_email(admin_addr, subject, html)
        except Exception as e:
            print(f"admin notify failed to {admin_addr}: {e}", file=sys.stderr)

# -------------------------------------------------
# Routes
# -------------------------------------------------

@app.route("/")
@auth_required
@pending_check
def index():
    return redirect(url_for('assets'))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if g.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, username, password_hash, role, group_id, is_pending, activate FROM users WHERE username=%s AND activate=TRUE;", (username,))
            user = cur.fetchone()

            if user and bcrypt.check_password_hash(user['password_hash'], password):
                # Successful login
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["user_role"] = user["role"]
                session["group_id"] = user["group_id"]
                session["is_pending"] = user["is_pending"]

                # Check if pending approval
                if user["is_pending"] and user["role"] == 'Pending':
                    flash("Your account is pending admin approval.", "info")
                    return redirect(url_for('pending'))
                
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "error")
        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            flash("An unexpected error occurred during login.", "error")
        finally:
            if conn:
                conn.close()

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per hour", methods=["POST"])
def signup():
    if g.is_authenticated:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip()
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")
        
        if not (username and password and password_confirm):
            flash("All fields are required.", "error")
            return render_template("signup.html", username=username, email=email)

        if password != password_confirm:
            flash("Passwords do not match.", "error")
            return render_template("signup.html", username=username, email=email)

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return render_template("signup.html", username=username, email=email)

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Check if username or email already exists
            cur.execute("SELECT id FROM users WHERE username=%s OR email=%s;", (username, email if email else None))
            if cur.fetchone():
                flash("A user with that username or email already exists.", "error")
                return render_template("signup.html", username=username, email=email)

            # Insert new user with Pending role and is_pending=True
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role, is_pending, group_id, activate)
                VALUES (%s, %s, %s, 'Pending', TRUE, NULL, TRUE) RETURNING id;
            """, (username, email if email else None, password_hash))
            conn.commit()

            # Notify admin
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            ua = request.headers.get('User-Agent', 'Unknown')
            notify_admin_new_user(email, username, ip, ua)

            flash("Signup successful! Your account is pending admin approval.", "success")
            return redirect(url_for('login'))

        except Exception as e:
            print(f"Signup error: {e}", file=sys.stderr)
            flash("An unexpected error occurred during signup.", "error")
        finally:
            if conn:
                conn.close()

    return render_template("signup.html")

@app.route("/pending")
@auth_required
def pending():
    if g.user_role != 'Pending' or not g.is_pending:
        return redirect(url_for('index'))
    return render_template('pending.html')


@app.route("/assets")
@auth_required
@pending_check
def assets():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Apply group filtering
        gf, gp = get_group_filter_clause(g.user_role, g.group_id, table_alias="a")
        
        # Select all assets for the user's group, but only show decrypted value
        cur.execute(f"""
            SELECT 
                a.id, a.type, a.name, a.country, a.currency, a.value, a.current_value, a.last_updated, a.notes,
                a.owner, a.owner_id, a.policy_or_plan_type,
                a.account_no, a.financial_institution, a.beneficiary_name, a.contact_phone, a.document_location,
                a.investment_strategy,
                u.username AS added_by
            FROM assets a
            JOIN users u ON a.user_id = u.id
            WHERE a.activate=TRUE {gf}
            ORDER BY a.name;
        """, gp)
        assets_list = cur.fetchall()

        # Decrypt sensitive fields for the list view
        for asset in assets_list:
            # We don't decrypt everything for the main list, only display fields if needed
            # For list view, usually only the name/value is needed.
            # If any of the SENSITIVE_ASSET_FIELDS were displayed here, you'd decrypt them.
            # asset['account_no'] = dec(asset['account_no']) # Example if needed in list view
            pass

        return render_template("assets.html", assets=assets_list)
    except Exception as e:
        print(f"assets list error: {e}", file=sys.stderr)
        flash("Failed to load assets.", "error")
        return render_template("assets.html", assets=[])
    finally:
        if conn:
            conn.close()

@app.route("/edit_asset/<int:asset_id>", methods=["GET", "POST"])
@auth_required
@pending_check
def edit_asset(asset_id):
    lists = get_common_lists()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        gf, gp = get_group_filter_clause(g.user_role, g.group_id, table_alias="a")
        
        # Fetch the asset
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
            # CSRF protection is handled by flask_wtf.CSRFProtect

            owner_id = request.form.get("owner_id")
            atype = request.form.get("type")
            name = request.form.get("name")
            account_no = request.form.get("account_no")
            value = request.form.get("value")
            current_value = request.form.get("current_value")
            currency = request.form.get("currency")
            country = request.form.get("country")
            financial_institution = request.form.get("financial_institution")
            policy_or_plan_type = request.form.get("policy_or_plan_type")
            beneficiary_name = request.form.get("beneficiary_name")
            contact_phone = request.form.get("contact_phone")
            document_location = request.form.get("document_location")
            investment_strategy = request.form.get("investment_strategy")
            notes = request.form.get("notes")
            description = request.form.get("description")
            last_updated = datetime.now()

            cur2 = conn.cursor()
            cur2.execute(f"""
                UPDATE assets
                SET owner_id=%s, type=%s, name=%s, account_no=%s, value=%s, current_value=%s, currency=%s, country=%s,
                    financial_institution=%s, policy_or_plan_type=%s, beneficiary_name=%s, contact_phone=%s,
                    document_location=%s, investment_strategy=%s, notes=%s, description=%s, last_updated=%s
                WHERE id=%s AND activate=TRUE {gf};
            """, (
                owner_id, atype, name, enc(account_no), value, current_value, currency, country,
                enc(financial_institution), policy_or_plan_type, enc(beneficiary_name), enc(contact_phone),
                enc(document_location), investment_strategy, notes, enc(description), last_updated, asset_id
            ) + gp)
            
            if cur2.rowcount == 0:
                flash("Update failed: not found or unauthorized.", "error")
            else:
                conn.commit()
                flash("Asset updated.", "success")
                return redirect(url_for("assets"))

        # Decrypt fields for the GET request display (or POST failure redisplay)
        # This is the critical change, iterating over the new SENSITIVE_ASSET_FIELDS list
        for f in SENSITIVE_ASSET_FIELDS:
            asset[f] = dec(asset.get(f))
        
        # Decrypt the description field, which is also sensitive
        asset['description'] = dec(asset.get('description'))

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
        flash("Failed to load or update asset.", "error")
        return redirect(url_for("assets"))
    finally:
        if conn:
            conn.close()

# ... (other routes like add_asset, delete_asset, profile, admin_users, init_db would follow)

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    # ... (Implementation details for admin_users)
    return "Admin Users Page (Placeholder)"

@app.route("/add_asset", methods=["GET", "POST"])
@auth_required
@pending_check
def add_asset():
    # ... (Implementation details for add_asset)
    return "Add Asset Page (Placeholder)"

@app.route("/init_db")
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # --- Create Tables (Simplified for brevity) ---
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE,
                password_hash VARCHAR(128) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'User',
                group_id VARCHAR(50),
                is_pending BOOLEAN NOT NULL DEFAULT TRUE,
                activate BOOLEAN NOT NULL DEFAULT TRUE
            );
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                type VARCHAR(50) NOT NULL,
                name VARCHAR(100) NOT NULL,
                country VARCHAR(50),
                currency VARCHAR(10),
                value NUMERIC(15, 2),
                current_value NUMERIC(15, 2),
                account_no VARCHAR(255),
                financial_institution VARCHAR(255),
                beneficiary_name VARCHAR(255),
                policy_or_plan_type VARCHAR(100),
                contact_phone VARCHAR(255),
                document_location VARCHAR(255),
                investment_strategy TEXT,
                description TEXT,
                notes TEXT,
                owner VARCHAR(80),
                owner_id INTEGER,
                added_date DATE NOT NULL DEFAULT CURRENT_DATE,
                last_updated TIMESTAMP WITHOUT TIME ZONE NOT NULL,
                group_id VARCHAR(50) NOT NULL,
                activate BOOLEAN NOT NULL DEFAULT TRUE
            );
            CREATE TABLE IF NOT EXISTS asset_types_list (name VARCHAR(50) PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS currencies_list (name VARCHAR(10) PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS countries_list (name VARCHAR(50) PRIMARY KEY);
        """)
        
        # --- Insert Default Lists ---
        for type_name in ["Bank Account", "Investment", "Real Estate", "Insurance Policy", "Other"]:
            cur.execute("INSERT INTO asset_types_list (name) VALUES (%s) ON CONFLICT (name) DO NOTHING;", (type_name,))
        for currency in ["USD", "EUR", "GBP", "CAD"]:
            cur.execute("INSERT INTO currencies_list (name) VALUES (%s) ON CONFLICT (name) DO NOTHING;", (currency,))
        for country in ["USA", "CAN", "UK", "GER"]:
            cur.execute("INSERT INTO countries_list (name) VALUES (%s) ON CONFLICT (name) DO NOTHING;", (country,))

        # --- Create Admin User ---
        admin_pass_hash = bcrypt.generate_password_hash("password").decode('utf-8')
        cur.execute("INSERT INTO users (username, email, password_hash, role, group_id, is_pending, activate) VALUES (%s, %s, %s, 'Admin', %s, FALSE, TRUE) ON CONFLICT (username) DO NOTHING RETURNING id;",
                    ("admin", "admin@example.com", admin_pass_hash, "family-demo"))
        admin_id = cur.fetchone()
        if admin_id:
            admin_id = admin_id[0]
        else:
            cur.execute("SELECT id FROM users WHERE username='admin';")
            admin_id = cur.fetchone()[0]

        # --- Sample Assets ---
        # NOTE: description is also encrypted in the sample data
        cur.execute("""
            INSERT INTO assets (user_id, type, name, country, currency, value, account_no, last_updated, notes, owner, owner_id,
                                financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location,
                                investment_strategy, current_value, description, added_date, group_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s);
        """, (admin_id, "Bank Account", "Checking - Demo", "USA", "USD", 5000.00, enc("****1234"),
              "Sample notes", "Admin User", admin_id, enc("Demo Bank"), enc("Spouse"),
              "Checking", enc("+1-800-111-2222"), enc("Locker A1"),
              "Keep $3k buffer", 5000.00, enc("Main household account"),
              datetime.now().date(), "family-demo"))

        conn.commit()
        return "Initialized. Admin login: admin / password"
    except Exception as e:
        print(f"init_db error: {e}", file=sys.stderr)
        return f"init_db failed. Error: {e}"
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    app.run(debug=True)
