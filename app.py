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

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per hour", "50 per minute"],
    app=app
)

# Encryption setup
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("WARNING: ENCRYPTION_KEY not set. Using a temporary key. Data encrypted with this key will be lost on restart.", file=sys.stderr)
    # Generate a temporary key for local development if not set, but warn the user.
    ENCRYPTION_KEY = secrets.token_urlsafe(32)
    
try:
    fernet = Fernet(ENCRYPTION_KEY)
except Exception as e:
    print(f"FATAL: Invalid ENCRYPTION_KEY: {e}", file=sys.stderr)
    sys.exit(1)

# Database connection
def get_db():
    if 'db_conn' not in g:
        try:
            g.db_conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
        except Exception as e:
            print(f"Database connection failed: {e}", file=sys.stderr)
            g.db_conn = None
            return None
    return g.db_conn

@app.teardown_appcontext
def close_db(e=None):
    db_conn = g.pop('db_conn', None)
    if db_conn is not None:
        db_conn.close()

# Email Configuration
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM_ADDR = os.environ.get("SMTP_FROM_ADDR", SMTP_USERNAME)
ADMIN_NOTIFY_EMAILS = [e.strip() for e in os.environ.get("ADMIN_NOTIFY_EMAILS", "").split(',') if e.strip()]

def send_email(to_addr, subject, html_content):
    if not (SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD):
        print(f"WARNING: Email settings not configured. Skipping email to {to_addr}.", file=sys.stderr)
        return
        
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM_ADDR
    msg['To'] = to_addr
    msg.add_header('Content-Type', 'text/html')
    msg.set_content(html_content, subtype='html')

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USERNAME, SMTP_PASSWORD)
            s.send_message(msg)
    except Exception as e:
        print(f"ERROR: Failed to send email to {to_addr}: {e}", file=sys.stderr)
        raise

def notify_admin_user_registered(username: str, email: str, ip: str, ua: str):
    if not ADMIN_NOTIFY_EMAILS:
        return
    when = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')
    subject = f"[Family Finance] New User Registration: {username}"
    html = f"""
        <h2>New User Registered</h2>
        <p>A new user has registered and is pending approval:</p>
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

# Encryption and Decryption Helpers
def enc(value):
    """Encrypts a string value."""
    if value is None or not isinstance(value, str) or not value.strip():
        return None
    try:
        return fernet.encrypt(value.encode()).decode()
    except Exception as e:
        print(f"Encryption failed: {e}", file=sys.stderr)
        return None

def dec(encrypted_value):
    """Decrypts an encrypted string value."""
    if encrypted_value is None or not isinstance(encrypted_value, str) or not encrypted_value.strip():
        return ""
    try:
        return fernet.decrypt(encrypted_value.encode()).decode()
    except Exception as e:
        # Fallback for unencrypted data during migration or if key is wrong
        return encrypted_value

# Helper to decrypt fields for display
def decrypt_row(row):
    """Converts a RealDictRow into a dict and decrypts specified fields."""
    row_dict = dict(row)
    for key, value in row_dict.items():
        if key in ['notes', 'account_no', 'financial_institution', 'beneficiary_name', 'contact_phone', 'document_location', 'description']:
            row_dict[key] = dec(value)
    return row_dict

# -------------------------------------------------
# Database Schema Initialization and Migration
# -------------------------------------------------

def init_db():
    conn = get_db()
    if conn is None:
        return "init_db failed: No database connection."
    try:
        cur = conn.cursor()
        
        # -----------------------------------------------------------------------------------
        # FIX FOR MIGRATION ERROR: Changing VARCHAR(255) to TEXT for encrypted fields
        # This resolves the "value too long for type character varying(255)" error.
        # -----------------------------------------------------------------------------------

        # USERS Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                email VARCHAR(120) UNIQUE,
                is_admin BOOLEAN DEFAULT FALSE,
                is_approved BOOLEAN DEFAULT FALSE,
                group_id VARCHAR(50) DEFAULT 'default_group',
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP WITHOUT TIME ZONE
            );
        """)

        # ASSETS Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users (id),
                group_id VARCHAR(50) NOT NULL,
                type VARCHAR(100) NOT NULL,
                name VARCHAR(150) NOT NULL,
                country VARCHAR(100),
                currency VARCHAR(10),
                value NUMERIC(15, 2) NOT NULL,
                account_no TEXT, -- FIXED: Changed from VARCHAR(255)
                last_updated TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                notes TEXT, -- FIXED: Changed from VARCHAR(255)
                owner VARCHAR(100),
                owner_id INTEGER,
                financial_institution TEXT, -- FIXED: Changed from VARCHAR(255)
                beneficiary_name TEXT, -- FIXED: Changed from VARCHAR(255)
                policy_or_plan_type VARCHAR(100),
                contact_phone TEXT, -- FIXED: Changed from VARCHAR(255)
                document_location TEXT, -- FIXED: Changed from VARCHAR(255)
                investment_strategy TEXT, -- FIXED: Changed from VARCHAR(255)
                current_value NUMERIC(15, 2),
                description TEXT, -- FIXED: Changed from VARCHAR(255)
                added_date DATE DEFAULT CURRENT_DATE
            );
        """)

        # EXPENSES Table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users (id),
                group_id VARCHAR(50) NOT NULL,
                amount NUMERIC(15, 2) NOT NULL,
                category VARCHAR(100) NOT NULL,
                description TEXT, -- FIXED: Changed from VARCHAR(255)
                date DATE NOT NULL,
                notes TEXT, -- FIXED: Changed from VARCHAR(255)
                is_recurring BOOLEAN DEFAULT FALSE,
                recurrence_frequency VARCHAR(50), -- e.g., 'monthly', 'yearly'
                added_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # CATEGORIES Table (for groups)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS categories (
                id SERIAL PRIMARY KEY,
                group_id VARCHAR(50) NOT NULL,
                category_name VARCHAR(100) UNIQUE NOT NULL,
                type VARCHAR(10) NOT NULL -- 'asset' or 'expense'
            );
        """)

        # Admin User and Sample Data Insertion
        # Check if admin user exists
        cur.execute("SELECT id, username, password_hash FROM users WHERE username = 'admin';")
        admin_user = cur.fetchone()

        if not admin_user:
            admin_password_hash = bcrypt.generate_password_hash("password").decode('utf-8')
            cur.execute("""
                INSERT INTO users (username, password_hash, email, is_admin, is_approved) 
                VALUES ('admin', %s, 'admin@example.com', TRUE, TRUE) RETURNING id;
            """, (admin_password_hash,))
            admin_id = cur.fetchone()[0]

            # Sample Data for demonstration
            cur.execute("INSERT INTO categories (group_id, category_name, type) VALUES (%s, %s, %s), (%s, %s, %s);",
                        ("family-demo", "Groceries", "expense"), ("family-demo", "Utilities", "expense"))

            # sample asset
            cur.execute("""
                INSERT INTO assets (user_id, type, name, country, currency, value, account_no, last_updated, notes, owner, owner_id,
                                    financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location,
                                    investment_strategy, current_value, description, added_date, group_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s);
            """, (admin_id, "Bank Account", "Checking - Demo", "USA", "USD", 5000.00, enc("****1234"),
                  enc("Sample notes for the checking account, this is a longer string now."), "Admin User", 1, enc("Demo Bank"), enc("Spouse"),
                  "Checking", enc("+1-800-111-2222"), enc("Locker A1 - Important Documents"),
                  enc("Keep $3k buffer for emergencies"), 5000.00, enc("Main household account for daily spending and bills."),
                  datetime.now().date(), "family-demo"))

        conn.commit()
        return "Initialized. Admin login: admin / password"
    except Exception as e:
        print(f"init_db error: {e}", file=sys.stderr)
        return f"init_db failed: {e}"


# -------------------------------------------------
# Context Processor and Decorators
# -------------------------------------------------

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None
    g.is_admin = False
    g.group_id = None
    g.is_approved = False

    if user_id is not None:
        conn = get_db()
        if conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, username, is_admin, group_id, is_approved FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if user:
                g.user = user
                g.is_admin = user['is_admin']
                g.group_id = user['group_id']
                g.is_approved = user['is_approved']

@app.context_processor
def inject_global_vars():
    return dict(
        user=g.user,
        is_admin=g.is_admin,
        group_id=g.group_id,
        is_approved=g.is_approved,
        title_prefix="Family Finance | "
    )

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("You need to log in to view this page.", "warning")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def approved_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user and not g.is_approved:
            flash("Your account is pending admin approval. Please wait or contact an administrator.", "info")
            return redirect(url_for('pending_approval'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not g.is_admin:
            flash("Access denied: Admin privileges required.", "danger")
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped_view


# -------------------------------------------------
# Forms (Placeholder - assuming you have actual form classes)
# -------------------------------------------------

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, DecimalField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, InputRequired, NumberRange

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email (Optional)', validators=[Optional(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AssetForm(FlaskForm):
    type = SelectField('Asset Type', validators=[DataRequired()], choices=[
        ('Bank Account', 'Bank Account'),
        ('Investment', 'Investment'),
        ('Real Estate', 'Real Estate'),
        ('Vehicle', 'Vehicle'),
        ('Other', 'Other')
    ])
    name = StringField('Name', validators=[DataRequired()])
    country = StringField('Country', validators=[Optional()])
    currency = StringField('Currency', validators=[DataRequired(), Length(max=10)], default='USD')
    value = DecimalField('Starting Value', validators=[InputRequired(), NumberRange(min=0)])
    account_no = StringField('Account/ID (Encrypted)', validators=[Optional()])
    notes = TextAreaField('Notes (Encrypted)', validators=[Optional()])
    owner = StringField('Owner', validators=[Optional()])
    financial_institution = StringField('Financial Institution (Encrypted)', validators=[Optional()])
    beneficiary_name = StringField('Beneficiary Name (Encrypted)', validators=[Optional()])
    policy_or_plan_type = StringField('Policy/Plan Type', validators=[Optional()])
    contact_phone = StringField('Contact Phone (Encrypted)', validators=[Optional()])
    document_location = StringField('Document Location (Encrypted)', validators=[Optional()])
    investment_strategy = TextAreaField('Investment Strategy (Encrypted)', validators=[Optional()])
    description = TextAreaField('Description (Encrypted)', validators=[Optional()])
    submit = SubmitField('Save Asset')

class ExpenseForm(FlaskForm):
    amount = DecimalField('Amount', validators=[InputRequired(), NumberRange(min=0)])
    category = StringField('Category', validators=[DataRequired()]) # Should be SelectField with dynamic options
    description = TextAreaField('Description (Encrypted)', validators=[Optional()])
    date = DateField('Date', format='%Y-%m-%d', validators=[DataRequired()], default=datetime.now().date)
    notes = TextAreaField('Notes (Encrypted)', validators=[Optional()])
    is_recurring = BooleanField('Recurring Expense')
    recurrence_frequency = SelectField('Frequency', choices=[
        ('', 'One-time'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('yearly', 'Yearly')
    ], validators=[Optional()])
    submit = SubmitField('Save Expense')

# -------------------------------------------------
# Route Definitions
# -------------------------------------------------

# The problematic import is removed here:
# import family_finance.routes # <--- This line caused the ModuleNotFoundError

@app.route('/')
@approved_required
@login_required
def index():
    conn = get_db()
    if not conn:
        flash("Could not connect to database.", "danger")
        return render_template('index.html', assets=[], expenses=[])

    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Fetch Assets
    cur.execute("SELECT * FROM assets WHERE group_id = %s ORDER BY added_date DESC", (g.group_id,))
    assets_raw = cur.fetchall()
    assets = [decrypt_row(row) for row in assets_raw]
    
    # Calculate Total Asset Value (Current Value preferred, otherwise use Value)
    total_assets = sum(row.get('current_value') or row.get('value', 0) for row in assets_raw if (row.get('current_value') is not None or row.get('value') is not None))

    # Fetch Recent Expenses (last 30 days)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    cur.execute("""
        SELECT * FROM expenses 
        WHERE group_id = %s AND date >= %s
        ORDER BY date DESC 
        LIMIT 10
    """, (g.group_id, thirty_days_ago))
    expenses_raw = cur.fetchall()
    expenses = [decrypt_row(row) for row in expenses_raw]
    
    # Calculate Expense Totals for the month
    current_month_start = datetime.now().date().replace(day=1)
    cur.execute("""
        SELECT SUM(amount) AS total_monthly_expense 
        FROM expenses 
        WHERE group_id = %s AND date >= %s
    """, (g.group_id, current_month_start))
    monthly_expense_total = cur.fetchone()['total_monthly_expense'] or 0

    cur.close()

    return render_template('index.html', 
        assets=assets, 
        expenses=expenses,
        total_assets=total_assets,
        monthly_expense_total=monthly_expense_total
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db()
        if not conn:
            flash("Database connection failed.", "danger")
            return render_template('login.html', form=form)

        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, password_hash, is_approved, is_admin FROM users WHERE username = %s", (form.username.data,))
        user = cur.fetchone()
        cur.close()
        
        if user and bcrypt.check_password_hash(user['password_hash'], form.password.data):
            if not user['is_approved']:
                flash("Login successful, but your account is pending admin approval.", "info")
                session['user_id'] = user['id']
                return redirect(url_for('pending_approval'))
            
            session.clear()
            session['user_id'] = user['id']
            # Update last login time
            cur = conn.cursor()
            cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))
            conn.commit()
            flash(f"Welcome back, {form.username.data}!", "success")
            return redirect(url_for('index'))
        else:
            flash("Login failed. Check username and password.", "danger")
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('index'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data or None
        password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        conn = get_db()
        if not conn:
            flash("Database connection failed.", "danger")
            return render_template('register.html', form=form)

        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (username, password_hash, email, is_approved) 
                VALUES (%s, %s, %s, FALSE)
                RETURNING id;
            """, (username, password_hash, email))
            
            new_user_id = cur.fetchone()[0]
            conn.commit()
            
            # Notify admin
            ip = request.remote_addr
            ua = request.headers.get('User-Agent', 'Unknown')
            notify_admin_user_registered(username, email or "N/A", ip, ua)
            
            flash("Registration successful. Your account is pending admin approval. You can log in now.", "success")
            session.clear()
            session['user_id'] = new_user_id
            return redirect(url_for('pending_approval'))
            
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Username or Email already taken.", "danger")
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred during registration: {e}", "danger")
            print(f"Registration error: {e}", file=sys.stderr)
            
    return render_template('register.html', form=form)

@app.route('/pending')
@login_required
def pending_approval():
    if g.is_approved:
        return redirect(url_for('index'))
    return render_template('pending.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return render_template('admin.html', pending_users=[], approved_users=[])
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Fetch pending users
    cur.execute("SELECT id, username, email, created_at, last_login, group_id FROM users WHERE is_approved = FALSE ORDER BY created_at ASC")
    pending_users = cur.fetchall()
    
    # Fetch approved users
    cur.execute("SELECT id, username, email, created_at, last_login, is_admin, group_id FROM users WHERE is_approved = TRUE ORDER BY username ASC")
    approved_users = cur.fetchall()
    
    # Handle POST request for approval/group assignment
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        group_id = request.form.get('group_id')
        is_admin = request.form.get('is_admin') == 'on'
        
        if user_id:
            try:
                cur_action = conn.cursor(cursor_factory=RealDictCursor)
                
                if action == 'approve':
                    cur_action.execute("UPDATE users SET is_approved = TRUE, group_id = %s WHERE id = %s RETURNING username;", 
                                       (group_id or 'default_group', user_id))
                    user_row = cur_action.fetchone()
                    if user_row:
                        notify_admin_user_approved(user_row['username'], g.user['username'], group_id)
                        flash(f"User {user_row['username']} approved and assigned to group {group_id}.", "success")
                
                elif action == 'set_admin':
                    cur_action.execute("UPDATE users SET is_admin = %s WHERE id = %s RETURNING username;", (is_admin, user_id))
                    user_row = cur_action.fetchone()
                    if user_row:
                        flash(f"Admin status for {user_row['username']} set to {is_admin}.", "success")

                elif action == 'set_group':
                    cur_action.execute("UPDATE users SET group_id = %s WHERE id = %s RETURNING username;", (group_id, user_id))
                    user_row = cur_action.fetchone()
                    if user_row:
                        flash(f"Group for {user_row['username']} set to {group_id}.", "success")
                        
                elif action == 'delete':
                    cur_action.execute("DELETE FROM users WHERE id = %s RETURNING username;", (user_id,))
                    user_row = cur_action.fetchone()
                    if user_row:
                        flash(f"User {user_row['username']} deleted.", "success")

                conn.commit()
                # Redirect to avoid re-submission and refresh the page data
                return redirect(url_for('admin_dashboard'))

            except Exception as e:
                conn.rollback()
                flash(f"An error occurred during admin action: {e}", "danger")
                print(f"Admin action error: {e}", file=sys.stderr)
    
    cur.close()
    return render_template('admin.html', 
                           pending_users=pending_users, 
                           approved_users=approved_users)

# ASSET Routes
@app.route('/assets')
@approved_required
@login_required
def assets_list():
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return render_template('assets_list.html', assets=[])
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM assets WHERE group_id = %s ORDER BY name ASC", (g.group_id,))
    assets_raw = cur.fetchall()
    assets = [decrypt_row(row) for row in assets_raw]
    cur.close()
    
    total_assets = sum(row.get('current_value') or row.get('value', 0) for row in assets_raw if (row.get('current_value') is not None or row.get('value') is not None))
    
    return render_template('assets_list.html', assets=assets, total_assets=total_assets)

@app.route('/asset/new', methods=['GET', 'POST'])
@approved_required
@login_required
def asset_new():
    form = AssetForm()
    if form.validate_on_submit():
        conn = get_db()
        if not conn:
            flash("Database connection failed.", "danger")
            return render_template('asset_form.html', form=form, title="Add New Asset")

        try:
            cur = conn.cursor()
            # Encrypt sensitive fields before inserting
            cur.execute("""
                INSERT INTO assets (user_id, group_id, type, name, country, currency, value, account_no, 
                                    notes, owner, financial_institution, beneficiary_name, policy_or_plan_type, 
                                    contact_phone, document_location, investment_strategy, current_value, 
                                    description, added_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 
                        %s, %s, %s, %s, %s, 
                        %s, %s, %s, %s, 
                        %s, %s);
            """, (g.user['id'], g.group_id, form.type.data, form.name.data, form.country.data, 
                  form.currency.data, form.value.data, enc(form.account_no.data), 
                  enc(form.notes.data), form.owner.data, enc(form.financial_institution.data), 
                  enc(form.beneficiary_name.data), form.policy_or_plan_type.data, 
                  enc(form.contact_phone.data), enc(form.document_location.data), 
                  enc(form.investment_strategy.data), form.value.data, 
                  enc(form.description.data), datetime.now().date()))

            conn.commit()
            flash(f"Asset '{form.name.data}' added successfully.", "success")
            return redirect(url_for('assets_list'))
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred while adding the asset: {e}", "danger")
            print(f"Asset insert error: {e}", file=sys.stderr)

    return render_template('asset_form.html', form=form, title="Add New Asset")

@app.route('/asset/<int:asset_id>/edit', methods=['GET', 'POST'])
@approved_required
@login_required
def asset_edit(asset_id):
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return redirect(url_for('assets_list'))
        
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM assets WHERE id = %s AND group_id = %s", (asset_id, g.group_id))
    asset_raw = cur.fetchone()
    cur.close()

    if not asset_raw:
        flash("Asset not found or access denied.", "danger")
        return redirect(url_for('assets_list'))

    asset = decrypt_row(asset_raw)
    form = AssetForm(obj=asset)
    
    # Manually populate fields that were decrypted
    form.account_no.data = asset.get('account_no')
    form.notes.data = asset.get('notes')
    form.financial_institution.data = asset.get('financial_institution')
    form.beneficiary_name.data = asset.get('beneficiary_name')
    form.contact_phone.data = asset.get('contact_phone')
    form.document_location.data = asset.get('document_location')
    form.investment_strategy.data = asset.get('investment_strategy')
    form.description.data = asset.get('description')
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            cur = conn.cursor()
            # Encrypt sensitive fields before updating
            cur.execute("""
                UPDATE assets SET 
                    type = %s, name = %s, country = %s, currency = %s, value = %s, 
                    account_no = %s, notes = %s, owner = %s, financial_institution = %s, 
                    beneficiary_name = %s, policy_or_plan_type = %s, contact_phone = %s, 
                    document_location = %s, investment_strategy = %s, description = %s, 
                    last_updated = NOW()
                WHERE id = %s AND group_id = %s;
            """, (form.type.data, form.name.data, form.country.data, form.currency.data, form.value.data, 
                  enc(form.account_no.data), enc(form.notes.data), form.owner.data, enc(form.financial_institution.data), 
                  enc(form.beneficiary_name.data), form.policy_or_plan_type.data, enc(form.contact_phone.data), 
                  enc(form.document_location.data), enc(form.investment_strategy.data), enc(form.description.data), 
                  asset_id, g.group_id))

            conn.commit()
            flash(f"Asset '{form.name.data}' updated successfully.", "success")
            return redirect(url_for('assets_list'))
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred while updating the asset: {e}", "danger")
            print(f"Asset update error: {e}", file=sys.stderr)

    return render_template('asset_form.html', form=form, title="Edit Asset", asset_id=asset_id)

@app.route('/asset/<int:asset_id>/delete', methods=['POST'])
@approved_required
@login_required
def asset_delete(asset_id):
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return redirect(url_for('assets_list'))

    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM assets WHERE id = %s AND group_id = %s RETURNING name;", (asset_id, g.group_id))
        asset_name = cur.fetchone()
        conn.commit()
        
        if asset_name:
            flash(f"Asset '{asset_name[0]}' deleted successfully.", "success")
        else:
            flash("Asset not found or access denied.", "danger")

    except Exception as e:
        conn.rollback()
        flash(f"An error occurred while deleting the asset: {e}", "danger")
        print(f"Asset delete error: {e}", file=sys.stderr)

    return redirect(url_for('assets_list'))

# EXPENSE Routes
@app.route('/expenses')
@approved_required
@login_required
def expenses_list():
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return render_template('expenses_list.html', expenses=[])
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM expenses WHERE group_id = %s ORDER BY date DESC", (g.group_id,))
    expenses_raw = cur.fetchall()
    expenses = [decrypt_row(row) for row in expenses_raw]
    cur.close()
    
    total_expenses = sum(row.get('amount', 0) for row in expenses_raw if row.get('amount') is not None)

    return render_template('expenses_list.html', expenses=expenses, total_expenses=total_expenses)

@app.route('/expense/new', methods=['GET', 'POST'])
@approved_required
@login_required
def expense_new():
    form = ExpenseForm()
    # Populate categories for the SelectField if you switch category to SelectField
    # For now, it's a StringField, so this is skipped.
    
    if form.validate_on_submit():
        conn = get_db()
        if not conn:
            flash("Database connection failed.", "danger")
            return render_template('expense_form.html', form=form, title="Add New Expense")

        try:
            cur = conn.cursor()
            # Encrypt sensitive fields before inserting
            cur.execute("""
                INSERT INTO expenses (user_id, group_id, amount, category, description, date, notes, is_recurring, recurrence_frequency)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (g.user['id'], g.group_id, form.amount.data, form.category.data, 
                  enc(form.description.data), form.date.data, enc(form.notes.data), 
                  form.is_recurring.data, form.recurrence_frequency.data or None))

            conn.commit()
            flash(f"Expense of ${form.amount.data} added successfully.", "success")
            return redirect(url_for('expenses_list'))
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred while adding the expense: {e}", "danger")
            print(f"Expense insert error: {e}", file=sys.stderr)

    return render_template('expense_form.html', form=form, title="Add New Expense")

@app.route('/expense/<int:expense_id>/edit', methods=['GET', 'POST'])
@approved_required
@login_required
def expense_edit(expense_id):
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return redirect(url_for('expenses_list'))
        
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM expenses WHERE id = %s AND group_id = %s", (expense_id, g.group_id))
    expense_raw = cur.fetchone()
    cur.close()

    if not expense_raw:
        flash("Expense not found or access denied.", "danger")
        return redirect(url_for('expenses_list'))

    expense = decrypt_row(expense_raw)
    form = ExpenseForm(obj=expense)
    
    # Manually populate fields that were decrypted
    form.description.data = expense.get('description')
    form.notes.data = expense.get('notes')
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            cur = conn.cursor()
            # Encrypt sensitive fields before updating
            cur.execute("""
                UPDATE expenses SET 
                    amount = %s, category = %s, description = %s, date = %s, 
                    notes = %s, is_recurring = %s, recurrence_frequency = %s
                WHERE id = %s AND group_id = %s;
            """, (form.amount.data, form.category.data, enc(form.description.data), form.date.data, 
                  enc(form.notes.data), form.is_recurring.data, form.recurrence_frequency.data or None,
                  expense_id, g.group_id))

            conn.commit()
            flash(f"Expense of ${form.amount.data} updated successfully.", "success")
            return redirect(url_for('expenses_list'))
        except Exception as e:
            conn.rollback()
            flash(f"An error occurred while updating the expense: {e}", "danger")
            print(f"Expense update error: {e}", file=sys.stderr)

    return render_template('expense_form.html', form=form, title="Edit Expense", expense_id=expense_id)

@app.route('/expense/<int:expense_id>/delete', methods=['POST'])
@approved_required
@login_required
def expense_delete(expense_id):
    conn = get_db()
    if not conn:
        flash("Database connection failed.", "danger")
        return redirect(url_for('expenses_list'))

    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM expenses WHERE id = %s AND group_id = %s RETURNING amount;", (expense_id, g.group_id))
        expense_amount = cur.fetchone()
        conn.commit()
        
        if expense_amount:
            flash(f"Expense of ${expense_amount[0]} deleted successfully.", "success")
        else:
            flash("Expense not found or access denied.", "danger")

    except Exception as e:
        conn.rollback()
        flash(f"An error occurred while deleting the expense: {e}", "danger")
        print(f"Expense delete error: {e}", file=sys.stderr)

    return redirect(url_for('expenses_list'))

# Utility route for database initialization
@app.route('/init')
def init():
    return init_db()


# -------------------------------------------------
# Migration Script (Called by run_migration_on_deploy.py)
# -------------------------------------------------

def run_migration():
    """
    Migrates existing unencrypted data to encrypted format.
    Assumes schema has been updated to use TEXT for all columns being encrypted.
    """
    conn = get_db()
    if conn is None:
        print("Migration failed: No database connection.", file=sys.stderr)
        return

    tables_to_migrate = {
        'assets': ['account_no', 'notes', 'financial_institution', 'beneficiary_name', 
                   'contact_phone', 'document_location', 'investment_strategy', 'description'],
        'expenses': ['description', 'notes']
    }

    print("--- Starting Database Encryption Migration ---", file=sys.stderr)
    
    for table_name, columns in tables_to_migrate.items():
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Select all records where at least one target column is not null and not yet encrypted
            # We assume non-encrypted strings do not start with 'gAAAA'
            where_clauses = [f"{col} IS NOT NULL AND {col} NOT LIKE 'gAAAA%'" for col in columns]
            cur.execute(f"SELECT id, {', '.join(columns)} FROM {table_name} WHERE {' OR '.join(where_clauses)};")
            
            records = cur.fetchall()
            print(f"\n⏳ Starting migration for {len(records)} records in '{table_name}'...", file=sys.stderr)

            # Use tqdm for progress indication
            from tqdm import tqdm
            for record in tqdm(records, desc=f"Encrypting {table_name}"):
                update_fields = {}
                for col in columns:
                    value = record.get(col)
                    if value and not value.startswith('gAAAA'): # Simple check for already encrypted Fernet data
                        encrypted_value = enc(str(value)) # Ensure value is cast to string for encryption
                        if encrypted_value:
                            update_fields[col] = encrypted_value
                
                if update_fields:
                    set_clauses = [f"{col} = %s" for col in update_fields.keys()]
                    params = list(update_fields.values()) + [record['id']]
                    
                    cur_update = conn.cursor()
                    cur_update.execute(f"UPDATE {table_name} SET {', '.join(set_clauses)} WHERE id = %s;", params)
                    cur_update.close()

            conn.commit()
            cur.close()

        except psycopg2.errors.StringDataRightTruncation as e:
            # This should now be solved by changing to TEXT, but we keep the error reporting
            print(f"\n❌ FATAL ERROR during {table_name} migration: {e}", file=sys.stderr)
            conn.rollback()
            return
        except Exception as e:
            print(f"\n❌ UNEXPECTED ERROR during {table_name} migration: {e}", file=sys.stderr)
            conn.rollback()
            return

    print("\n--- Migration Complete. Your data is now encrypted. ---", file=sys.stderr)
    return

if __name__ == '__main__':
    # This block is used for local running, not the Render deployment Gunicorn command
    app.run(debug=True)
