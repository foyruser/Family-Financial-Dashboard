from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools
import os
import sys
import secrets
from datetime import datetime, timedelta
from email.message import EmailMessage
import smtplib
from cryptography.fernet import Fernet

# --- APPLICATION INITIALIZATION & CONFIG ---
app = Flask(__name__)
# CRITICAL: SET FLASK_SECRET_KEY ENVIRONMENT VARIABLE FOR PRODUCTION
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_long_random_fallback_key') 
bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL') 
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY')
# CRITICAL: Fernet Encryption Key
FERNET_KEY = os.environ.get('FERNET_KEY')

# --- Email Configuration ---
MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
MAIL_USERNAME = os.environ.get('MAIL_USERNAME') # Your sending email address (and Admin's email)
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') # Your App Password
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'Family Dashboard Admin')

# --- ENCRYPTOR IMPLEMENTATION ---
class Encryptor:
    """Handles field-level encryption and decryption using Fernet."""
    def __init__(self, key):
        if not key:
            raise ValueError("Encryption key cannot be empty.")
        self.f = Fernet(key)

    def encrypt(self, data):
        """Encrypts data. Returns None if data is None or empty."""
        if data is None or data == '':
            return None
        try:
            return self.f.encrypt(data.encode()).decode()
        except Exception as e:
            print(f"Encryption error: {e}", file=sys.stderr)
            return None

    def decrypt(self, token):
        """Decrypts a token. Returns empty string if token is None or empty."""
        if token is None or token == '':
            return ''
        try:
            return self.f.decrypt(token.encode()).decode()
        except Exception as e:
            print(f"Decryption error for token: {e}", file=sys.stderr)
            return '--- DECRYPTION ERROR ---'

try:
    encryptor = Encryptor(FERNET_KEY)
except ValueError as e:
    print(f"FATAL: {e}", file=sys.stderr)
    sys.exit(1)


# --- DATABASE UTILITIES ---

def get_db_connection():
    """Connects to the PostgreSQL database."""
    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}", file=sys.stderr)
        return None


# --- EMAIL UTILITIES ---

def send_email(subject, recipient, body):
    """Sends an email using configured SMTP settings."""
    if not MAIL_USERNAME or not MAIL_PASSWORD:
        print("WARNING: Email credentials missing. Cannot send real email.", file=sys.stderr)
        return
    
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f"{MAIL_DEFAULT_SENDER} <{MAIL_USERNAME}>"
    msg['To'] = recipient
    msg.set_content(body)
    
    try:
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        if MAIL_USE_TLS:
            server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"SUCCESS: Email sent to {recipient} for '{subject}'", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: Failed to send email to {recipient}. Exception: {e}", file=sys.stderr)

def send_password_reset_email(email, token):
    """Sends the actual password reset link."""
    reset_link = url_for('reset_password', token=token, _external=True)
    subject = "Password Reset Request for Dream Bee Network"
    body = (
        f"You requested a password reset for your account ({email}).\n\n"
        f"Please click on the following link to reset your password within the next hour:\n"
        f"{reset_link}\n\n"
        f"If you did not request this, please ignore this email. The link will expire in 60 minutes."
    )
    send_email(subject, email, body)

def send_admin_approval_email(username, user_id):
    """Sends a notification to the admin that a new user needs approval."""
    admin_email = MAIL_USERNAME # Assuming the sending account is the admin account
    subject = "ACTION REQUIRED: New User Pending Approval"
    approval_link = url_for('admin_approve_users', _external=True)
    body = (
        f"A new user ({username}) has registered and requires approval.\n"
        f"User ID: {user_id}\n\n"
        f"Please log in as an Admin and approve the user here:\n"
        f"{approval_link}"
    )
    send_email(subject, admin_email, body)


# --- ACCESS CONTROL & CONTEXT ---

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to access that page.", 'error')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user_role != 'admin':
            return render_template('error.html', code=403, message="Access Denied. Administrator privileges required."), 403
        return view(**kwargs)
    return wrapped_view

@app.before_request
def load_logged_in_user():
    """Loads user info into Flask's global 'g' object before each request."""
    user_id = session.get('user_id')
    g.user = None
    g.user_role = None
    g.group_id = None

    if user_id is not None:
        conn = get_db_connection()
        if conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id, username, role, group_id FROM users WHERE id = %s;', (user_id,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            if user:
                g.user = user
                g.user_role = user['role']
                g.group_id = user['group_id']
                if g.user_role == 'pending':
                    # Block pending users from accessing the main app
                    if request.endpoint not in ('pending_approval', 'logout', 'static'):
                        return redirect(url_for('pending_approval'))
            else:
                session.clear() # User ID in session is invalid

def check_user_access():
    """Checks if the user is authenticated and not pending."""
    if not g.user:
        return redirect(url_for('login'))
    if g.user_role == 'pending':
        return redirect(url_for('pending_approval'))
    return None

def get_group_filter_clause(role, group_id, table_name):
    """
    Returns the SQL WHERE clause and parameters for group-level data filtering.
    """
    if group_id and group_id != 'pending-group':
        # Admins and regular users are filtered by their group_id
        return f'AND {table_name}.group_id = %s', (group_id,)
    
    # Fallback for users without a proper group_id (e.g., system admin or newly registered)
    return '', () 


# --- CONTEXT PROCESSORS (For Template variables used globally) ---
@app.context_processor
def inject_global_vars():
    """Injects static list data into all templates."""
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'CAD', 'JPY'] 
    categories = ['Housing', 'Food', 'Transport', 'Utilities', 'Entertainment', 'Debt', 'Travel', 'Salary', 'Miscellaneous']
    asset_types = ['Checking', 'Savings', 'Investment', 'Real Estate', 'Life Insurance', 'Retirement', 'Other']
    countries = ['USA', 'Canada', 'UK', 'India', 'Germany', 'Japan', 'Other']
    return dict(currencies=currencies, categories=categories, asset_types=asset_types, countries=countries)

@app.context_processor
def inject_user_for_templates():
    """Injects g.user as 'current_user' to satisfy template expectations (like Flask-Login)."""
    return dict(current_user=g.user)

def get_owners():
    """Fetches list of owners for dropdowns."""
    conn = get_db_connection()
    if not conn: return []
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Fetch only owners associated with the user's group
        # Use a simplified filter for the Owners table, which we assume is group-specific.
        where_clause = 'WHERE TRUE'
        group_params = ()
        if g.group_id and g.group_id != 'pending-group':
             where_clause = 'WHERE group_id = %s'
             group_params = (g.group_id,)
        
        cur.execute(f'SELECT id, name FROM owners {where_clause} ORDER BY name;', group_params)
        owners = cur.fetchall()
        return owners
    except Exception as e:
        print(f"Error fetching owners: {e}", file=sys.stderr)
        return []
    finally:
        if 'cur' in locals(): cur.close() 
        if conn: conn.close()


# --- CURRENCY API UTILITY ---
def get_exchange_rates(base_currency='USD'):
    """Fetches current exchange rates from a public API."""
    if not EXCHANGE_RATE_API_KEY:
        print("WARNING: EXCHANGE_RATE_API_KEY is missing. Using fallback rates.", file=sys.stderr)
        # Fallback rates if API key is missing/invalid
        return {'USD': 1.0, 'INR': 83.0, 'EUR': 0.92, 'GBP': 0.81, 'CAD': 1.36, 'JPY': 156.0}

    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/latest/{base_currency}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get('result') == 'success':
            return data['conversion_rates']
        else:
            print(f"API Error: {data.get('error-type')}", file=sys.stderr)
            return None
    except requests.RequestException as e:
        print(f"Exchange Rate API failed: {e}", file=sys.stderr)
        return None


# --- AUTHENTICATION ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        if not conn:
            flash("Database error. Please try again later.", 'error')
            return render_template('login.html')

        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Fix: Correctly search by 'username' (which holds the email string), not the integer 'id'
        cur.execute('SELECT id, username, password_hash, role, group_id FROM users WHERE username = %s;', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            if user['role'] == 'pending':
                session['user_id'] = user['id'] # Log them in just to show pending page
                session['username'] = user['username']
                return redirect(url_for('pending_approval'))
            
            # Successful login for 'user' or 'admin'
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", 'error')
            return render_template('login.html')
            
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('register.html')
            
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = get_db_connection()
        if not conn:
            flash("Database connection error during registration.", 'error')
            return render_template('register.html')

        try:
            cur = conn.cursor()
            # Register user as 'pending' with a temporary 'pending-group' ID
            cur.execute('INSERT INTO users (username, email, password_hash, role, group_id) VALUES (%s, %s, %s, %s, %s) RETURNING id;', 
                        (username, username, password_hash, 'pending', 'pending-group'))
            user_id = cur.fetchone()[0]
            conn.commit()
            
            # Notify Admin
            send_admin_approval_email(username, user_id) 
            
            session['user_id'] = user_id
            session['username'] = username
            flash("Registration successful. Your account is pending administrator approval.", 'info')
            return redirect(url_for('pending_approval')) 
        except psycopg2.IntegrityError:
            conn.rollback()
            flash("Username (Email) already registered.", 'error')
            return render_template('register.html')
        except Exception as e:
            conn.rollback()
            flash(f"Registration error: {e}", 'error')
            return render_template('register.html')
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", 'info')
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # The user typically inputs their username (which is their email) here.
        username_or_email = request.form['username'] 
        conn = get_db_connection()
        if not conn:
            flash("System error. Please try again.", 'error')
            return render_template('forgot_password.html')

        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Find the user by the input string (username/email)
        cur.execute('SELECT id, email, username FROM users WHERE username = %s OR email = %s;', 
                    (username_or_email, username_or_email))
        user = cur.fetchone()
        
        # Security: Don't confirm if email exists, just send a success message always
        flash("If your email address is in our system, you will receive a password reset link shortly.", 'success')
        
        if user:
            # Generate token and set expiration
            token = secrets.token_urlsafe(32)
            expiration = datetime.now() + timedelta(hours=1)
            
            try:
                # Use the retrieved integer 'user['id']' for the UPDATE WHERE clause
                user_email = user['email']
                
                cur.execute('UPDATE users SET reset_token = %s, token_expiration = %s WHERE id = %s;', 
                            (token, expiration, user['id']))
                conn.commit()
                send_password_reset_email(user_email, token)
            except Exception as e:
                conn.rollback()
                print(f"Error saving/sending token: {e}", file=sys.stderr)
        
        cur.close()
        conn.close()
        return render_template('forgot_password.html')
        
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    if not conn:
        flash("System error. Please try again.", 'error')
        return redirect(url_for('forgot_password'))
        
    cur = conn.cursor(cursor_factory=RealDictCursor)
    # Find user by token and ensure token is not expired
    cur.execute('SELECT id, username FROM users WHERE reset_token = %s AND token_expiration > %s;', 
                (token, datetime.now()))
    user = cur.fetchone()
    
    if not user:
        cur.close(); conn.close()
        return render_template('reset.html', token=token, invalid=True, message="The reset link is invalid or has expired. Please request a new one.")

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('reset.html', token=token, invalid=False, message="Please ensure both passwords match.")
        
        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", 'error')
            return render_template('reset.html', token=token, invalid=False, message="Password must be at least 8 characters long.")

        password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        try:
            # Update password and clear token fields
            cur.execute('UPDATE users SET password_hash = %s, reset_token = NULL, token_expiration = NULL WHERE id = %s;', 
                        (password_hash, user['id']))
            conn.commit()
            flash("Your password has been successfully reset. You may now log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            print(f"Password reset error: {e}", file=sys.stderr)
            flash("An error occurred during password update.", 'error')
            return render_template('reset.html', token=token, invalid=False)
        finally:
            cur.close()
            conn.close()
    
    # GET request: Show the reset form
    cur.close(); conn.close()
    return render_template('reset.html', token=token, invalid=False, message="Enter your new password.")

# --- UTILITY ROUTES ---

@app.route('/pending_approval')
def pending_approval():
    """Page shown to users with the 'pending' role."""
    if g.user and g.user_role == 'pending':
        return render_template('pending_approval.html')
    # If they somehow land here but are approved, redirect home
    return redirect(url_for('home'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        conn = get_db_connection()
        if not conn:
            flash("Database error.", 'error')
            return redirect(url_for('change_password'))

        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT password_hash FROM users WHERE id = %s;', (g.user['id'],))
        user_data = cur.fetchone()
        
        if not bcrypt.check_password_hash(user_data['password_hash'], old_password):
            flash("Incorrect current password.", 'error')
        elif new_password != confirm_password:
            flash("New passwords do not match.", 'error')
        else:
            new_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
            try:
                cur.execute('UPDATE users SET password_hash = %s WHERE id = %s;', (new_hash, g.user['id']))
                conn.commit()
                flash("Your password has been changed successfully.", 'success')
                return redirect(url_for('profile'))
            except Exception as e:
                conn.rollback()
                flash(f"Password update error: {e}", 'error')

        cur.close()
        conn.close()
        return redirect(url_for('change_password'))

    return render_template('change_password.html')

@app.route('/profile')
@login_required
def profile():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    # Display user info (role, group_id, username)
    return render_template('profile.html')


# --- ADMIN ROUTE ---

@app.route('/admin/approve_users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_approve_users():
    conn = get_db_connection()
    if not conn:
        flash("Database error.", 'error'); return redirect(url_for('home'))

    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        user_id = request.form.get('user_id', type=int)
        action = request.form.get('action')
        new_group_id = request.form.get('group_id') or secrets.token_urlsafe(10) # Auto-generate new group ID

        if action == 'approve':
            try:
                cur.execute('UPDATE users SET role = %s, group_id = %s WHERE id = %s;', 
                            ('user', new_group_id, user_id))
                conn.commit()
                flash(f"User ID {user_id} approved and assigned to group {new_group_id}.", 'success')
            except Exception as e:
                conn.rollback()
                flash(f"Approval failed: {e}", 'error')
        elif action == 'delete':
            try:
                cur.execute('DELETE FROM users WHERE id = %s;', (user_id,))
                conn.commit()
                flash(f"User ID {user_id} deleted.", 'success')
            except Exception as e:
                conn.rollback()
                flash(f"Deletion failed: {e}", 'error')
        
        return redirect(url_for('admin_approve_users'))

    # GET request: Fetch pending users and current groups
    cur.execute('SELECT id, username, role, group_id, email FROM users WHERE role = %s OR role = %s ORDER BY id;', 
                ('pending', 'user'))
    pending_users = cur.fetchall()
    
    # Fetch all existing group IDs
    cur.execute('SELECT DISTINCT group_id FROM users WHERE group_id IS NOT NULL AND group_id != %s ORDER BY group_id;', ('pending-group',))
    existing_groups = [row['group_id'] for row in cur.fetchall()]

    cur.close()
    conn.close()
    
    return render_template('admin_approve_users.html', pending_users=pending_users, existing_groups=existing_groups)


# --- MAIN APPLICATION ROUTES ---

@app.route('/')
@login_required
def home():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    # Initialize dashboard data with defaults to prevent template errors if any calculation fails
    default_dashboard_data = {
        'total_asset_usd': 0.0,
        'total_expense_usd': 0.0,
        'net_worth_usd': 0.0,
        'net_worth_inr': 'N/A',
        'assets_by_currency': {},
        'expenses_by_currency': {},
        'reporting_currency': 'USD',
        'secondary_currency': 'INR'
    }
    dashboard_data = default_dashboard_data
    
    conn = get_db_connection()
    if not conn:
        flash("Database connection failure.", 'error'); return render_template('home.html', dashboard_data=dashboard_data)

    cur = conn.cursor(cursor_factory=RealDictCursor)
    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
    
    # 1. Fetch all asset and expense sums grouped by currency for the user's group
    try:
        cur.execute(f"""
            SELECT currency, SUM(value) as total_value
            FROM assets 
            WHERE activate = TRUE {group_filter} 
            GROUP BY currency;
        """, group_params)
        assets_by_currency = {item['currency']: float(item['total_value'] or 0) for item in cur.fetchall()}

        # Note the table name change in group_filter replacement for expenses
        cur.execute(f"""
            SELECT currency, SUM(amount) as total_amount
            FROM expenses 
            WHERE activate = TRUE {group_filter.replace('assets', 'expenses')} 
            GROUP BY currency;
        """, group_params)
        expenses_by_currency = {item['currency']: float(item['total_amount'] or 0) for item in cur.fetchall()}
        
        # 2. Get Exchange Rates (Base to USD for simplification)
        rates = get_exchange_rates('USD') 
        
        if not rates:
            flash("Could not fetch live exchange rates. Displaying sums without conversion.", 'warning')
            rates = {c: (1.0 if c == 'USD' else 0) for c in assets_by_currency.keys() | expenses_by_currency.keys()}

        # Calculate Total Asset Value in USD
        total_asset_usd = 0
        for currency, value in assets_by_currency.items():
            rate = rates.get(currency, 0)
            if rate != 0:
                if currency == 'USD':
                    total_asset_usd += value
                else:
                    # Conversion: Value_in_USD = Value_in_Currency / (Rate of USD to Currency)
                    total_asset_usd += value / rate

        # Calculate Total Expense Value in USD
        total_expense_usd = 0
        for currency, value in expenses_by_currency.items():
            rate = rates.get(currency, 0)
            if rate != 0:
                if currency == 'USD':
                    total_expense_usd += value
                else:
                    total_expense_usd += value / rate

        
        # Convert total USD to INR for the secondary metric
        usd_rate = rates.get('USD', 1.0)
        # Avoid division by zero if USD rate is somehow 0
        usd_to_inr = rates.get('INR', 0) / usd_rate if usd_rate != 0 and rates.get('INR') else 0
        
        dashboard_data = {
            'total_asset_usd': round(total_asset_usd, 2),
            'total_expense_usd': round(total_expense_usd, 2),
            'net_worth_usd': round(total_asset_usd - total_expense_usd, 2),
            'net_worth_inr': round((total_asset_usd - total_expense_usd) * usd_to_inr, 2) if usd_to_inr else 'N/A',
            'assets_by_currency': assets_by_currency,
            'expenses_by_currency': expenses_by_currency,
            'reporting_currency': 'USD',
            'secondary_currency': 'INR'
        }

    except Exception as e:
        print(f"Dashboard calculation error: {e}", file=sys.stderr)
        flash("Error calculating financial summaries. Displaying zeros.", 'error')
        # dashboard_data remains the default zeroed dictionary from initialization
    finally:
        cur.close()
        conn.close()

    return render_template('home.html', dashboard_data=dashboard_data)


# --- ASSET CRUD ROUTES ---

@app.route('/index')
@login_required
def index():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    conn = get_db_connection()
    if not conn: 
        flash("Database connection error.", 'error'); return render_template('index.html', assets=[])
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'a')
    
    try:
        cur.execute(f"""
            SELECT a.id, a.type, a.currency, a.value, a.last_updated, o.name AS owner_name, 
                   a.name, a.account_no, a.financial_institution, a.policy_or_plan_type, a.notes 
            FROM assets a 
            JOIN owners o ON a.owner_id = o.id
            WHERE a.activate = TRUE {group_filter} 
            ORDER BY a.type, a.value DESC;
        """, group_params)
        assets = cur.fetchall()
        
        # DECRYPT sensitive fields
        for asset in assets:
            asset['name'] = encryptor.decrypt(asset['name'])
            asset['account_no'] = encryptor.decrypt(asset['account_no'])
            asset['financial_institution'] = encryptor.decrypt(asset['financial_institution'])
            asset['policy_or_plan_type'] = encryptor.decrypt(asset['policy_or_plan_type'])
            asset['notes'] = encryptor.decrypt(asset['notes'])

    except Exception as e:
        print(f"Asset fetch error: {e}", file=sys.stderr)
        flash("Error retrieving assets.", 'error')
        assets = []
    finally:
        cur.close()
        conn.close()

    return render_template('index.html', assets=assets)

@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    owners = get_owners()
    
    if request.method == 'POST':
        form_data = request.form
        
        # ENCRYPT sensitive fields
        encrypted_name = encryptor.encrypt(form_data['name'])
        encrypted_account_no = encryptor.encrypt(form_data['account_no'])
        encrypted_institution = encryptor.encrypt(form_data['financial_institution'])
        encrypted_beneficiary = encryptor.encrypt(form_data['beneficiary_name'])
        encrypted_policy = encryptor.encrypt(form_data['policy_or_plan_type'])
        encrypted_phone = encryptor.encrypt(form_data['contact_phone'])
        encrypted_document = encryptor.encrypt(form_data['document_location'])
        encrypted_strategy = encryptor.encrypt(form_data['investment_strategy'])
        encrypted_notes = encryptor.encrypt(form_data['notes'])
        
        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", 'error'); return redirect(url_for('add_asset'))
        
        try:
            cur = conn.cursor()
            insert_query = """
                INSERT INTO assets (
                    group_id, owner_id, name, account_no, financial_institution, beneficiary_name, 
                    policy_or_plan_type, contact_phone, document_location, investment_strategy, 
                    notes, type, country, currency, value
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """
            cur.execute(insert_query, (
                g.group_id, form_data['owner_id'], encrypted_name, encrypted_account_no, 
                encrypted_institution, encrypted_beneficiary, encrypted_policy, encrypted_phone, 
                encrypted_document, encrypted_strategy, encrypted_notes, form_data['type'], 
                form_data['country'], form_data['currency'], form_data['value']
            ))
            conn.commit()
            flash("Asset added successfully.", 'success')
            return redirect(url_for('index'))
        except Exception as e:
            conn.rollback()
            flash(f"Error adding asset: {e}", 'error')
        finally:
            cur.close()
            conn.close()
            
    return render_template('add_asset.html', owners=owners)

@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    owners = get_owners()
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", 'error'); return redirect(url_for('index'))
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'a')

    # GET request: Fetch existing data
    if request.method == 'GET':
        cur.execute(f"""
            SELECT a.*, o.name AS owner_name FROM assets a 
            JOIN owners o ON a.owner_id = o.id
            WHERE a.id = %s {group_filter};
        """, (asset_id,) + group_params)
        asset = cur.fetchone()
        
        if asset:
            # DECRYPT sensitive fields
            asset['name'] = encryptor.decrypt(asset['name'])
            asset['account_no'] = encryptor.decrypt(asset['account_no'])
            asset['financial_institution'] = encryptor.decrypt(asset['financial_institution'])
            asset['beneficiary_name'] = encryptor.decrypt(asset['beneficiary_name'])
            asset['policy_or_plan_type'] = encryptor.decrypt(asset['policy_or_plan_type'])
            asset['contact_phone'] = encryptor.decrypt(asset['contact_phone'])
            asset['document_location'] = encryptor.decrypt(asset['document_location'])
            asset['investment_strategy'] = encryptor.decrypt(asset['investment_strategy'])
            asset['notes'] = encryptor.decrypt(asset['notes'])
            
            cur.close()
            conn.close()
            return render_template('edit_asset.html', asset=asset, owners=owners)
        else:
            cur.close(); conn.close()
            flash("Asset not found or unauthorized.", 'error'); return redirect(url_for('index'))

    # POST request: Update data
    elif request.method == 'POST':
        form_data = request.form
        
        # ENCRYPT sensitive fields
        encrypted_name = encryptor.encrypt(form_data['name'])
        encrypted_account_no = encryptor.encrypt(form_data['account_no'])
        encrypted_institution = encryptor.encrypt(form_data['financial_institution'])
        encrypted_beneficiary = encryptor.encrypt(form_data['beneficiary_name'])
        encrypted_policy = encryptor.encrypt(form_data['policy_or_plan_type'])
        encrypted_phone = encryptor.encrypt(form_data['contact_phone'])
        encrypted_document = encryptor.encrypt(form_data['document_location'])
        encrypted_strategy = encryptor.encrypt(form_data['investment_strategy'])
        encrypted_notes = encryptor.encrypt(form_data['notes'])

        try:
            update_query = f"""
                UPDATE assets SET 
                    owner_id = %s, name = %s, account_no = %s, financial_institution = %s, 
                    beneficiary_name = %s, policy_or_plan_type = %s, contact_phone = %s, 
                    document_location = %s, investment_strategy = %s, notes = %s, 
                    type = %s, country = %s, currency = %s, value = %s, last_updated = CURRENT_DATE
                WHERE id = %s {group_filter};
            """
            params = (
                form_data['owner_id'], encrypted_name, encrypted_account_no, encrypted_institution, 
                encrypted_beneficiary, encrypted_policy, encrypted_phone, encrypted_document, 
                encrypted_strategy, encrypted_notes, form_data['type'], form_data['country'], 
                form_data['currency'], form_data['value'], asset_id
            ) + group_params
            
            cur.execute(update_query, params)
            if cur.rowcount == 0: flash("Update failed: Asset not found or unauthorized.", 'error')
            else: flash("Asset updated successfully.", 'success')
            conn.commit()
            return redirect(url_for('index'))
        except Exception as e:
            conn.rollback()
            flash(f"Asset update error: {e}", 'error')
        finally:
            cur.close()
            conn.close()

@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required 
def delete_asset(asset_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = get_db_connection()
    if not conn:
        flash("Database error.", 'error'); return redirect(url_for('index'))

    try:
        cur = conn.cursor()
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
        # Soft delete
        cur.execute(f'UPDATE assets SET activate = FALSE WHERE id = %s {group_filter};', (asset_id,) + group_params)
        if cur.rowcount == 0: 
            flash("Delete failed: Asset not found or unauthorized.", 'error')
        else:
            flash("Asset deleted successfully.", 'success')
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Asset deletion error: {e}", 'error')
    finally:
        cur.close()
        conn.close()
        
    return redirect(url_for('index'))


# --- EXPENSE CRUD ROUTES ---

@app.route('/expenses')
@login_required
def expenses():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    conn = get_db_connection()
    if not conn: 
        flash("Database connection error.", 'error'); return render_template('expenses.html', expenses=[])
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
    
    try:
        cur.execute(f"""
            SELECT e.id, e.category, e.amount, e.currency, e.expense_date, o.name AS owner_name, e.description, e.notes 
            FROM expenses e 
            JOIN owners o ON e.owner_id = o.id
            WHERE e.activate = TRUE {group_filter} 
            ORDER BY e.expense_date DESC;
        """, group_params)
        expenses = cur.fetchall()
        
        # DECRYPT sensitive fields
        for expense in expenses:
            expense['description'] = encryptor.decrypt(expense['description'])
            expense['notes'] = encryptor.decrypt(expense['notes'])

    except Exception as e:
        print(f"Expense fetch error: {e}", file=sys.stderr)
        flash("Error retrieving expenses.", 'error')
        expenses = []
    finally:
        cur.close()
        conn.close()

    return render_template('expenses.html', expenses=expenses)


@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    owners = get_owners()
    
    if request.method == 'POST':
        form_data = request.form
        
        # ENCRYPT sensitive fields
        encrypted_description = encryptor.encrypt(form_data['description'])
        encrypted_notes = encryptor.encrypt(form_data['notes'])
        
        conn = get_db_connection()
        if not conn:
            flash("Database connection error.", 'error'); return redirect(url_for('add_expense'))
        
        try:
            cur = conn.cursor()
            insert_query = """
                INSERT INTO expenses (
                    group_id, owner_id, description, notes, category, amount, currency, expense_date
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """
            cur.execute(insert_query, (
                g.group_id, form_data['owner_id'], encrypted_description, encrypted_notes, 
                form_data['category'], form_data['amount'], form_data['currency'], form_data['expense_date']
            ))
            conn.commit()
            flash("Expense added successfully.", 'success')
            return redirect(url_for('expenses'))
        except Exception as e:
            conn.rollback()
            flash(f"Error adding expense: {e}", 'error')
        finally:
            cur.close()
            conn.close()
            
    return render_template('add_expense.html', owners=owners)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    owners = get_owners()
    conn = get_db_connection()
    if not conn:
        flash("Database connection error.", 'error'); return redirect(url_for('expenses'))
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')

    # GET request: Fetch existing data
    if request.method == 'GET':
        cur.execute(f"""
            SELECT e.*, o.name AS owner_name FROM expenses e 
            JOIN owners o ON e.owner_id = o.id
            WHERE e.id = %s {group_filter};
        """, (expense_id,) + group_params)
        expense = cur.fetchone()
        
        if expense:
            # DECRYPT sensitive fields
            expense['description'] = encryptor.decrypt(expense['description'])
            expense['notes'] = encryptor.decrypt(expense['notes'])
            
            cur.close()
            conn.close()
            return render_template('edit_expense.html', expense=expense, owners=owners)
        else:
            cur.close(); conn.close()
            flash("Expense not found or unauthorized.", 'error'); return redirect(url_for('expenses'))

    # POST request: Update data
    elif request.method == 'POST':
        form_data = request.form
        
        # ENCRYPT sensitive fields
        encrypted_description = encryptor.encrypt(form_data['description'])
        encrypted_notes = encryptor.encrypt(form_data['notes'])

        try:
            update_query = f"""
                UPDATE expenses SET 
                    owner_id = %s, description = %s, notes = %s, category = %s, 
                    amount = %s, currency = %s, expense_date = %s
                WHERE id = %s {group_filter};
            """
            params = (
                form_data['owner_id'], encrypted_description, encrypted_notes, form_data['category'], 
                form_data['amount'], form_data['currency'], form_data['expense_date'], expense_id
            ) + group_params
            
            cur.execute(update_query, params)
            if cur.rowcount == 0: flash("Update failed: Expense not found or unauthorized.", 'error')
            else: flash("Expense updated successfully.", 'success')
            conn.commit()
            return redirect(url_for('expenses'))
        except Exception as e:
            conn.rollback()
            flash(f"Expense update error: {e}", 'error')
        finally:
            cur.close()
            conn.close()


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required 
def delete_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = get_db_connection()
    if not conn:
        flash("Database error.", 'error'); return redirect(url_for('expenses'))

    try:
        cur = conn.cursor()
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        # Soft delete
        cur.execute(f'UPDATE expenses SET activate = FALSE WHERE id = %s {group_filter};', (expense_id,) + group_params)
        if cur.rowcount == 0: 
            flash("Delete failed: Expense not found or unauthorized.", 'error')
        else:
            flash("Expense deleted successfully.", 'success')
        conn.commit()
    except Exception as e:
        conn.rollback()
        flash(f"Expense deletion error: {e}", 'error')
    finally:
        cur.close()
        conn.close()
        
    return redirect(url_for('expenses'))


# --- ERROR HANDLERS ---

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', code=403, message="Access Denied. You do not have permission to view this resource."), 403

@app.errorhandler(404)
def page_not_found(error):
    return render_template('error.html', code=404, message="The page you are looking for does not exist or has been moved."), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('error.html', code=500, message="A server error occurred. We have been notified of the issue and are working to fix it."), 500


if __name__ == '__main__':
    # WARNING: On a production server like Render, set debug=False.
    # The production environment will handle running the app via a WSGI server (e.g., Gunicorn).
    app.run(debug=True)
