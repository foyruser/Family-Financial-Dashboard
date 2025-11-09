from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools
import os
import sys
from cryptography.fernet import Fernet
import secrets
from datetime import datetime, timedelta
import smtplib 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- APPLICATION INITIALIZATION & CONFIG ---
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_long_random_fallback_key') 
bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL') 
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY')
FERNET_KEY = os.environ.get('FERNET_KEY')

# --- ENCRYPTOR IMPLEMENTATION (Field-Level Encryption) ---
class Encryptor:
    """Handles encryption and decryption of sensitive fields."""
    def __init__(self, key):
        if not key:
            print("WARNING: FERNET_KEY not set. Using fallback key. DO NOT use in production.", file=sys.stderr)
            # Use a dummy key if env variable is missing, but warn the user.
            key = Fernet.generate_key().decode()
        
        self.f = Fernet(key.encode())

    def encrypt(self, data):
        """Encrypts a string or bytes object."""
        if isinstance(data, str):
            data = data.encode()
        return self.f.encrypt(data).decode()

    def decrypt(self, token):
        """Decrypts a token back to a string."""
        if isinstance(token, str):
            token = token.encode()
        try:
            return self.f.decrypt(token).decode()
        except Exception as e:
            print(f"Decryption error: {e}", file=sys.stderr)
            return ""

# Initialize Encryptor globally
encryptor = Encryptor(FERNET_KEY)

# --- DATABASE CONNECTION & UTILITY ---
def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable is not set.")
    return psycopg2.connect(DATABASE_URL, sslmode='require')

def get_exchange_rate(base_currency):
    """Fetches the exchange rate for the base_currency to USD."""
    if base_currency.upper() == 'USD':
        return 1.0

    if not EXCHANGE_RATE_API_KEY:
        print("WARNING: EXCHANGE_RATE_API_KEY not set. Cannot fetch live rates.", file=sys.stderr)
        # Fallback to 1.0 if API key is missing (bad, but prevents crash)
        return 1.0

    try:
        # Using a reliable exchange rate API (example structure)
        url = f"https://api.freecurrencyapi.com/v1/latest?apikey={EXCHANGE_RATE_API_KEY}&base_currency={base_currency}&currencies=USD"
        response = requests.get(url)
        response.raise_for_status() # Raises an HTTPError for bad responses
        data = response.json()
        
        # The API usually returns the value of USD relative to the base_currency
        rate_to_usd = data['data'].get('USD')
        if rate_to_usd:
             # The result is the value of 1 unit of base_currency in USD.
             return 1 / rate_to_usd 
        
        # Fallback if the specific currency is missing from the response
        return 1.0 
    
    except requests.RequestException as e:
        print(f"Error fetching exchange rate for {base_currency}: {e}", file=sys.stderr)
        # In case of API failure, assume 1.0 to prevent crash, but log error
        return 1.0 
    except Exception as e:
        print(f"Unexpected error in get_exchange_rate: {e}", file=sys.stderr)
        return 1.0

def execute_query(query, params=(), fetch_one=False):
    """A generic function to execute non-SELECT queries."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(query, params)
        
        if fetch_one:
            result = cur.fetchone()
        else:
            result = cur.fetchall()

        conn.commit()
        return result
    except psycopg2.Error as e:
        print(f"Database query error: {e}", file=sys.stderr)
        return None
    finally:
        if conn: cur.close(); conn.close()

# --- AUTHENTICATION & GROUP MANAGEMENT UTILITY ---

def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

def verify_password(hashed_password, password):
    return bcrypt.check_password_hash(hashed_password, password)

def generate_reset_token():
    """Generates a secure, temporary password reset token."""
    return secrets.token_urlsafe(32)

def send_password_reset_email(user_email, token):
    """
    STUB: Sends a password reset email to the user.
    In a real app, this would use a robust email service (SendGrid, Mailgun, etc.).
    """
    reset_link = url_for('reset_password', token=token, _external=True)
    
    # Check if a mail server is configured (SMTP_SERVER, etc.)
    if not os.environ.get('SMTP_SERVER'):
        print(f"STUB: Password reset link generated for {user_email}: {reset_link}", file=sys.stderr)
        return

    msg = MIMEMultipart()
    msg['From'] = os.environ.get('SMTP_USER', 'noreply@financetracker.com')
    msg['To'] = user_email
    msg['Subject'] = 'Password Reset Request'
    
    body = f"""
    You have requested a password reset for your Financial Tracker account.
    Click the link below to reset your password. This link will expire in 1 hour.

    {reset_link}

    If you did not request this, please ignore this email.
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Example for a simple SMTP server setup
        server = smtplib.SMTP_SSL(os.environ.get('SMTP_SERVER'), os.environ.get('SMTP_PORT', 465))
        server.login(os.environ.get('SMTP_USER'), os.environ.get('SMTP_PASSWORD'))
        server.sendmail(msg['From'], user_email, msg.as_string())
        server.quit()
        print(f"Password reset email sent to {user_email}")
    except Exception as e:
        print(f"Error sending email: {e}", file=sys.stderr)


def get_group_filter_clause(user_role, group_id, table_name):
    """Constructs the WHERE clause for group access."""
    if user_role == 'admin':
        # Admins see everything
        return '', ()
    elif group_id:
        # Standard users see only their group's data
        return f' AND {table_name}.group_id = %s', (group_id,)
    else:
        # Should not happen if user is logged in, but as a safeguard
        return ' AND 1 = 0', () # Return no rows

@app.before_request
def load_logged_in_user():
    """Loads user and group info from session before each request."""
    user_id = session.get('user_id')
    g.user = None
    g.user_id = None
    g.group_id = None
    g.user_role = 'guest' # Default role

    if user_id is None:
        return
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username, email, group_id, role FROM users WHERE id = %s;", (user_id,))
        user = cur.fetchone()
        
        if user:
            g.user = user
            g.user_id = user['id']
            g.group_id = user['group_id']
            g.user_role = user['role']
        else:
            session.pop('user_id', None) # Clear session if user is not found
    except psycopg2.Error as e:
        print(f"DB Error loading user: {e}", file=sys.stderr)
        session.pop('user_id', None)
    finally:
        if conn: cur.close(); conn.close()

def login_required(view):
    """Decorator for views that require user authentication."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def check_user_access():
    """Checks if the user has a group_id or is an admin, otherwise denies access to core features."""
    if g.user_role != 'admin' and g.group_id is None:
        flash('Access Denied: You must be assigned to a family group to use the financial tracker features.', 'error')
        return redirect(url_for('home')) # Redirect to home/dashboard if unauthorized
    return None

# --- CORE DATA FETCHING FUNCTIONS (FIXED) ---

def fetch_assets(user_id=None, group_id=None, user_role=None):
    """
    Fetches active assets, dynamically calculating usd_value in Python (FIXED).
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        group_filter, group_params = get_group_filter_clause(user_role, group_id, 'assets')
        
        # FIX: Removed a.usd_value reference
        query = f"""
            SELECT a.id, a.name, a.description, a.type, a.value AS amount, a.currency
            FROM assets a
            WHERE a.activate = TRUE {group_filter}
            ORDER BY a.name;
        """
        cur.execute(query, group_params)
        assets = cur.fetchall()
        
        # Calculate USD value for each asset (REQUIRED FIX)
        for asset in assets:
            rate = get_exchange_rate(asset['currency'])
            asset['usd_value'] = float(asset['amount']) / rate if rate else 0.0
            
        return assets
    except psycopg2.Error as e:
        print(f"Error fetching assets: {e}", file=sys.stderr)
        # CRASH PREVENTION: Return empty list on error
        return []
    finally:
        if conn: cur.close(); conn.close()


def fetch_expenses(user_id=None, group_id=None, user_role=None):
    """
    Fetches active expenses, dynamically calculating usd_value in Python (FIXED).
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        group_filter, group_params = get_group_filter_clause(user_role, group_id, 'expenses')

        # FIX: Removed e.usd_value reference
        query = f"""
            SELECT e.id, e.amount, e.currency, e.description, e.category, e.date, e.user_id, e.group_id
            FROM expenses e
            WHERE e.activate = TRUE {group_filter}
            ORDER BY e.date DESC;
        """
        cur.execute(query, group_params)
        expenses = cur.fetchall()
        
        # Calculate USD value for each expense (REQUIRED FIX)
        for expense in expenses:
            rate = get_exchange_rate(expense['currency'])
            expense['usd_value'] = float(expense['amount']) / rate if rate else 0.0

        return expenses
    except psycopg2.Error as e:
        print(f"Error fetching expenses: {e}", file=sys.stderr)
        # CRASH PREVENTION: Return empty list on error
        return []
    finally:
        if conn: cur.close(); conn.close()


def calculate_financial_summary(assets, expenses):
    """
    Calculates the financial summary (total assets, total liabilities, net worth).
    Uses the pre-calculated 'usd_value' from fetch_assets/fetch_expenses.
    """
    # CRASH PREVENTION: Wrap in try/except and return default on failure
    try:
        total_assets_usd = sum(a['usd_value'] for a in assets if a.get('type') != 'Liability')
        total_liabilities_usd = sum(a['usd_value'] for a in assets if a.get('type') == 'Liability')
        
        total_expenses_usd = sum(e['usd_value'] for e in expenses)

        net_worth_usd = total_assets_usd - total_liabilities_usd
        
        return {
            'total_assets_usd': total_assets_usd,
            'total_liabilities_usd': total_liabilities_usd,
            'net_worth_usd': net_worth_usd,
            'total_expenses_usd': total_expenses_usd,
        }
    except Exception as e:
        print(f"Error calculating financial summary: {e}", file=sys.stderr)
        # CRITICAL FIX: Return a default summary object on processing failure
        return {
            'total_assets_usd': 0.0,
            'total_liabilities_usd': 0.0,
            'net_worth_usd': 0.0,
            'total_expenses_usd': 0.0,
        }


def calculate_asset_breakdown(assets):
    """Calculates breakdown of assets by type."""
    breakdown = {}
    for asset in assets:
        asset_type = asset.get('type', 'Other')
        # Use the dynamically calculated usd_value
        usd_val = asset.get('usd_value', 0.0)
        breakdown[asset_type] = breakdown.get(asset_type, 0.0) + usd_val

    # Convert to a list of dicts for Jinja templating (Name, Value)
    return [{'name': k, 'value': v} for k, v in breakdown.items()]


def get_lists():
    """Returns static lists for categories, types, and currencies."""
    return {
        'asset_types': ['Cash', 'Bank Account', 'Investment', 'Real Estate', 'Vehicle', 'Liability', 'Other'],
        'expense_categories': ['Housing', 'Food', 'Transport', 'Utilities', 'Healthcare', 'Entertainment', 'Debt', 'Other'],
        'currencies': ['USD', 'EUR', 'GBP', 'JPY', 'CAD', 'AUD', 'INR', 'BRL', 'MXN', 'TRY']
    }

# --- AUTH VIEWS ---

@app.route('/register', methods=('GET', 'POST'))
def register():
    # ... (Registration logic - unchanged)
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        hashed_password = hash_password(password)
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            # Attempt to insert new user (default role 'member', group_id NULL)
            cur.execute(
                "INSERT INTO users (username, email, password, role) VALUES (%s, %s, %s, %s);",
                (username, email, hashed_password, 'member')
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            flash('User with that email or username already exists.', 'error')
        except Exception as e:
            flash(f'An error occurred during registration: {e}', 'error')
            print(f"Registration error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()
            
    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    # ... (Login logic - unchanged)
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = None
        user = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, password, username, group_id, role FROM users WHERE email = %s;", (email,))
            user = cur.fetchone()
        except Exception as e:
            print(f"Login DB error: {e}", file=sys.stderr)
            flash("A server error occurred during login.", 'error')
            return render_template('login.html')
        finally:
            if conn: cur.close(); conn.close()
            
        if user and verify_password(user['password'], password):
            session['user_id'] = user['id']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    # ... (Logout logic - unchanged)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # ... (Forgot Password logic - unchanged)
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("Please enter your email address.", 'error')
            return render_template('forgot_password.html')

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
            user = cur.fetchone()
            
            if user:
                token = generate_reset_token()
                expires = datetime.now() + timedelta(hours=1)
                
                cur.execute(
                    "UPDATE users SET reset_token = %s, reset_token_expires = %s WHERE id = %s;",
                    (token, expires, user['id'])
                )
                conn.commit()
                
                send_password_reset_email(email, token)
                flash("A password reset link has been sent to your email.", 'success')
                return redirect(url_for('login'))
            else:
                flash("If the email is registered, a password reset link has been sent.", 'info')
                return redirect(url_for('login'))
                
        except Exception as e:
            flash(f"An error occurred: {e}", 'error')
            print(f"Forgot password error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()
            
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # ... (Reset Password logic - unchanged)
    conn = None
    user = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check for valid token and expiry
        cur.execute(
            "SELECT id, username FROM users WHERE reset_token = %s AND reset_token_expires > NOW();",
            (token,)
        )
        user = cur.fetchone()
    except Exception as e:
        flash(f"A server error occurred: {e}", 'error')
        print(f"Reset password initial error: {e}", file=sys.stderr)
        if conn: cur.close(); conn.close()
        return redirect(url_for('forgot_password'))
        
    if not user:
        flash("Invalid or expired token.", 'error')
        if conn: cur.close(); conn.close()
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", 'error')
            if conn: cur.close(); conn.close()
            return render_template('reset_password.html', token=token)

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", 'error')
            if conn: cur.close(); cur.close()
            return render_template('reset_password.html', token=token)

        try:
            hashed_password = hash_password(new_password)
            
            # Update password and clear the token/expiry
            cur.execute(
                "UPDATE users SET password = %s, reset_token = NULL, reset_token_expires = NULL WHERE id = %s;",
                (hashed_password, user['id'])
            )
            conn.commit()
            flash("Your password has been successfully reset. Please log in.", 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred while resetting the password: {e}", 'error')
            print(f"Password reset error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()

    if conn: cur.close(); conn.close()
    return render_template('reset_password.html', token=token)


# --- DASHBOARD VIEW (FIXED) ---

@app.route('/')
@login_required
def home():
    """Dashboard view showing summary and recent activity."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    # CRITICAL FIX: Initialize all variables to a safe default before fetching data
    summary = {
        'total_assets_usd': 0.0,
        'total_liabilities_usd': 0.0,
        'net_worth_usd': 0.0,
        'total_expenses_usd': 0.0,
    }
    last_expenses = []
    asset_breakdown = []
    
    try:
        # Fetch all data (uses the FIXED fetch functions)
        assets = fetch_assets(g.user_id, g.group_id, g.user_role)
        expenses = fetch_expenses(g.user_id, g.group_id, g.user_role)

        # Process data
        summary = calculate_financial_summary(assets, expenses)
        # Get last 5 expenses
        last_expenses = sorted(expenses, key=lambda x: x['date'], reverse=True)[:5]
        asset_breakdown = calculate_asset_breakdown(assets)

    except Exception as e:
        # This catches any remaining errors during processing, but the DB error is handled in fetch_*
        print(f"General error in home view: {e}", file=sys.stderr)
    
    # CRITICAL FIX: 'summary' is always defined and passed to the template
    return render_template('home.html',
                           group_id=g.group_id,
                           user_role=g.user_role,
                           summary=summary,
                           last_expenses=last_expenses,
                           asset_breakdown=asset_breakdown)


# --- ASSET VIEWS (FIXED) ---

@app.route('/assets')
@login_required
def index():
    """Assets list view (index endpoint)."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    # CRITICAL FIX: Initialize assets to a safe default
    assets = []
    summary = {
        'total_assets_usd': 0.0,
        'total_liabilities_usd': 0.0,
    }

    try:
        # Fetch assets (uses the FIXED fetch function)
        assets = fetch_assets(g.user_id, g.group_id, g.user_role)
        
        # Calculate summary for display on the Assets page
        # Fetch expenses here too for complete summary, though only assets are needed for the list
        expenses = fetch_expenses(g.user_id, g.group_id, g.user_role) 
        summary = calculate_financial_summary(assets, expenses)

    except Exception as e:
        print(f"General error in index view: {e}", file=sys.stderr)

    return render_template('index.html', assets=assets, summary=summary)


@app.route('/assets/add', methods=['GET', 'POST'])
@login_required
def add_asset():
    """Add new asset view."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = get_lists()
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        asset_type = request.form['type']
        value = request.form['value']
        currency = request.form['currency']
        
        if not name or not value:
            flash('Name and Value are required fields.', 'error')
            return render_template('add_asset.html', **lists)

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Insert asset, linking to current user and group
            cur.execute(
                "INSERT INTO assets (name, description, type, value, currency, user_id, group_id) VALUES (%s, %s, %s, %s, %s, %s, %s);",
                (name, description, asset_type, value, currency, g.user_id, g.group_id)
            )
            
            conn.commit()
            flash(f"Asset '{name}' successfully added.", 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f"Error adding asset: {e}", 'error')
            print(f"Asset addition error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()

    return render_template('add_asset.html', **lists)


@app.route('/assets/edit/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    """Edit existing asset view."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = get_lists()
    asset = None
    conn = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'a')
        # Fetch existing asset details
        cur.execute(f"SELECT id, name, description, type, value, currency FROM assets a WHERE id = %s {group_filter};", (asset_id,) + group_params)
        asset = cur.fetchone()
        
        if not asset:
            flash("Asset not found or unauthorized.", 'error')
            return redirect(url_for('index'))
            
        # Re-fetch asset after post to ensure data is fresh if something went wrong
        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            asset_type = request.form['type']
            value = request.form['value']
            currency = request.form['currency']

            if not name or not value:
                flash('Name and Value are required fields.', 'error')
                return render_template('edit_asset.html', asset=asset, **lists)

            # Update asset
            cur.execute(
                f"UPDATE assets SET name = %s, description = %s, type = %s, value = %s, currency = %s WHERE id = %s {group_filter};",
                (name, description, asset_type, value, currency, asset_id) + group_params
            )
            
            if cur.rowcount == 0:
                 flash("Update failed: Asset not found or unauthorized.", 'error')
                 conn.commit()
                 return redirect(url_for('index'))

            conn.commit()
            flash(f"Asset '{name}' successfully updated.", 'success')
            return redirect(url_for('index'))
            
    except Exception as e:
        flash(f"Error updating asset: {e}", 'error')
        print(f"Asset update error: {e}", file=sys.stderr)
        if request.method == 'POST':
             # Return to the form with an error message
             return render_template('edit_asset.html', asset=asset, **lists)
    finally:
        if conn: cur.close(); conn.close()
    
    return render_template('edit_asset.html', asset=asset, **lists)


@app.route('/assets/delete/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    """Delete existing asset (soft delete)."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Soft delete: set activate = FALSE
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
        cur.execute(f'UPDATE assets SET activate = FALSE WHERE id = %s {group_filter};', (asset_id,) + group_params)
        
        if cur.rowcount == 0:
            flash("Delete failed: Asset not found or unauthorized.", 'error')
            return redirect(url_for('index'))
            
        conn.commit()
        flash("Asset successfully removed.", 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        flash(f"Error deleting asset: {e}", 'error')
        print(f"Asset deletion error: {e}", file=sys.stderr)
        return redirect(url_for('index'))
    finally:
        if conn: cur.close(); conn.close()


# --- EXPENSE VIEWS ---

@app.route('/expenses')
@login_required
def expenses():
    """Expenses list view."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    # CRITICAL FIX: Initialize expenses to a safe default
    expenses = []
    
    try:
        # Fetch expenses (uses the FIXED fetch function)
        expenses = fetch_expenses(g.user_id, g.group_id, g.user_role)
    except Exception as e:
        print(f"General error in expenses view: {e}", file=sys.stderr)

    return render_template('expenses.html', expenses=expenses)


@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    """Add new expense view."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = get_lists()
    
    if request.method == 'POST':
        date = request.form['date']
        amount = request.form['amount']
        currency = request.form['currency']
        category = request.form['category']
        description = request.form['description']
        
        if not date or not amount:
            flash('Date and Amount are required fields.', 'error')
            return render_template('add_expense.html', **lists)

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Insert expense, linking to current user and group
            cur.execute(
                "INSERT INTO expenses (date, amount, currency, category, description, user_id, group_id) VALUES (%s, %s, %s, %s, %s, %s, %s);",
                (date, amount, currency, category, description, g.user_id, g.group_id)
            )
            
            conn.commit()
            flash(f"Expense of {amount} {currency} on {date} successfully added.", 'success')
            return redirect(url_for('expenses'))
            
        except Exception as e:
            flash(f"Error adding expense: {e}", 'error')
            print(f"Expense addition error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()

    return render_template('add_expense.html', **lists)


@app.route('/expenses/edit/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    """Edit existing expense view."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = get_lists()
    expense = None
    conn = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
        # Fetch existing expense details
        cur.execute(f"SELECT id, date, amount, currency, category, description FROM expenses e WHERE id = %s {group_filter};", (expense_id,) + group_params)
        expense = cur.fetchone()
        
        if not expense:
            flash("Expense not found or unauthorized.", 'error')
            return redirect(url_for('expenses'))
            
        if request.method == 'POST':
            date = request.form['date']
            amount = request.form['amount']
            currency = request.form['currency']
            category = request.form['category']
            description = request.form['description']

            if not date or not amount:
                flash('Date and Amount are required fields.', 'error')
                # Re-render with existing expense data if validation fails
                expense['date'] = date
                expense['amount'] = amount
                expense['currency'] = currency
                expense['category'] = category
                expense['description'] = description
                return render_template('edit_expense.html', expense=expense, **lists)

            # Update expense
            cur.execute(
                f"UPDATE expenses SET date = %s, amount = %s, currency = %s, category = %s, description = %s WHERE id = %s {group_filter};",
                (date, amount, currency, category, description, expense_id) + group_params
            )
            
            if cur.rowcount == 0:
                 flash("Update failed: Expense not found or unauthorized.", 'error')
                 conn.commit()
                 return redirect(url_for('expenses'))

            conn.commit()
            flash("Expense successfully updated.", 'success')
            return redirect(url_for('expenses'))
            
    except Exception as e:
        flash(f"Error updating expense: {e}", 'error')
        print(f"Expense update error: {e}", file=sys.stderr)
        if request.method == 'POST':
             return redirect(url_for('edit_expense', expense_id=expense_id))
    finally:
        if conn: cur.close(); conn.close()
    
    return render_template('edit_expense.html', expense=expense, **lists)


@app.route('/expenses/delete/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    """Delete existing expense (soft delete)."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Soft delete: set activate = FALSE
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        cur.execute(f'UPDATE expenses SET activate = FALSE WHERE id = %s {group_filter};', (expense_id,) + group_params)
        
        if cur.rowcount == 0:
            flash("Delete failed: Expense not found or unauthorized.", 'error')
            return redirect(url_for('expenses'))
            
        conn.commit()
        flash("Expense successfully removed.", 'success')
        return redirect(url_for('expenses'))
        
    except Exception as e:
        flash(f"Error deleting expense: {e}", 'error')
        print(f"Expense deletion error: {e}", file=sys.stderr)
        return redirect(url_for('expenses'))
    finally:
        if conn: cur.close(); conn.close()


# --- CURRENCIES VIEW ---

@app.route('/currencies')
@login_required
def currencies():
    # ... (Currencies logic - unchanged)
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    lists = get_lists()
    currency_data = []

    # Get rate for each defined currency against USD
    for currency in lists['currencies']:
        rate = get_exchange_rate(currency)
        
        # If the rate fetched is the value of 1 BASE_CURRENCY in USD, 
        # we display 1 USD = X BASE_CURRENCY (1 / rate)
        usd_to_currency = 1.0 / rate if rate and rate != 0 else 'N/A'
        
        currency_data.append({
            'code': currency,
            'rate_to_usd': rate,
            'usd_to_rate': usd_to_currency
        })

    return render_template('currencies.html', currency_data=currency_data)


# --- REPORTS VIEW ---

@app.route('/reports')
@login_required
def reports():
    # ... (Reports logic - unchanged)
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    # CRITICAL FIX: Initialize all variables to a safe default
    assets = []
    expenses = []
    expense_breakdown = []
    
    try:
        assets = fetch_assets(g.user_id, g.group_id, g.user_role)
        expenses = fetch_expenses(g.user_id, g.group_id, g.user_role)

        # 1. Expense Breakdown by Category (in USD)
        expense_breakdown_dict = {}
        for expense in expenses:
            category = expense.get('category', 'Uncategorized')
            usd_val = expense.get('usd_value', 0.0)
            expense_breakdown_dict[category] = expense_breakdown_dict.get(category, 0.0) + usd_val
        
        expense_breakdown = [{'category': k, 'total_usd': v} for k, v in expense_breakdown_dict.items()]

        # 2. Monthly Expense Trend (simple calculation)
        monthly_trend = {}
        for expense in expenses:
            month_year = expense['date'].strftime('%Y-%m') # Requires 'date' field to be a datetime object
            usd_val = expense.get('usd_value', 0.0)
            monthly_trend[month_year] = monthly_trend.get(month_year, 0.0) + usd_val
        
        # Format for display/charting
        monthly_trend_list = [{'month': k, 'total_usd': v} for k, v in sorted(monthly_trend.items())]


    except Exception as e:
        print(f"Error generating reports data: {e}", file=sys.stderr)
    
    summary = calculate_financial_summary(assets, expenses) # Still useful for context

    return render_template('reports.html', 
                           expense_breakdown=expense_breakdown,
                           monthly_trend=monthly_trend_list,
                           summary=summary)

# --- USER MANAGEMENT VIEWS (Admin Only) ---

@app.route('/users', methods=['GET', 'POST'])
@login_required
def users():
    # ... (Users logic - unchanged)
    if g.user_role != 'admin':
        flash('Permission Denied: Only administrators can manage users.', 'error')
        return redirect(url_for('home'))

    conn = None
    users_list = []
    groups_list = []

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch all users
        cur.execute("SELECT id, username, email, group_id, role, EXTRACT(epoch FROM created_at) AS created_at_ts FROM users ORDER BY username;")
        users_list = cur.fetchall()
        
        # Fetch all groups
        cur.execute("SELECT id, name FROM groups ORDER BY name;")
        groups_list = cur.fetchall()
        
        # Action processing (Add Group or Assign User)
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'add_group':
                group_name = request.form.get('group_name')
                if group_name:
                    cur.execute("INSERT INTO groups (name) VALUES (%s) RETURNING id;", (group_name,))
                    new_group = cur.fetchone()
                    conn.commit()
                    flash(f"Group '{group_name}' added (ID: {new_group['id']}).", 'success')
                else:
                    flash("Group name cannot be empty.", 'error')
            
            elif action == 'assign_user':
                user_id = request.form.get('user_id')
                new_group_id = request.form.get('new_group_id')
                new_role = request.form.get('new_role')
                
                # Convert 'None' string from form to actual NULL/None
                if new_group_id == 'None':
                    new_group_id = None
                
                # Basic validation
                if not user_id or not new_role:
                    flash("User ID and Role are required.", 'error')
                else:
                    # Update user's group and role
                    cur.execute(
                        "UPDATE users SET group_id = %s, role = %s WHERE id = %s;",
                        (new_group_id, new_role, user_id)
                    )
                    conn.commit()
                    flash("User successfully updated.", 'success')

            # Redirect after POST to see updated lists
            return redirect(url_for('users'))

    except Exception as e:
        flash(f"An error occurred in user/group management: {e}", 'error')
        print(f"User/Group Management error: {e}", file=sys.stderr)
    finally:
        if conn: cur.close(); conn.close()
        
    return render_template('users.html', users=users_list, groups=groups_list)


# --- ENCRYPTED FIELD VIEW ---

@app.route('/secret_info', methods=['GET', 'POST'])
@login_required
def secret_info():
    # ... (Secret Info logic - unchanged)
    if g.user_role == 'guest':
        flash('Access Denied.', 'error')
        return redirect(url_for('home'))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # 1. Fetch current encrypted data
        cur.execute("SELECT encrypted_data FROM user_secrets WHERE user_id = %s;", (g.user_id,))
        secret_record = cur.fetchone()
        
        display_data = ""
        encrypted_token = ""
        
        if secret_record and secret_record['encrypted_data']:
            encrypted_token = secret_record['encrypted_data']
            # Decrypt for display
            display_data = encryptor.decrypt(encrypted_token)

        # 2. Handle POST request to save new data
        if request.method == 'POST':
            raw_data = request.form.get('secret_data')
            
            if raw_data:
                # Encrypt raw data for storage
                encrypted_data = encryptor.encrypt(raw_data)
                
                cur.execute(
                    "INSERT INTO user_secrets (user_id, encrypted_data) VALUES (%s, %s) ON CONFLICT (user_id) DO UPDATE SET encrypted_data = EXCLUDED.encrypted_data;",
                    (g.user_id, encrypted_data)
                )
                conn.commit()
                flash("Secret information successfully encrypted and saved.", 'success')
                # Redirect to GET to show decrypted data
                return redirect(url_for('secret_info'))
            else:
                flash("Data field cannot be empty.", 'error')
                
    except Exception as e:
        flash(f"An error occurred while handling secret data: {e}", 'error')
        print(f"Secret info error: {e}", file=sys.stderr)
    finally:
        if conn: cur.close(); conn.close()

    # If GET or POST failed, render the form with current data
    return render_template('secret_info.html', encrypted_token=encrypted_token, display_data=display_data)

if __name__ == '__main__':
    # Flask runs on port 5000 by default, but Render/deployment environments might use 
    # the PORT environment variable.
    port = int(os.environ.get('PORT', 5000))
    # In a real setup, ensure debug is False in production
    app.run(host='0.0.0.0', port=port, debug=True)
