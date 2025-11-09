from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools
import os
import sys
# New: For field-level encryption
from cryptography.fernet import Fernet
# New: For password reset token generation and expiry
import secrets
from datetime import datetime, timedelta
import smtplib # Used for the email stub function

# --- APPLICATION INITIALIZATION & CONFIG ---
app = Flask(__name__)
# CRITICAL: SET FLASK_SECRET_KEY ENVIRONMENT VARIABLE FOR PRODUCTION
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_long_random_fallback_key') 
bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL') 
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY')
# CRITICAL: Fernet Encryption Key
FERNET_KEY = os.environ.get('FERNET_KEY')

# --- ENCRYPTOR IMPLEMENTATION ---
class Encryptor:
    def __init__(self, key):
        if not key:
            raise ValueError("Encryption key cannot be empty.")
        self.f = Fernet(key)

    def encrypt(self, data):
        if data is None or data == '':
            return None
        # data is encoded to bytes, encrypted, and then decoded to string for DB storage
        return self.f.encrypt(data.encode()).decode()

    def decrypt(self, data):
        if data is None or data == '':
            return None
        # data is encoded back to bytes, decrypted, and then decoded to string
        return self.f.decrypt(data.encode()).decode()
# Initialise Encryptor
try:
    encryptor = Encryptor(FERNET_KEY)
except ValueError as e:
    # Handle the error, maybe log it and exit, or use a dummy Encryptor
    print(f"FATAL ERROR: Failed to initialize Encryptor: {e}")
    sys.exit(1)


# --- DATABASE CONNECTION ---
def get_db_connection():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

# --- AUTHENTICATION & GROUP UTILITIES ---

# Placeholder for email function
def send_email(to_email, subject, body):
    """Placeholder function for sending emails."""
    print(f"--- Sending Email ---")
    print(f"To: {to_email}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")
    print(f"---------------------")

# Login required decorator
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in to access this page.", 'warning')
            return redirect(url_for('login'))
        
        # Re-fetch user details and set global variables on every request
        user_id = session.get('user_id')
        conn = get_db_connection()
        if conn:
            try:
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute("SELECT id, name, group_id, role FROM users WHERE id = %s;", (user_id,))
                user = cur.fetchone()
                if user:
                    g.user_id = user['id']
                    g.user_name = user['name']
                    g.group_id = user['group_id']
                    g.user_role = user['role'] # 'admin' or 'member'
                else:
                    session.pop('user_id', None)
                    flash("User not found, please log in again.", 'error')
                    return redirect(url_for('login'))
            finally:
                cur.close()
                conn.close()
        
        return view(*args, **kwargs)
    return wrapped_view

# Group filter helper
def get_group_filter_clause(user_role, group_id, table_alias):
    """
    Returns SQL WHERE clause and parameters for filtering data by group.
    Admins see everything in the group. Members see only their own data.
    """
    if user_role == 'admin':
        # Admin: See all data in their group
        return f" AND {table_alias}.group_id = %s", (group_id,)
    else:
        # Member: See only their own data
        return f" AND {table_alias}.owner_id = %s AND {table_alias}.group_id = %s", (g.user_id, group_id)


def check_user_access():
    """Checks if g.group_id and g.user_id are set, usually after login_required."""
    if not (hasattr(g, 'group_id') and hasattr(g, 'user_id')):
        flash("Authorization failed. Please log in.", 'error')
        return redirect(url_for('login'))
    return None

# --- CURRENCY & EXCHANGE RATE UTILITIES ---

def get_exchange_rate(from_currency, to_currency='USD'):
    """Fetches real-time exchange rate from external API."""
    if from_currency == to_currency:
        return 1.0

    if not EXCHANGE_RATE_API_KEY:
        print("Warning: EXCHANGE_RATE_API_KEY is not set. Using fallback rate of 1.0.")
        return 1.0 # Fallback rate
        
    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/pair/{from_currency}/{to_currency}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        if data.get('result') == 'success':
            return data.get('conversion_rate', 1.0)
        else:
            print(f"API Error fetching rate for {from_currency}/{to_currency}: {data.get('error-type')}")
            return 1.0
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}. Falling back to 1.0.")
        return 1.0

# Function to get the current INR conversion rate
def get_usd_to_inr_rate():
    """Fetches USD to INR rate for display purposes."""
    rate = get_exchange_rate('USD', 'INR')
    # If API fails or returns 1.0 (fallback), use a hardcoded safe rate if possible
    if rate == 1.0 and EXCHANGE_RATE_API_KEY: 
        # Attempt to get a fallback from another currency if available, or just stick with 1.0
        return 83.5 
    return rate

# Global variable to store the USD to INR rate for the request lifetime
USD_TO_INR_RATE = None

@app.before_request
def setup_global_rates():
    """Initializes the USD to INR rate once per request."""
    global USD_TO_INR_RATE
    if request.path.startswith(url_for('static', filename='')):
        return # Skip for static files
    
    # Only fetch rate if needed (e.g., if we access the home/dashboard route)
    # USD_TO_INR_RATE is currently set to None at the start of the request
    # and will be fetched only if convert_to_inr_if_needed is called.
    pass 

def convert_to_inr_if_needed(usd_amount):
    """Converts a USD amount to INR using a globally fetched rate."""
    if usd_amount is None:
        return 'N/A'
    
    global USD_TO_INR_RATE
    if USD_TO_INR_RATE is None:
        # Lazy load the rate only when conversion is needed
        USD_TO_INR_RATE = get_usd_to_inr_rate()
    
    # Return 'N/A' if rate is bad (e.g., 1.0 fallback used, or 0)
    if USD_TO_INR_RATE in [1.0, 0] and EXCHANGE_RATE_API_KEY:
        return 'N/A'
        
    return usd_amount * USD_TO_INR_RATE


# --- NEW HELPER FUNCTION FOR DASHBOARD ---
## NEW HELPER FUNCTION: PLACE THIS NEAR OTHER UTILITY FUNCTIONS AT THE TOP
def calculate_financial_summaries(cur, group_filter, group_params):
    """
    Calculates key financial metrics and fetches recent data for the dashboard.
    
    Args:
        cur: Database cursor (RealDictCursor).
        group_filter: SQL filter clause for group access.
        group_params: Parameters for the group filter.
        
    Returns:
        A dictionary containing all necessary dashboard metrics.
    """
    
    # 1. Fetch Total Assets (USD equivalent)
    cur.execute(f"""
        SELECT COALESCE(SUM(amount * exchange_rate_to_usd), 0.0) as total_assets
        FROM assets WHERE activate = TRUE {group_filter};
    """, group_params)
    total_asset_usd = cur.fetchone()['total_assets']

    # 2. Fetch Total Expenses (USD equivalent)
    cur.execute(f"""
        SELECT COALESCE(SUM(amount * exchange_rate_to_usd), 0.0) as total_expenses
        FROM expenses WHERE activate = TRUE {group_filter};
    """, group_params)
    total_expense_usd = cur.fetchone()['total_expenses']

    net_usd = total_asset_usd - total_expense_usd

    # 3. Convert to INR if needed
    total_asset_inr = convert_to_inr_if_needed(total_asset_usd)
    total_expense_inr = convert_to_inr_if_needed(total_expense_usd)
    net_inr = convert_to_inr_if_needed(net_usd)
    
    # 4. Fetch Asset Breakdown by Type
    cur.execute(f"""
        SELECT type, COALESCE(SUM(amount * exchange_rate_to_usd), 0.0) as total_value
        FROM assets WHERE activate = TRUE {group_filter}
        GROUP BY type ORDER BY total_value DESC;
    """, group_params)
    # Convert list of dicts to a single dict for easier template usage
    asset_breakdown = {row['type']: row['total_value'] for row in cur.fetchall()}

    # 5. Fetch Last 5 Expenses
    cur.execute(f"""
        SELECT
            e.expense_date, e.category, e.amount, e.currency, e.description, u.name as owner_name
        FROM expenses e
        JOIN users u ON e.owner_id = u.id
        WHERE e.activate = TRUE {group_filter}
        ORDER BY e.expense_date DESC, e.id DESC
        LIMIT 5;
    """, group_params)
    last_expenses = cur.fetchall()

    return {
        'net_usd': net_usd,
        'net_inr': net_inr,
        'total_asset_usd': total_asset_usd,
        'total_asset_inr': total_asset_inr,
        'total_expense_usd': total_expense_usd,
        'total_expense_inr': total_expense_inr,
        'last_expenses': last_expenses,
        'asset_breakdown': asset_breakdown
    }

# --- ROUTES ---

# ... [Your existing /login, /logout, /register routes here] ...

## NEW DASHBOARD ROUTE (/)
@app.route('/')
@login_required 
def home():
    """Renders the main dashboard with financial summaries."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Get the group filtering clause (admin sees group, member sees self)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
        # We need to adjust the alias for the calculation helper which uses different aliases:
        # For assets: table_alias='assets', For expenses: table_alias='expenses'
        
        # Calculate all metrics and fetch recent data
        data = calculate_financial_summaries(cur, 
                                             f" AND assets.group_id = %s" if g.user_role == 'admin' else f" AND assets.owner_id = %s AND assets.group_id = %s", 
                                             group_params)

        # Merge the user data into the metrics dictionary for rendering
        data['user_name'] = g.user_name

        # The data dictionary keys match the variables expected by home.html
        return render_template('home.html', **data)
        
    except Exception as e:
        flash(f"An error occurred while loading the dashboard: {e}", 'error')
        print(f"Dashboard error: {e}")
        return render_template('home.html', 
                               net_usd=0.0, total_asset_usd=0.0, total_expense_usd=0.0, 
                               last_expenses=[], asset_breakdown={}, net_inr='N/A', 
                               total_asset_inr='N/A', total_expense_inr='N/A')
    finally:
        if conn: cur.close(); conn.close()

# ... [Your existing /expenses, /add_expense, /edit_expense, /delete_expense routes continue here] ...

# ... [Your remaining routes] ...
