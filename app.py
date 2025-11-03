from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_bcrypt import Bcrypt
from collections import Counter
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools # For the login_required decorator
import os # To read environment variables securely
import sys # For logging critical errors
from datetime import datetime

# --- APPLICATION INITIALIZATION ---
app = Flask(__name__)

# --- SECURITY CONFIGURATION ---
# CRITICAL: CHANGE THIS TO A LONG, RANDOM STRING FOR PRODUCTION
app.secret_key = os.environ.get('SECRET_KEY', 'default-fallback-key-for-testing-only')
bcrypt = Bcrypt(app)
# ------------------------------

# --- GLOBAL CONSTANTS ---
# This ID must match the default one used in the SQL migration scripts.
DEFAULT_GROUP_ID = 'default-family'
BASE_CURRENCY = 'USD' # Currency for all exchange rate lookups

# -----------------------------------------------------------
# SECURE CONFIGURATION: Reading credentials from Environment Variables
# -----------------------------------------------------------

# 1. Database connection string (DSN)
DATABASE_URL = os.environ.get('DATABASE_URL') 

# 2. Currency Exchange API Key
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY')

# -----------------------------------------------------------

# --- CONNECTION HELPER FUNCTIONS ---

class ConnectionError(Exception):
    """Custom exception for database connection failures."""
    pass

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        # Critical error if DSN is missing
        print("CRITICAL ERROR: DATABASE_URL environment variable is not set.", file=sys.stderr)
        raise ConnectionError("Database URL is not configured.")
        
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}", file=sys.stderr)
        raise ConnectionError("Failed to connect to the database.")

def get_exchange_rates():
    """Fetches the latest exchange rates from USD base."""
    key = EXCHANGE_RATE_API_KEY
    
    if not key:
        print("WARNING: EXCHANGE_RATE_API_KEY environment variable is not set.", file=sys.stderr)
        # Return a fallback with only the base currency
        return {BASE_CURRENCY: 1.0}
    
    # Using ExchangeRate-API (free tier allows USD as base)
    url = f'https://v6.exchangerate-api.com/v6/{key}/latest/{BASE_CURRENCY}'
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('result') == 'success':
            return data['conversion_rates']
        else:
            print(f"Exchange Rate API Error: {data.get('error-type')}", file=sys.stderr)
            return {BASE_CURRENCY: 1.0}

    except requests.exceptions.RequestException as e:
        print(f"Error fetching exchange rates: {e}", file=sys.stderr)
        return {BASE_CURRENCY: 1.0}
        
# --- AUTHENTICATION & MULTI-TENANCY DECORATOR ---

def login_required(view):
    """
    Decorator that ensures a user is logged in, approved, and loads
    their user data (including group_id) into Flask's `g` object.
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user_id = session.get('user_id')
        
        if user_id is None:
            # User not logged in, redirect to login page
            return redirect(url_for('login'))
        
        # Load user data and check approval status
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # CRITICAL: Fetch is_approved AND group_id from public.users
            cur.execute("""
                SELECT id, username, is_approved, group_id 
                FROM public.users 
                WHERE id = %s;
            """, (user_id,))
            user = cur.fetchone()
            
            if user is None:
                # User exists in session but not in DB (deleted?)
                session.clear()
                return redirect(url_for('login'))

            # Store user data for easy access in views
            g.user_id = user['id']
            g.username = user['username']
            g.is_approved = user['is_approved']
            # CRITICAL: Store group_id for multi-tenancy filtering
            g.group_id = user['group_id']
            
            # Check for approval status
            if not g.is_approved:
                # Approved status must be checked first before proceeding to any main app routes
                return redirect(url_for('pending_approval'))
                
        except ConnectionError:
             return "Database connection failed during user load.", 500
        except Exception as e:
            print(f"Database error during user load: {e}", file=sys.stderr)
            session.clear() # Clear session just in case of corruption
            return "An internal error occurred.", 500
        finally:
            if conn:
                conn.close()

        # If logged in and approved, proceed to the requested view function
        return view(**kwargs)
    return wrapped_view

# --- ROUTES ---

@app.route('/')
@login_required
def index():
    """
    Shows a dashboard or list of all active assets for the user's group.
    """
    conn = None
    assets = []
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # CRITICAL MULTI-TENANCY CHANGE: Filter public.assets by group_id
        cur.execute("""
            SELECT id, name, type, current_value, currency, description, 
                   added_date, last_updated
            FROM public.assets
            WHERE activate = TRUE AND group_id = %s
            ORDER BY last_updated DESC;
        """, (g.group_id,))
        
        assets = cur.fetchall()
        
    except ConnectionError:
        return "Database connection failed.", 500
    except Exception as e:
        print(f"Error fetching assets: {e}", file=sys.stderr)
        return "An internal error occurred while fetching assets.", 500
    finally:
        if conn:
            conn.close()
            
    # Load exchange rates once for display conversion, if needed (logic not fully implemented here)
    rates = get_exchange_rates()

    return render_template('index.html', assets=assets, rates=rates)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session creation."""
    if session.get('user_id'):
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = None
        
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Fetch group_id along with other user data from public.users
            cur.execute("SELECT id, password_hash, is_approved, group_id FROM public.users WHERE username = %s;", (username,))
            user = cur.fetchone()
            
            if user is None:
                error = 'Incorrect username or password.'
            elif not bcrypt.check_password_hash(user['password_hash'], password):
                error = 'Incorrect username or password.'
            else:
                session['user_id'] = user['id']
                # CRITICAL: Store group_id in session upon successful login
                session['group_id'] = user['group_id'] 
                
                # Check approval status immediately after login
                if not user['is_approved']:
                    return redirect(url_for('pending_approval'))
                    
                return redirect(url_for('index'))
                
        except ConnectionError:
            error = "Database connection failed."
        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            error = "An unexpected error occurred during login."
        finally:
            if conn:
                conn.close()

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles new user registration."""
    if session.get('user_id'):
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            error = 'Username and password are required.'
        else:
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            conn = None
            
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                
                # Check if username already exists in public.users
                cur.execute("SELECT id FROM public.users WHERE username = %s;", (username,))
                if cur.fetchone() is not None:
                    error = f"User {username} is already registered."
                else:
                    # CRITICAL: Assign the DEFAULT_GROUP_ID to the new user in public.users
                    cur.execute("""
                        INSERT INTO public.users (username, password_hash, is_approved, group_id)
                        VALUES (%s, %s, FALSE, %s);
                    """, (username, password_hash, DEFAULT_GROUP_ID))
                    
                    conn.commit()
                    return redirect(url_for('login'))
                    
            except ConnectionError:
                error = "Database connection failed during registration."
            except Exception as e:
                if conn: conn.rollback()
                print(f"Registration error: {e}", file=sys.stderr)
                error = "An unexpected error occurred during registration."
            finally:
                if conn:
                    conn.close()

    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    """Clears the session and logs the user out."""
    session.clear()
    return redirect(url_for('login'))

@app.route('/pending_approval')
def pending_approval():
    """Informs the user that their account is awaiting approval."""
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
        
    # Check if the user is suddenly approved (in case of race condition)
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Check public.users
        cur.execute("SELECT is_approved FROM public.users WHERE id = %s;", (user_id,))
        is_approved_tuple = cur.fetchone()
        
        if is_approved_tuple and is_approved_tuple[0]:
            return redirect(url_for('index'))
            
    except Exception as e:
        print(f"Approval check error: {e}", file=sys.stderr)
    finally:
        if conn:
            conn.close()

    return render_template('pending_approval.html')


@app.route('/api/assets/<int:asset_id>')
@login_required
def view_asset_details(asset_id):
    """
    Fetches the details of a single asset and its associated expenses.
    """
    conn = None
    asset = None
    expenses = []

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # 1. Fetch Asset Details (CRITICAL: Filter public.assets by group_id)
        cur.execute("""
            SELECT id, name, type, current_value, currency, description, added_date, last_updated
            FROM public.assets
            WHERE id = %s AND group_id = %s AND activate = TRUE;
        """, (asset_id, g.group_id))
        
        asset = cur.fetchone()

        if asset is None:
            return "Asset not found or access denied.", 404

        # 2. Fetch Associated Expenses (Assuming public.expenses is linked via asset_id)
        # Note: Best practice is to have group_id on public.expenses too, but for now we rely on the asset filter.
        cur.execute("""
            SELECT id, amount, category, date, description, activate
            FROM public.expenses 
            WHERE asset_id = %s AND activate = TRUE
            ORDER BY date DESC;
        """, (asset_id,))
        
        expenses = cur.fetchall()

    except ConnectionError:
        return "Database connection failed.", 500
    except Exception as e:
        print(f"Error fetching asset details: {e}", file=sys.stderr)
        return "An internal error occurred.", 500
    finally:
        if conn:
            conn.close()

    return render_template('asset_details.html', asset=asset, expenses=expenses)


@app.route('/api/add_expense', methods=['POST'])
@login_required
def add_expense():
    """
    Adds a new expense to an existing asset.
    """
    asset_id = request.form.get('asset_id', type=int)
    amount = request.form.get('amount', type=float)
    category = request.form.get('category')
    description = request.form.get('description')
    date_str = request.form.get('date')

    if not all([asset_id, amount, category, date_str]):
        return "Missing required expense fields.", 400

    conn = None
    try:
        # Validate that the asset exists and belongs to the user's group
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check asset existence and ownership in public.assets
        cur.execute("SELECT id FROM public.assets WHERE id = %s AND group_id = %s;", (asset_id, g.group_id))
        if cur.fetchone() is None:
            return "Asset not found or you do not have permission to modify it.", 403

        # Insert the new expense into public.expenses
        cur.execute("""
            INSERT INTO public.expenses (asset_id, amount, category, description, date, activate)
            VALUES (%s, %s, %s, %s, %s, TRUE);
        """, (asset_id, amount, category, description, date_str))

        conn.commit()
        return redirect(url_for('view_asset_details', asset_id=asset_id))
        
    except ConnectionError:
        return "Database Connection Error: Cannot add expense.", 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error adding expense: {e}", file=sys.stderr)
        return f"An error occurred adding expense: {e}", 500
    finally:
        if conn:
            conn.close()

@app.route('/api/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    """
    Marks an expense as inactive (soft delete).
    CRITICAL: Must verify the expense belongs to an asset in the user's group.
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Find the asset_id associated with the expense_id in public.expenses
        cur.execute("SELECT asset_id FROM public.expenses WHERE id = %s;", (expense_id,))
        result = cur.fetchone()
        
        if result is None:
            return "Expense not found.", 404
            
        asset_id = result[0]

        # 2. Verify asset ownership for the current group in public.assets
        cur.execute("SELECT id FROM public.assets WHERE id = %s AND group_id = %s;", (asset_id, g.group_id))
        if cur.fetchone() is None:
            # Although the expense exists, the asset owner is not in the current group
            return "Access denied: This expense is not part of your group's assets.", 403

        # 3. Soft-delete the expense in public.expenses
        cur.execute('UPDATE public.expenses SET activate = FALSE WHERE id = %s;', (expense_id,))
        conn.commit()
        
        # Redirect back to the asset details page
        return redirect(url_for('view_asset_details', asset_id=asset_id))
        
    except ConnectionError:
        return "Database Connection Error: Cannot delete expense.", 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Expense deletion error: {e}", file=sys.stderr)
        return f"An error occurred deleting expense: {e}", 500
    finally:
        if conn:
            conn.close()
            
@app.route('/api/summary')
@login_required
def summary():
    """
    Generates a financial summary (e.g., total asset value, asset type breakdown)
    for the current user's group.
    """
    conn = None
    summary_data = {
        'total_value': 0.0,
        'breakdown': {}
    }
        
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # 1. Total Asset Value and Breakdown by Type (CRITICAL: Filter public.assets by group_id)
        cur.execute("""
            SELECT type, SUM(current_value) AS total_value, currency, COUNT(id) as count
            FROM public.assets
            WHERE activate = TRUE AND group_id = %s
            GROUP BY type, currency;
        """, (g.group_id,))
        
        raw_breakdown = cur.fetchall()
        
        # Process breakdown for display (simple aggregation by type)
        for item in raw_breakdown:
            key = f"{item['type']} ({item['currency']})"
            summary_data['breakdown'][key] = {
                'total_value': float(item['total_value']),
                'count': item['count']
            }

        # 2. Latest Exchange Rates for client-side display
        rates = get_exchange_rates()
        summary_data['rates'] = rates
        summary_data['base_currency'] = BASE_CURRENCY
        
        
    except ConnectionError:
        return "Database connection failed.", 500
    except Exception as e:
        print(f"Error generating summary: {e}", file=sys.stderr)
        return "An internal error occurred while generating the summary.", 500
    finally:
        if conn:
            conn.close()
            
    return render_template('summary.html', summary=summary_data, group_id=g.group_id)

@app.route('/group_management')
@login_required
def group_management():
    """
    Simple view showing the user their group ID and current username.
    """
    # g.username and g.group_id are guaranteed to exist by login_required
    return render_template('group_management.html', 
                           group_id=g.group_id, 
                           username=g.username)

# --- RUN THE APP ---
if __name__ == '__main__':
    # Use environment variable for port, default to 5000
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
