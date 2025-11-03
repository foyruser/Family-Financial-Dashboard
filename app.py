from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from flask_bcrypt import Bcrypt
from collections import Counter
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools # For the login_required decorator
import os # To read environment variables securely
import sys # For logging critical errors
from datetime import datetime
import uuid # For generating unique group IDs

# --- APPLICATION INITIALIZATION ---
app = Flask(__name__)

# --- SECURITY CONFIGURATION ---
# CRITICAL: CHANGE THIS TO A LONG, RANDOM STRING FOR PRODUCTION
app.secret_key = os.environ.get('SECRET_KEY', 'default-fallback-key-for-testing-only')
bcrypt = Bcrypt(app)
# ------------------------------

# --- GLOBAL CONSTANTS ---
# This ID is only for temporary/unassigned users. Real groups get a unique ID.
DEFAULT_GROUP_ID = 'unassigned-default-group' 
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
        return {BASE_CURRENCY: 1.0}
    
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
        
def generate_unique_group_id():
    """Generates a simple, unique group identifier."""
    # Use a small part of a UUID to keep it short and unique
    short_uuid = uuid.uuid4().hex[:6] 
    return f"family-{short_uuid}"

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
            return redirect(url_for('login'))
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            
            # Fetch is_approved and group_id from public.users
            cur.execute("""
                SELECT id, username, is_approved, group_id 
                FROM public.users 
                WHERE id = %s;
            """, (user_id,))
            user = cur.fetchone()
            
            if user is None:
                session.clear()
                return redirect(url_for('login'))

            g.user_id = user['id']
            g.username = user['username']
            g.is_approved = user['is_approved']
            # CRITICAL: Store group_id for multi-tenancy filtering
            g.group_id = user['group_id']
            
            if not g.is_approved:
                return redirect(url_for('pending_approval'))
                
        except ConnectionError:
             flash("Database connection failed during user load.", 'error')
             return redirect(url_for('login'))
        except Exception as e:
            print(f"Database error during user load: {e}", file=sys.stderr)
            session.clear() 
            flash("An internal error occurred.", 'error')
            return redirect(url_for('login'))
        finally:
            if conn:
                conn.close()

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
    
    # Check if the user is still in the temporary group
    if g.group_id == DEFAULT_GROUP_ID:
        flash("Welcome! Please create or join a family group to start tracking assets.", 'warning')
        return redirect(url_for('group_management'))

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
        flash("Database connection failed.", 'error')
        return redirect(url_for('logout'))
    except Exception as e:
        print(f"Error fetching assets: {e}", file=sys.stderr)
        flash("An internal error occurred while fetching assets.", 'error')
        return redirect(url_for('logout'))
    finally:
        if conn:
            conn.close()
            
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
            
            cur.execute("SELECT id, password_hash, is_approved, group_id FROM public.users WHERE username = %s;", (username,))
            user = cur.fetchone()
            
            if user is None or not bcrypt.check_password_hash(user['password_hash'], password):
                error = 'Incorrect username or password.'
            else:
                session['user_id'] = user['id']
                session['group_id'] = user['group_id'] 
                
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
    """
    Handles new user registration. Users can optionally join a group immediately.
    """
    if session.get('user_id'):
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # User can optionally provide a group ID to join upon registration
        desired_group_id = request.form.get('group_id', '').strip()
        
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
                    final_group_id = DEFAULT_GROUP_ID
                    
                    if desired_group_id:
                        # If a group ID is provided, check if it exists (i.e., if anyone is in it)
                        cur.execute("SELECT group_id FROM public.users WHERE group_id = %s LIMIT 1;", (desired_group_id,))
                        if cur.fetchone():
                            final_group_id = desired_group_id
                        else:
                            error = f"The Group ID '{desired_group_id}' does not exist. Please register without a Group ID and join later, or check your code."
                            conn.close() # Close connection to abort registration
                            return render_template('register.html', error=error, group_id=desired_group_id)

                    # Assign the calculated group ID to the new user in public.users
                    cur.execute("""
                        INSERT INTO public.users (username, password_hash, is_approved, group_id)
                        VALUES (%s, %s, FALSE, %s);
                    """, (username, password_hash, final_group_id))
                    
                    conn.commit()
                    flash('Registration successful! Please wait for admin approval.', 'success')
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


# --- GROUP MANAGEMENT ROUTES ---

@app.route('/group_management')
@login_required
def group_management():
    """
    View for the user to see their current group ID and options to create/join a new one.
    """
    # g.username and g.group_id are guaranteed to exist by login_required
    return render_template('group_management.html', 
                           group_id=g.group_id, 
                           username=g.username,
                           is_default_group=(g.group_id == DEFAULT_GROUP_ID))

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    """
    Creates a new unique group ID and updates the current user's group_id.
    """
    conn = None
    new_group_id = generate_unique_group_id()

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Update the user's group_id in public.users
        cur.execute("""
            UPDATE public.users SET group_id = %s WHERE id = %s;
        """, (new_group_id, g.user_id))

        conn.commit()
        
        # 2. Update the session/g object with the new group ID
        session['group_id'] = new_group_id
        g.group_id = new_group_id
        
        flash(f"Successfully created and joined a new group: {new_group_id}. Share this ID!", 'success')
        return redirect(url_for('group_management'))
        
    except ConnectionError:
        flash("Database connection failed during group creation.", 'error')
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error creating group: {e}", file=sys.stderr)
        flash("An unexpected error occurred during group creation.", 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('group_management'))
    
@app.route('/join_group', methods=['POST'])
@login_required
def join_group():
    """
    Allows a user (typically from the default group) to join an existing group.
    """
    target_group_id = request.form.get('target_group_id', '').strip()
    
    if not target_group_id:
        flash("You must enter a Group ID to join.", 'error')
        return redirect(url_for('group_management'))
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Check if the target_group_id actually exists in public.users (i.e., someone is in it)
        cur.execute("SELECT group_id FROM public.users WHERE group_id = %s LIMIT 1;", (target_group_id,))
        if cur.fetchone() is None:
            flash(f"Group ID '{target_group_id}' does not exist or has no members.", 'error')
            return redirect(url_for('group_management'))
            
        # 2. Update the current user's group_id
        cur.execute("""
            UPDATE public.users SET group_id = %s WHERE id = %s;
        """, (target_group_id, g.user_id))

        conn.commit()
        
        # 3. Update the session/g object
        session['group_id'] = target_group_id
        g.group_id = target_group_id
        
        flash(f"Successfully joined group: {target_group_id}.", 'success')
        return redirect(url_for('index'))
        
    except ConnectionError:
        flash("Database connection failed during group joining.", 'error')
    except Exception as e:
        if conn: conn.rollback()
        print(f"Error joining group: {e}", file=sys.stderr)
        flash("An unexpected error occurred while trying to join the group.", 'error')
    finally:
        if conn:
            conn.close()
            
    return redirect(url_for('group_management'))

# --- ASSET/EXPENSE ROUTES (Unchanged, rely on login_required for isolation) ---

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

# --- RUN THE APP ---
if __name__ == '__main__':
    # Use environment variable for port, default to 5000
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
