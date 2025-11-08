from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_bcrypt import Bcrypt
from collections import Counter
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools # For the login_required decorator
import os # To read environment variables securely
import sys # For logging critical errors


# --- APPLICATION INITIALIZATION ---
app = Flask(__name__)

# --- SECURITY CONFIGURATION (CRITICAL FIXES) ---

# CRITICAL FIX 1: Read the secret key from a secure environment variable.
# YOU MUST SET FLASK_SECRET_KEY in your environment for production.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 
                                'a_very_long_and_random_fallback_key_that_should_still_be_set_securely_in_prod_1234567890') 
bcrypt = Bcrypt(app)
# ------------------------------

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

def get_exchange_rates():
    """Fetches the latest exchange rates from USD base."""
    key = EXCHANGE_RATE_API_KEY
    
    if not key:
        print("WARNING: EXCHANGE_RATE_API_KEY is missing. Using fallback rates.", file=sys.stderr)
        return {'USD': 1.0, 'INR': 83.0, 'EUR': 0.9, 'GBP': 0.8}
        
    url = f'https://v6.exchangerate-api.com/v6/{key}/latest/USD'
    try:
        response = requests.get(url)
        data = response.json()
        if data.get('result') == 'success':
            return data['conversion_rates']
        else:
            print(f"ERROR: Exchange rate API call failed. Status: {data.get('result')}. Using fallback rates.", file=sys.stderr)
            return {'USD': 1.0, 'INR': 83.0, 'EUR': 0.9, 'GBP': 0.8}
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to connect to exchange rate API: {e}. Using fallback rates.", file=sys.stderr)
        return {'USD': 1.0, 'INR': 83.0, 'EUR': 0.9, 'GBP': 0.8}


def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database using DSN."""
    if not DATABASE_URL:
        raise ConnectionError("DATABASE_URL environment variable not found. Cannot connect to database.")

    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection failed using DSN: {e}", file=sys.stderr)
        raise ConnectionError(f"Failed to connect to database: {e}")


def get_user_role(user_id):
    """Fetches the role of a given user ID."""
    if not user_id:
        return None
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # FIX: Select the 'role' column from the database
        cur.execute('SELECT role FROM users WHERE id = %s;', (user_id,))
        role_tuple = cur.fetchone()
        return role_tuple[0] if role_tuple else None
    except Exception as e:
        print(f"CRITICAL: Failed to fetch user role for ID {user_id}: {e}", file=sys.stderr)
        # CRITICAL FIX 4: If DB check fails, deny access.
        return None 
    finally:
        if conn:
            conn.close()


# --- AUTHENTICATION DECORATORS ---

def login_required(view):
    """Decorator that ensures a user is logged in before allowing access."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            # Redirect to the login page if not logged in
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    """
    Decorator that ensures the logged-in user has the 'admin' role.
    Note: This must be placed AFTER @login_required.
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user_id = session.get('user_id')
        user_role = get_user_role(user_id) # FIX 2: Check role instead of ID
        
        if user_role != 'admin':
            # Render the custom error template for access denial
            return render_template('error.html', message="Access Denied: You must be an administrator to view this page."), 403
            
        return view(**kwargs)
    return wrapped_view


# --- AUTH ROUTES ---


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration and password hashing."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            # FIX: Insert new users with role = 'pending'
            cur.execute('INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id;', (username, password_hash, 'pending'))
            user_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()

            session['user_id'] = user_id
            session['username'] = username
            return redirect(url_for('pending_approval')) 

        except psycopg2.IntegrityError:
            return render_template('register.html', error='Username already taken. Please choose another.')
        except ConnectionError as e:
            return render_template('register.html', error=f'Connection Error: {e}')
        except Exception as e:
            print(f"Registration error: {e}")
            return render_template('register.html', error=f'An error occurred: {e}')

    return render_template('register.html', error=None)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session creation."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            # FIX: Select the 'role' column instead of is_approved
            cur.execute('SELECT id, password_hash, role FROM users WHERE username = %s;', (username,))
            user = cur.fetchone()
            cur.close()
            conn.close()
        except ConnectionError as e:
            return render_template('login.html', error=f'Connection Error: {e}')
        except Exception as e:
            return render_template('login.html', error=f'An error occurred during lookup: {e}')

        if user and bcrypt.check_password_hash(user['password_hash'], password):
            
            session['user_id'] = user['id']
            session['username'] = username

            # Check for 'pending' role
            if user.get('role') == 'pending':
                return redirect(url_for('pending_approval'))
            
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html', error=None)


@app.route('/logout')
def logout():
    """Clears the session and logs the user out."""
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# --- NEW PENDING APPROVAL ROUTE ---
@app.route('/pending')
@login_required 
def pending_approval():
    """Displays the page notifying the user their account is pending approval."""
    user_role = get_user_role(session.get('user_id'))
    if user_role == 'user' or user_role == 'admin':
        return redirect(url_for('home'))
    
    return render_template('pending_approval.html')

# --- NEW ADMIN APPROVAL ROUTE ---
@app.route('/admin/approve', methods=['GET', 'POST'])
@login_required 
@admin_required # FIX: Now checks for 'admin' role dynamically
def admin_approve_users():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        if request.method == 'POST':
            user_id_to_approve = request.form.get('user_id')
            if user_id_to_approve:
                # FIX: Update the database to change role from 'pending' to 'user'
                cur.execute('UPDATE users SET role = %s WHERE id = %s AND role = %s;', ('user', user_id_to_approve, 'pending'))
                conn.commit()

        # Fetch all unapproved (pending) users
        cur.execute("SELECT id, username FROM users WHERE role = 'pending' ORDER BY id;")
        pending_users = cur.fetchall()
        
        cur.close()
        return render_template('admin_approve_users.html', pending_users=pending_users)

    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Admin approval error: {e}", file=sys.stderr)
        if conn: conn.rollback()
        return f"An error occurred during approval process: {e}", 500
    finally:
        if conn is not None:
            conn.close()

# --- HELPER FUNCTION: Check Role and Reroute ---
def check_user_access():
    """Checks user role and redirects if access is denied or pending."""
    user_id = session.get('user_id')
    user_role = get_user_role(user_id)
    
    # CRITICAL FIX 4: If role check fails (e.g., DB error, no role found) or if pending, deny access.
    if user_role is None:
        # DB error or user not found. Kill session and redirect to login.
        session.pop('user_id', None)
        session.pop('username', None)
        return redirect(url_for('login'), 307)
    
    if user_role == 'pending':
        return redirect(url_for('pending_approval'), 307)
        
    return None # Access granted

# --- HELPER FUNCTION: Get Owners ---
def get_owners():
    """Fetches all owner records (id and name) from the database."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id, name FROM owners ORDER BY name;')
        owners = cur.fetchall()
        cur.close()
        return owners
    except ConnectionError:
        return []
    finally:
        if conn is not None:
            conn.close()

# --- ADDITION for asset type pie chart ---
def get_asset_type_distribution():
    """Fetches total asset value grouped by asset type (for pie chart)."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT type, SUM(value) as total_value
            FROM assets
            WHERE activate = TRUE
            GROUP BY type
            ORDER BY total_value DESC
        """)
        data = cur.fetchall()
        cur.close()
        return data
    except ConnectionError:
        return []
    finally:
        if conn is not None:
            conn.close()


# --- PROTECTED APPLICATION ROUTES ---


@app.route('/home')
@login_required # PROTECTED
def home():
    """Dashboard view showing aggregated assets, expenses, and net worth."""
    
    # NEW CHECK: Ensure the user is approved before running the full dashboard logic
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response # Reroutes pending/unapproved/DB error users
                
    # Proceed with dashboard data fetching only if approved
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch assets
        cur.execute('''
            SELECT a.*, o.name AS owner_name
            FROM assets a
            JOIN owners o ON a.owner_id = o.id
            WHERE a.activate = TRUE;
        ''')
        assets = cur.fetchall()
        
        # Fetch expenses
        cur.execute('''
            SELECT e.*, o.name AS owner_name
            FROM expenses e
            JOIN owners o ON e.owner_id = o.id
            WHERE e.activate = TRUE;
        ''')
        expenses = cur.fetchall()
        cur.close()
    
    except ConnectionError as e:
        print(f"Home route DB error: {e}", file=sys.stderr)
        return "Database Connection Error: Cannot load dashboard data.", 500
    finally:
        if conn is not None:
            conn.close()

    rates = get_exchange_rates()

    total_asset_usd = 0
    total_asset_inr = 0
    for asset in assets:
        cur_currency = asset['currency']
        try:
            value = float(asset['value'])
        except (TypeError, ValueError):
            value = 0
        
        # Convert to USD
        if cur_currency == 'USD':
            value_usd = value
        else:
            rate_to_usd = rates.get(cur_currency, None)
            value_usd = round(value / rate_to_usd, 2) if rate_to_usd and rate_to_usd != 0 else 0
            
        # Convert to INR
        value_inr = round(value_usd * rates.get('INR', 83), 2)
        total_asset_usd += value_usd
        total_asset_inr += value_inr


    total_expense_usd = 0
    total_expense_inr = 0
    for expense in expenses:
        cur_currency = expense['currency']
        try:
            amount = float(expense['amount'])
        except (TypeError, ValueError):
            amount = 0
            
        # Convert to USD
        if cur_currency == 'USD':
            amount_usd = amount
        else:
            rate_to_usd = rates.get(cur_currency, None)
            amount_usd = round(amount / rate_to_usd, 2) if rate_to_usd and rate_to_usd != 0 else 0
            
        # Convert to INR
        amount_inr = round(amount_usd * rates.get('INR', 83), 2)
        total_expense_usd += amount_usd
        total_expense_inr += amount_inr


    asset_type_data = get_asset_type_distribution()

    net_usd = round(total_asset_usd - total_expense_usd, 2)
    net_inr = round(total_asset_inr - total_expense_inr, 2)


    return render_template('home.html',
        total_asset_usd=round(total_asset_usd, 2),
        total_asset_inr=round(total_asset_inr, 2),
        total_expense_usd=round(total_expense_usd, 2),
        total_expense_inr=round(total_expense_inr, 2),
        net_usd=net_usd,
        net_inr=net_inr,
        asset_type_data=asset_type_data
    )


# --- INDEX/ASSETS LISTING ROUTE ---
@app.route('/')
@login_required # PROTECTED
def index():
    """Lists all active assets with sorting and currency conversion."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response 
    
    # Proceed with original logic...
    sort_by = request.args.get('sort_by', 'value_usd')
    order = request.args.get('order', 'desc')


    # CRITICAL FIX 3: Whitelist columns for DB sorting to prevent SQL Injection
    db_sort_columns = {
        'id': 'a.id', 
        'type': 'a.type', 
        'name': 'a.name', 
        'country': 'a.country', 
        'currency': 'a.currency', 
        'value': 'a.value', 
        'last_updated': 'a.last_updated', 
        'owner_name': 'o.name'
    }
    # Columns for Python/in-memory sorting (calculated values)
    python_sort_columns = ['value_usd'] 

    # Determine sorting method
    if sort_by in db_sort_columns:
        # Use DB sorting for whitelisted columns
        sort_column = db_sort_columns[sort_by]
        order_db = 'ASC' if order.lower() == 'asc' else 'DESC'
        # The query will be securely constructed using the validated column name
    elif sort_by in python_sort_columns:
        # Default to DB sorting by ID for the initial fetch, then sort in Python
        sort_column = 'a.id'
        order_db = 'DESC' 
    else:
        # Default to DB sorting by ID if invalid field is requested
        sort_by = 'value_usd' # Maintain the UI state for calculated field
        sort_column = 'a.id'
        order_db = 'DESC'


    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Query uses the validated sort_column and order_db (CRITICAL FIX 3)
        query = f'''
            SELECT a.*, o.name AS owner_name 
            FROM assets a 
            JOIN owners o ON a.owner_id = o.id 
            WHERE a.activate = TRUE 
            ORDER BY {sort_column} {order_db};
        '''
        cur.execute(query)
        assets = cur.fetchall()
        cur.close()
    
    except ConnectionError as e:
        print(f"Index route DB error: {e}", file=sys.stderr)
        return "Database Connection Error: Cannot load asset list.", 500
    finally:
        if conn is not None:
            conn.close()


    rates = get_exchange_rates()


    total_usd = 0
    total_inr = 0


    # 1. Calculate Converted Values
    for asset in assets:
        cur_currency = asset['currency']
        try:
            value = float(asset['value']) 
        except (TypeError, ValueError):
            value = 0.00
        
        # Calculate USD value
        if cur_currency == 'USD':
            asset['value_usd'] = value
        else:
            rate_to_usd = rates.get(cur_currency, None)
            if rate_to_usd and rate_to_usd != 0:
                asset['value_usd'] = round(value / rate_to_usd, 2)
            else:
                asset['value_usd'] = 0.00
                asset['value_usd_display'] = "N/A"
            
        # Calculate INR value
        if 'value_usd_display' not in asset:
             asset['value_usd_display'] = round(asset['value_usd'], 2)
             asset['value_inr'] = round(asset['value_usd'] * rates.get('INR', 83), 2)
             total_usd += asset['value_usd']
             total_inr += asset['value_inr']
        else:
            asset['value_inr'] = 0.00
            asset['value_inr_display'] = "N/A"


    # 2. Python Sorting for Calculated Fields (value_usd)
    if sort_by in python_sort_columns:
        reverse_sort = order_db == 'DESC'
        
        assets.sort(key=lambda a: a.get(sort_by, 0.00), reverse=reverse_sort)


    total_usd = round(total_usd, 2)
    total_inr = round(total_inr, 2)
    
    return render_template('index.html', assets=assets, total_usd=total_usd, total_inr=total_inr, sort_by=sort_by, order=order_db.lower())


# --- ADD ASSET ROUTE ---
@app.route('/add_asset', methods=['GET', 'POST'])
@login_required # PROTECTED
def add_asset():
    """Displays form and handles submission for adding a new asset."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)


        cur.execute('SELECT type_name FROM asset_types ORDER BY type_name;')
        asset_types = [row['type_name'] for row in cur.fetchall()]


        cur.execute('SELECT country_name FROM countries ORDER BY country_name;')
        countries = [row['country_name'] for row in cur.fetchall()]


        cur.execute('SELECT currency_code FROM currencies ORDER BY currency_code;')
        currencies = [row['currency_code'] for row in cur.fetchall()]

        owners = get_owners() 
        
        cur.close()
    
    except ConnectionError as e:
        print(f"Add asset config error: {e}", file=sys.stderr)
        return "Database Connection Error: Cannot load form options.", 500
    finally:
        if conn is not None and request.method == 'GET':
            conn.close()


    if request.method == 'POST':
        owner_id = request.form['owner_id']
        type = request.form['type']
        name = request.form['name']
        country = request.form['country']
        currency = request.form['currency']
        
        value_str = request.form['value']
        try:
            value = float(value_str)
        except (ValueError, TypeError):
            value = 0.00 
            
        account_no = request.form['account_no']
        notes = request.form['notes']
        
        financial_institution = request.form['financial_institution']
        beneficiary_name = request.form['beneficiary_name']
        policy_or_plan_type = request.form['policy_or_plan_type']
        contact_phone = request.form['contact_phone']
        document_location = request.form['document_location']
        investment_strategy = request.form['investment_strategy']


        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO assets (
                    owner_id, type, name, country, currency, value, account_no, last_updated, notes, activate,
                    financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location, investment_strategy
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, CURRENT_DATE, %s, TRUE,
                    %s, %s, %s, %s, %s, %s
                )
            """, (
                owner_id, type, name, country, currency, value, account_no, notes,
                financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location, investment_strategy
            ))
            conn.commit()
        except ConnectionError as e:
            return f"Database Connection Error: {e}", 500
        except Exception as e:
            if conn: conn.rollback()
            print(f"Database insertion error in add_asset: {e}", file=sys.stderr)
            return f"An error occurred during asset insertion: {e}", 500
        finally:
            if conn is not None:
                cur.close()
                conn.close()
        return redirect('/')


    return render_template('add_asset.html', asset_types=asset_types, countries=countries, currencies=currencies, owners=owners)


# --- EDIT ASSET ROUTE (Updated for 6 new fields) ---
@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required # PROTECTED
def edit_asset(asset_id):
    """Displays form and handles submission for editing an existing asset."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)


        cur.execute('SELECT type_name FROM asset_types ORDER BY type_name;')
        asset_types = [row['type_name'] for row in cur.fetchall()]


        cur.execute('SELECT country_name FROM countries ORDER BY country_name;')
        countries = [row['country_name'] for row in cur.fetchall()]


        cur.execute('SELECT currency_code FROM currencies ORDER BY currency_code;')
        currencies = [row['currency_code'] for row in cur.fetchall()]


        owners = get_owners() 
        
        # Fetch the asset to edit, regardless of request method
        cur.execute('SELECT * FROM assets WHERE id=%s;', (asset_id,))
        asset = cur.fetchone()

        if asset is None:
            return "Asset not found", 404

    except ConnectionError as e:
        print(f"Edit asset config error: {e}", file=sys.stderr)
        return "Database Connection Error: Cannot load form options or asset.", 500
    except Exception as e:
        print(f"Edit asset initial fetch error: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None and request.method == 'GET':
            cur.close()
            conn.close()


    if request.method == 'POST':
        owner_id = request.form['owner_id']
        type = request.form['type']
        name = request.form['name']
        country = request.form['country']
        currency = request.form['currency']
        
        value_str = request.form['value']
        try:
            value = float(value_str)
        except (ValueError, TypeError):
            value = 0.00 
            
        account_no = request.form['account_no']
        notes = request.form['notes']


        financial_institution = request.form['financial_institution']
        beneficiary_name = request.form['beneficiary_name']
        policy_or_plan_type = request.form['policy_or_plan_type']
        contact_phone = request.form['contact_phone']
        document_location = request.form['document_location']
        investment_strategy = request.form['investment_strategy']

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE assets
                SET 
                    owner_id=%s, type=%s, name=%s, country=%s, currency=%s, value=%s, account_no=%s, notes=%s, last_updated=CURRENT_DATE,
                    financial_institution=%s, beneficiary_name=%s, policy_or_plan_type=%s, contact_phone=%s, document_location=%s, investment_strategy=%s
                WHERE id=%s
            """, (
                owner_id, type, name, country, currency, value, account_no, notes,
                financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location, investment_strategy,
                asset_id
            ))
            conn.commit()
        except ConnectionError as e:
            return f"Database Connection Error: {e}", 500
        except Exception as e:
            if conn: conn.rollback()
            print(f"Database update error in edit_asset: {e}", file=sys.stderr)
            return f"An error occurred during asset update: {e}", 500
        finally:
            if conn is not None:
                cur.close()
                conn.close()
            
        return redirect('/')

    # GET request render
    return render_template('edit_asset.html', asset=asset, asset_types=asset_types, countries=countries, currencies=currencies, owners=owners)


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required # PROTECTED
def delete_asset(asset_id):
    """Marks an asset as inactive (soft delete)."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE assets SET activate = FALSE WHERE id = %s;', (asset_id,))
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Database error on delete: {e}", file=sys.stderr)
        return f"An error occurred during deletion: {e}", 500
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    return redirect('/')


# --- EXPENSES ROUTES (All Updated) ---
@app.route('/expenses')
@login_required # PROTECTED
def expenses():
    """Lists all active expenses with sorting."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response
    
    sort_by = request.args.get('sort_by', 'expense_date')
    order = request.args.get('order', 'desc')


    allowed_sort_columns = {
        'id': 'e.id', 
        'description': 'e.description', 
        'category': 'e.category', 
        'amount': 'e.amount', 
        'currency': 'e.currency', 
        'expense_date': 'e.expense_date', 
        'owner_name': 'o.name'
    }
    
    # CRITICAL FIX 3: Whitelist check for expense sorting
    if sort_by not in allowed_sort_columns:
        sort_by = 'expense_date'
        sort_column = 'e.expense_date'
    else:
        sort_column = allowed_sort_columns[sort_by]
        
    order = 'asc' if order.lower() == 'asc' else 'desc'
    order_db = 'ASC' if order == 'asc' else 'DESC'

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Query uses validated sort_column and order_db (CRITICAL FIX 3)
        query = f'''
            SELECT e.*, o.name AS owner_name
            FROM expenses e
            JOIN owners o ON e.owner_id = o.id
            WHERE e.activate = TRUE 
            ORDER BY {sort_column} {order_db};
        '''
        cur.execute(query)
        expenses = cur.fetchall()
        cur.close()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Expense list fetch error: {e}", file=sys.stderr)
        return f"An error occurred fetching expenses: {e}", 500
    finally:
        if conn is not None:
            conn.close()


    return render_template('expenses.html', expenses=expenses, sort_by=sort_by, order=order)


@app.route('/add_expense', methods=['GET', 'POST'])
@login_required # PROTECTED
def add_expense():
    """Displays form and handles submission for adding a new expense."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response
    
    categories = ['Travel', 'Office Supplies', 'Utilities', 'Salary', 'Miscellaneous']
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'JPY']
    
    owners = get_owners()


    if request.method == 'POST':
        owner_id = request.form['owner_id']
        description = request.form['description']
        category = request.form['category']
        
        amount_str = request.form['amount']
        try:
            amount = float(amount_str)
        except (ValueError, TypeError):
            amount = 0.00
            
        currency = request.form['currency']
        expense_date = request.form['expense_date']
        notes = request.form['notes']


        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO expenses (owner_id, description, category, amount, currency, expense_date, notes, activate)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE)
            """, (owner_id, description, category, amount, currency, expense_date, notes))
            conn.commit()
        except ConnectionError as e:
            return f"Database Connection Error: {e}", 500
        except Exception as e:
            if conn: conn.rollback()
            print(f"Expense insertion error: {e}", file=sys.stderr)
            return f"An error occurred inserting expense: {e}", 500
        finally:
            if conn is not None:
                cur.close()
                conn.close()
        return redirect('/expenses')


    return render_template('add_expense.html', categories=categories, currencies=currencies, owners=owners)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required # PROTECTED
def edit_expense(expense_id):
    """Displays form and handles submission for editing an existing expense."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response
                
    categories = ['Travel', 'Office Supplies', 'Utilities', 'Salary', 'Miscellaneous']
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'JPY']
    
    conn = None
    owners = get_owners() 

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Fetch expense for GET/initial check
        cur.execute('SELECT * FROM expenses WHERE id=%s;', (expense_id,))
        expense = cur.fetchone()
        
        if expense is None:
            return "Expense not found", 404

    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Expense fetch error: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None and request.method == 'GET':
            cur.close()
            conn.close()

    if request.method == 'POST':
        owner_id = request.form['owner_id']
        description = request.form['description']
        category = request.form['category']
        
        amount_str = request.form['amount']
        try:
            amount = float(amount_str)
        except (ValueError, TypeError):
            amount = 0.00
            
        currency = request.form['currency']
        expense_date = request.form['expense_date']
        notes = request.form['notes']

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE expenses
                SET owner_id=%s, description=%s, category=%s, amount=%s, currency=%s, expense_date=%s, notes=%s
                WHERE id=%s
            """, (owner_id, description, category, amount, currency, expense_date, notes, expense_id))
            
            conn.commit()
        except ConnectionError as e:
            return f"Database Connection Error: {e}", 500
        except Exception as e:
            if conn: conn.rollback()
            print(f"Expense update error: {e}", file=sys.stderr)
            return f"An error occurred updating expense: {e}", 500
        finally:
            if conn is not None:
                cur.close()
                conn.close()
        return redirect('/expenses')


    # GET request render
    return render_template(
        'edit_expense.html', 
        expense=expense, 
        categories=categories, 
        currencies=currencies, 
        owners=owners
    )


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required # PROTECTED
def delete_expense(expense_id):
    """Marks an expense as inactive (soft delete)."""
    
    # NEW CHECK: Reroute unapproved users
    access_denied_response = check_user_access()
    if access_denied_response:
        return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE expenses SET activate = FALSE WHERE id = %s;', (expense_id,))
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        if conn: conn.rollback()
        print(f"Expense deletion error: {e}", file=sys.stderr)
        return f"An error occurred deleting expense: {e}", 500
    finally:
        if conn is not None:
            cur.close()
            conn.close()
    return redirect('/expenses')



if __name__ == '__main__':
    # NOTE: You must set FLASK_SECRET_KEY, DATABASE_URL, and EXCHANGE_RATE_API_KEY 
    # as environment variables before running in production.
    app.run(debug=True)
