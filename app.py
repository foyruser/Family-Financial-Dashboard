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

# --- APPLICATION INITIALIZATION & CONFIG ---
app = Flask(__name__)
# CRITICAL: SET FLASK_SECRET_KEY ENVIRONMENT VARIABLE FOR PRODUCTION
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_long_random_fallback_key') 
bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL') 
# Use a placeholder API key and provide a fallback
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY', 'YOUR_API_KEY_HERE')
# CRITICAL: Fernet Encryption Key
FERNET_KEY = os.environ.get('FERNET_KEY', Fernet.generate_key().decode())

# --- ENCRYPTOR IMPLEMENTATION ---
class Encryptor:
    """Handles field-level encryption for sensitive data."""
    def __init__(self, key):
        if not key:
            print("WARNING: FERNET_KEY not set. Using fallback key. DO NOT use in production.", file=sys.stderr)
            key = Fernet.generate_key().decode()
        
        self.f = Fernet(key.encode())
    
    def encrypt(self, data):
        if data is None: return None
        return self.f.encrypt(str(data).encode()).decode()

    def decrypt(self, data):
        if data is None: return None
        try:
            return self.f.decrypt(data.encode()).decode()
        except Exception:
            # Log error but return a safe default
            print(f"Decryption failed for data: {data[:20]}...", file=sys.stderr)
            return "[Decryption Error]"

encryptor = Encryptor(FERNET_KEY)

# --- DATABASE CONNECTION & HELPERS ---

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        # In a real environment, this should raise a proper configuration error
        raise Exception("DATABASE_URL environment variable is not set.")
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# Helper function to get lists for forms (Categories, Currencies, etc.)
def get_common_lists():
    return {
        'currencies': ['USD', 'EUR', 'INR', 'GBP', 'JPY', 'CAD'],
        'expense_categories': ['Travel', 'Food', 'Utilities', 'Software', 'Salary', 'Misc'],
        'asset_categories': ['Investment', 'Savings', 'Revenue', 'Loan', 'Misc'],
        'groups': [{'id': 1, 'name': 'Finance Team'}, {'id': 2, 'name': 'Sales Team'}],
    }

def login_required(view):
    """Decorator that redirects unauthenticated users to the login page."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def get_group_filter_clause(user_role, group_id, table_alias=''):
    """Generates the SQL WHERE clause for group filtering based on user role."""
    if table_alias and not table_alias.endswith('.'):
        table_alias += '.'
        
    if user_role == 'Admin':
        # Admin can see everything
        return '', ()
    elif group_id is not None:
        # Managers/Members can only see their group's data
        return f'AND {table_alias}group_id = %s', (group_id,)
    else:
        # Default/Unassigned member sees nothing group-related
        return f'AND 1=0', ()

def check_user_access():
    """Checks if the user is authenticated and ready; used by various routes."""
    if not g.user_role:
        flash("Unauthorized access. Please log in again.", 'error')
        return redirect(url_for('login'))
    return None # No redirect if access is granted

@app.before_request
def load_logged_in_user():
    """Loads user role and group_id into the global context (g)."""
    user_id = session.get('user_id')
    g.user_id = None
    g.user_role = None
    g.group_id = None
    g.user_name = None # Added for completeness

    if user_id is not None:
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            # Assuming 'users' table has id, user_role, group_id, and name
            cur.execute("SELECT user_role, group_id, user_name FROM users WHERE id = %s;", (user_id,))
            user = cur.fetchone()
            if user:
                g.user_id = user_id
                g.user_role = user['user_role']
                g.group_id = user['group_id']
                g.user_name = user['user_name']
            else:
                session.clear() # Clear session if user ID is invalid
        except Exception as e:
            print(f"Database connection error in before_request: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()

# --- Currency Helpers (NEW) ---

def get_exchange_rate(from_currency, to_currency='USD'):
    """Fetches exchange rate from an external API."""
    if EXCHANGE_RATE_API_KEY and EXCHANGE_RATE_API_KEY != 'YOUR_API_KEY_HERE':
        try:
            url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/latest/{from_currency}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            if data['result'] == 'success':
                # The conversion_rates dictionary gives the rate for 1 unit of from_currency
                return data['conversion_rates'].get(to_currency, 1.0)
            print(f"API Error for {from_currency}: {data}", file=sys.stderr)
            return 1.0
        except Exception as e:
            # API failure means we fallback to 1.0 (no conversion)
            print(f"Exchange Rate API failed: {e}", file=sys.stderr)
            return 1.0
    return 1.0

def convert_to_usd(amount, currency):
    """Converts an amount from any currency to USD using the API."""
    if currency == 'USD':
        return amount
    
    # Get the rate to convert the foreign currency to USD (e.g., EUR to USD)
    # The API gives the rate to convert the 'latest' base currency to the target.
    # We need the rate to convert the *foreign currency* (e.g., EUR) to USD.
    rate_to_usd = get_exchange_rate(currency, 'USD')
    
    # If EUR/USD rate is 1.08, then Amount_USD = Amount_EUR / 1.08
    return float(amount) / rate_to_usd if rate_to_usd != 0 else 0


# --- CORE ROUTES ---

@app.route('/')
@login_required
def home():
    """
    Renders the main dashboard (home.html), including the calculated financial summary.
    This replaces the simple 'placeholder' home route.
    """
    conn = None
    summary = {
        'total_assets_usd': 0.0,
        'total_expenses_usd': 0.0,
        'total_assets_inr': 'N/A',
        'total_expenses_inr': 'N/A',
        'net_balance_usd': 0.0,
        'net_balance_inr': 'N/A'
    }

    if not g.user_id:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # 1. Get the exchange rate USD -> INR for final display conversion
        # We fetch this in the opposite direction (Base: USD, Target: INR)
        usd_to_inr_rate = get_exchange_rate('USD', 'INR')

        # 2. Setup group filter
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        
        # 3. Fetch all active assets for the group
        cur.execute(f"SELECT amount, currency FROM assets WHERE activate = TRUE {group_filter};", group_params)
        assets = cur.fetchall()

        # 4. Fetch all active expenses for the group
        cur.execute(f"SELECT amount, currency FROM expenses WHERE activate = TRUE {group_filter};", group_params)
        expenses = cur.fetchall()

        # 5. Calculate Total Assets in USD
        total_assets_usd = sum(convert_to_usd(asset['amount'], asset['currency']) for asset in assets)
        
        # 6. Calculate Total Expenses in USD
        total_expenses_usd = sum(convert_to_usd(expense['amount'], expense['currency']) for expense in expenses)

        summary['total_assets_usd'] = total_assets_usd
        summary['total_expenses_usd'] = total_expenses_usd
        summary['net_balance_usd'] = total_assets_usd - total_expenses_usd

        # 7. Convert USD totals to INR for display
        if usd_to_inr_rate > 1.0 and summary['net_balance_usd'] is not None:
            summary['total_assets_inr'] = summary['total_assets_usd'] * usd_to_inr_rate
            summary['total_expenses_inr'] = summary['total_expenses_usd'] * usd_to_inr_rate
            summary['net_balance_inr'] = summary['net_balance_usd'] * usd_to_inr_rate
        
        # 8. Render the home template with the calculated summary
        return render_template('home.html', summary=summary, user_role=g.user_role, group_id=g.group_id)

    except Exception as e:
        flash(f"An error occurred while loading the dashboard summary: {e}", 'error')
        print(f"Dashboard summary error: {e}", file=sys.stderr)
        # Return summary with zero values on failure
        return render_template('home.html', summary=summary, user_role=g.user_role, group_id=g.group_id) 

    finally:
        if conn: cur.close(); conn.close()


# --- AUTHENTICATION ROUTES (Stubs) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, password_hash FROM users WHERE email = %s;", (email,))
            user = cur.fetchone()

            if user and bcrypt.check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                flash('Login successful.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password.', 'error')
        except Exception as e:
            flash('An error occurred during login.', 'error')
            print(f"Login error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    lists = get_common_lists()
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        group_id = request.form.get('group_id', None)
        role = 'Member' # Default role

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (user_name, email, password_hash, user_role, group_id) VALUES (%s, %s, %s, %s, %s) RETURNING id;",
                (name, email, password_hash, role, group_id)
            )
            user_id = cur.fetchone()[0]
            conn.commit()
            session['user_id'] = user_id
            flash('Registration successful. You are now logged in.', 'success')
            return redirect(url_for('home'))
        except psycopg2.IntegrityError:
            flash('A user with that email already exists.', 'error')
        except Exception as e:
            flash('An unexpected error occurred during registration.', 'error')
            print(f"Registration error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()
    return render_template('register.html', **lists)

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# --- EXPENSE MANAGEMENT ROUTES (Complete Logic Stubs) ---

@app.route('/expenses')
@login_required
def expenses():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    conn = None
    expenses_list = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Apply group filter
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        
        # Select expenses marked as active (not soft-deleted)
        cur.execute(f"SELECT id, description, amount, currency, category, date_incurred, activate, group_id FROM expenses WHERE activate = TRUE {group_filter} ORDER BY date_incurred DESC;", group_params)
        
        raw_expenses = cur.fetchall()
        
        for exp in raw_expenses:
            # Decrypt sensitive data (e.g., description could be encrypted)
            exp['description'] = encryptor.decrypt(exp['description']) if exp['description'] else 'N/A'
            expenses_list.append(exp)

    except Exception as e:
        flash(f"Error loading expenses: {e}", 'error')
        print(f"Expenses list error: {e}", file=sys.stderr)
    finally:
        if conn: cur.close(); conn.close()
        
    return render_template('expenses.html', expenses=expenses_list)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    lists = get_common_lists()
    
    if request.method == 'POST':
        description = request.form['description']
        amount = request.form['amount']
        currency = request.form['currency']
        category = request.form['category']
        date_incurred = request.form['date_incurred']
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Encrypt description before storing
            encrypted_description = encryptor.encrypt(description)
            
            # Use the logged-in user's group_id
            group_id = g.group_id 
            
            cur.execute(
                "INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s);",
                (group_id, encrypted_description, amount, currency, category, date_incurred, g.user_id)
            )
            conn.commit()
            flash('Expense successfully added.', 'success')
            return redirect(url_for('expenses'))
            
        except Exception as e:
            flash(f"Error adding expense: {e}", 'error')
            print(f"Expense creation error: {e}", file=sys.stderr)
        finally:
            if conn: cur.close(); conn.close()
            
    return render_template('add_expense.html', **lists, current_date=datetime.now().strftime('%Y-%m-%d'))


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    lists = get_common_lists()
    conn = None
    expense = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get expense details, applying group filter for security
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        cur.execute(f"SELECT id, description, amount, currency, category, date_incurred FROM expenses WHERE id = %s AND activate = TRUE {group_filter};", (expense_id,) + group_params)
        expense = cur.fetchone()
        
        if not expense:
            flash("Expense not found or unauthorized access.", 'error')
            return redirect(url_for('expenses'))
            
        # Decrypt description for display in the form
        expense['description'] = encryptor.decrypt(expense['description']) if expense['description'] else ''
        
    except Exception as e:
        flash(f"Error loading expense for edit: {e}", 'error')
        print(f"Expense fetch error: {e}", file=sys.stderr)
        return redirect(url_for('expenses'))

    if request.method == 'POST':
        description = request.form['description']
        amount = request.form['amount']
        currency = request.form['currency']
        category = request.form['category']
        date_incurred = request.form['date_incurred']
        
        try:
            conn = get_db_connection() # Re-open connection for POST
            cur = conn.cursor()
            
            encrypted_description = encryptor.encrypt(description)
            
            # Update expense, ensuring the group filter is reapplied for safety
            group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
            cur.execute(
                f"UPDATE expenses SET description = %s, amount = %s, currency = %s, category = %s, date_incurred = %s WHERE id = %s AND activate = TRUE {group_filter};",
                (encrypted_description, amount, currency, category, date_incurred, expense_id) + group_params
            )
            
            if cur.rowcount == 0:
                flash("Update failed: Expense not found or unauthorized.", 'error')
            else:
                conn.commit()
                flash('Expense successfully updated.', 'success')
                return redirect(url_for('expenses'))
                
        except Exception as e:
            flash(f"Error updating expense: {e}", 'error')
            print(f"Expense update error: {e}", file=sys.stderr)
            return redirect(url_for('edit_expense', expense_id=expense_id))
        finally:
            if conn: cur.close(); conn.close()
    
    return render_template('edit_expense.html', expense=expense, **lists)


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Soft delete: set activate = FALSE
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        cur.execute(f'UPDATE expenses SET activate = FALSE WHERE id = %s {group_filter};', (expense_id,) + group_params)
        
        if cur.rowcount == 0:
            flash("Delete failed: Expense not found or unauthorized.", 'error')
            return redirect(url_for('expenses'))
            
        conn.commit()
        flash("Expense successfully removed.", 'success')
        return redirect(url_for('expenses'))
        
    except Exception as e:
        flash(f"Error deleting expense: {e}", 'error')
        print(f"Expense delete error: {e}", file=sys.stderr)
        
    finally:
        if conn: cur.close(); conn.close()
        
    return redirect(url_for('expenses'))

# --- ASSET MANAGEMENT ROUTES (Stubs for completeness) ---

@app.route('/assets')
@login_required
def assets():
    flash("Assets list page placeholder. (Functionality matches expenses listing)", 'info')
    # Actual implementation would be very similar to /expenses
    return "Assets List Page"

@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    flash("Add asset page placeholder.", 'info')
    return "Add Asset Page"

@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    flash(f"Edit asset {asset_id} page placeholder.", 'info')
    return "Edit Asset Page"

@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    flash(f"Delete asset {asset_id} action placeholder.", 'info')
    return redirect(url_for('assets'))


# --- UTILITY ROUTES (Stubs for completeness) ---

# Example initialization route for database schema (run once)
@app.route('/init_db')
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Database Schema Creation (Simplified)
        cur.execute("""
            -- Drop tables if they exist to allow re-initialization
            DROP TABLE IF EXISTS expenses;
            DROP TABLE IF EXISTS assets;
            DROP TABLE IF EXISTS users;

            -- Users Table
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                user_name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                user_role VARCHAR(50) NOT NULL DEFAULT 'Member', -- Admin, Manager, Member
                group_id INTEGER, -- FK to a 'groups' table if you had one, but simple INTEGER for now
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
            );

            -- Expenses Table
            CREATE TABLE expenses (
                id SERIAL PRIMARY KEY,
                group_id INTEGER,
                description TEXT NOT NULL,
                amount NUMERIC(15, 2) NOT NULL,
                currency VARCHAR(10) NOT NULL,
                category VARCHAR(50) NOT NULL,
                date_incurred DATE NOT NULL,
                created_by INTEGER REFERENCES users(id),
                activate BOOLEAN NOT NULL DEFAULT TRUE, -- Soft delete
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
            );

            -- Assets Table (Similar structure)
            CREATE TABLE assets (
                id SERIAL PRIMARY KEY,
                group_id INTEGER,
                description TEXT NOT NULL,
                amount NUMERIC(15, 2) NOT NULL,
                currency VARCHAR(10) NOT NULL,
                category VARCHAR(50) NOT NULL,
                date_acquired DATE NOT NULL,
                created_by INTEGER REFERENCES users(id),
                activate BOOLEAN NOT NULL DEFAULT TRUE, -- Soft delete
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
            );
        """)
        
        # Insert a sample Admin user
        sample_password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
        cur.execute(
            "INSERT INTO users (user_name, email, password_hash, user_role, group_id) VALUES (%s, %s, %s, %s, %s) RETURNING id;",
            ('Admin User', 'admin@example.com', sample_password_hash, 'Admin', 1)
        )
        admin_id = cur.fetchone()[0]

        # Insert sample expenses and assets
        encrypted_expense = encryptor.encrypt("Office Rental Payment")
        encrypted_asset = encryptor.encrypt("Q3 Revenue Deposit")

        cur.execute(
            "INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s);",
            (1, encrypted_expense, 5000.00, 'USD', 'Utilities', datetime.now().date(), admin_id)
        )
        cur.execute(
            "INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s);",
            (1, encryptor.encrypt("Travel to London"), 8500.00, 'INR', 'Travel', datetime.now().date(), admin_id)
        )
        cur.execute(
            "INSERT INTO assets (group_id, description, amount, currency, category, date_acquired, created_by) VALUES (%s, %s, %s, %s, %s, %s, %s);",
            (1, encrypted_asset, 15000.00, 'USD', 'Revenue', datetime.now().date(), admin_id)
        )
        conn.commit()
        
        return "Database initialized and sample data inserted successfully. Admin credentials: admin@example.com/password"
        
    except Exception as e:
        print(f"Database initialization failed: {e}", file=sys.stderr)
        return f"Database initialization failed: {e}", 500
        
    finally:
        if conn: cur.close(); conn.close()
