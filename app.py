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
            # Fallback for environments without the key set
            print("WARNING: FERNET_KEY not set. Using fallback key. DO NOT use in production.", file=sys.stderr)
            key = Fernet.generate_key().decode()
        
        self.f = Fernet(key.encode())

    def encrypt(self, data):
        if data is None or data == '':
            return None
        # data is encoded to bytes, encrypted, and then decoded to string for DB storage
        return self.f.encrypt(data.encode()).decode()

    def decrypt(self, token):
        if token is None or token == '':
            return ''
        try:
            # token is encoded back to bytes, decrypted, and then decoded to string
            return self.f.decrypt(token.encode()).decode()
        except Exception as e:
            # Handle possible errors (e.g., token tampered with, wrong key)
            print(f"Decryption error: {e}", file=sys.stderr)
            return f"[Decryption Error]" # Return a generic error message

try:
    encryptor = Encryptor(FERNET_KEY)
except ValueError as e:
    print(f"Fatal Error: {e}", file=sys.stderr)
    sys.exit(1)


# --- DATABASE UTILITIES ---

def get_db_connection():
    # Use environment variable for connection
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def create_tables():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. users table: Stores user auth and profile info
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(100) NOT NULL,
                role VARCHAR(20) DEFAULT 'member' NOT NULL, -- 'admin' or 'member'
                group_id VARCHAR(50) NOT NULL,
                reset_token VARCHAR(100),
                token_expiry TIMESTAMP
            );
        """)

        # 2. assets table: Stores all assets (UPDATED SCHEMA)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                group_id VARCHAR(50) NOT NULL,
                owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                
                -- Core Fields
                name VARCHAR(255) NOT NULL, -- Renamed from description
                type VARCHAR(100) NOT NULL,
                value NUMERIC(15, 2) NOT NULL, -- Renamed from amount
                currency VARCHAR(10) NOT NULL,
                usd_value NUMERIC(15, 2) DEFAULT 0.0,
                country VARCHAR(100) NOT NULL,
                
                -- Administrative Details (Encrypted where required)
                account_no VARCHAR(512), -- Encrypted
                financial_institution VARCHAR(255),
                policy_or_plan_type VARCHAR(255),
                beneficiary_name VARCHAR(255),
                contact_phone VARCHAR(512), -- Encrypted
                document_location VARCHAR(512), -- Encrypted
                
                -- Notes and Strategy (Text fields, encrypted)
                investment_strategy TEXT, -- Encrypted
                notes TEXT, -- Encrypted
                
                -- Status and Dates
                acquisition_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activate BOOLEAN DEFAULT TRUE NOT NULL
            );
        """)

        # 3. expenses table: Stores all expenses (Original Schema)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                group_id VARCHAR(50) NOT NULL,
                owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                amount NUMERIC(10, 2) NOT NULL,
                currency VARCHAR(10) NOT NULL,
                usd_value NUMERIC(10, 2) DEFAULT 0.0,
                category VARCHAR(100) NOT NULL,
                description VARCHAR(255),
                expense_date DATE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                activate BOOLEAN DEFAULT TRUE NOT NULL
            );
        """)
        
        conn.commit()
    except Exception as e:
        print(f"Database table creation error: {e}", file=sys.stderr)
        if conn: conn.rollback()
    finally:
        if conn: cur.close(); conn.close()

# Ensure tables are created on startup
create_tables()


# --- AUTHENTICATION AND ACCESS CONTROL UTILITIES ---

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def check_user_access():
    # Simplification: Ensure user is loaded and has a group_id
    if not hasattr(g, 'user_role') or not hasattr(g, 'group_id') or not g.group_id:
        flash('Authentication context missing or incomplete. Please log in again.', 'error')
        return redirect(url_for('login'))
    return None

def get_group_filter_clause(user_role, group_id, table_name):
    # All data is scoped by group_id for all members/admins
    return f" AND {table_name}.group_id = %s", (group_id,)

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user_id = user_id
    
    if user_id is None:
        g.user_role = None
        g.group_id = None
    else:
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id, role, group_id FROM users WHERE id = %s;', (user_id,))
            user = cur.fetchone()
            if user:
                g.user_role = user['role']
                g.group_id = user['group_id']
            else:
                session.clear()
                g.user_role = None
                g.group_id = None
        except Exception as e:
            print(f"Database connection error in before_request: {e}", file=sys.stderr)
            session.clear()
        finally:
            if conn: cur.close(); conn.close()


# --- DATA UTILITIES ---

def get_exchange_rate(base_currency, target_currency):
    if base_currency == target_currency:
        return 1.0
    if not EXCHANGE_RATE_API_KEY:
        print("WARNING: EXCHANGE_RATE_API_KEY not set. Using USD/INR fallback rate of 83.0.", file=sys.stderr)
        if base_currency == 'INR' and target_currency == 'USD':
             return 1/83.0
        if base_currency == 'USD' and target_currency == 'INR':
            return 83.0
        return 1.0 # Default to 1 if no key and not USD/INR
        
    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/latest/{base_currency}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get('result') == 'success':
            return data['conversion_rates'].get(target_currency)
        else:
            print(f"Exchange Rate API error: {data.get('error-type')}", file=sys.stderr)
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed for exchange rate: {e}", file=sys.stderr)
        return None

def get_common_lists():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        # Asset Types
        asset_types = ['Real Estate', 'Stocks', 'Bonds', 'Savings Account', 'Checking Account', 'Retirement Fund', 'Vehicle', 'Other']
        
        # Expense Categories
        expense_categories = ['Groceries', 'Rent/Mortgage', 'Utilities', 'Transport', 'Entertainment', 'Healthcare', 'Investment', 'Other']
        
        # Currencies
        currencies = ['USD', 'INR', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'CNY']
        
        # Countries (NEW: Added to support the detailed asset form)
        countries = ['United States', 'India', 'Canada', 'United Kingdom', 'Australia', 'Germany', 'Japan', 'China', 'Other']
        
        # Owners (Users in the current group)
        owners = []
        if hasattr(g, 'group_id') and g.group_id:
             cur.execute('SELECT id, username, role FROM users WHERE group_id = %s ORDER BY username;', (g.group_id,))
             owners = cur.fetchall()

        return {
            'asset_types': asset_types,
            'expense_categories': expense_categories,
            'currencies': currencies,
            'owners': owners,
            'countries': countries
        }
        
    except Exception as e:
        print(f"Error fetching common lists: {e}", file=sys.stderr)
        return {
            'asset_types': [], 'expense_categories': [], 'currencies': [], 'owners': [], 'countries': []
        }
    finally:
        if conn: cur.close(); conn.close()


def calculate_total_values(items, is_assets=True):
    total_usd = 0.0
    total_inr = 0.0
    
    # Get the necessary exchange rates only once
    usd_to_inr_rate = get_exchange_rate('USD', 'INR')
    
    for item in items:
        # Use 'value' for assets and 'amount' for expenses
        amount_key = 'value' if is_assets else 'amount'
        
        if item.get('currency') == 'USD':
            usd_value = float(item.get(amount_key, 0))
            item['usd_value'] = usd_value
        else:
            rate = get_exchange_rate(item.get('currency'), 'USD')
            if rate:
                # Convert local to USD
                usd_value = float(item.get(amount_key, 0)) / rate 
                item['usd_value'] = usd_value
            else:
                usd_value = 0.0
                item['usd_value'] = 0.0 # Could not calculate rate

        total_usd += usd_value

    if usd_to_inr_rate:
        total_inr = total_usd * usd_to_inr_rate
    else:
        # If rate fetching failed, return N/A for INR
        total_inr = 'N/A'

    return total_usd, total_inr

# --- CORE DATA FETCHING FUNCTIONS ---

def get_assets(limit=None):
    if not hasattr(g, 'group_id') or not g.group_id: return [], 0.0, 0.0
    
    conn = None
    assets = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # NOTE: Aliasing 'name' to 'description' and 'value' to 'amount' for compatibility with index.html/home.html
        query = f"""
            SELECT a.id, a.name AS description, a.type, a.value AS amount, a.currency, a.usd_value,
                   a.acquisition_date, u.username AS owner_name
            FROM assets a
            JOIN users u ON a.owner_id = u.id
            WHERE a.activate = TRUE AND a.group_id = %s
            ORDER BY a.usd_value DESC
        """
        
        params = [g.group_id]
        
        if limit:
            query += f" LIMIT %s"
            params.append(limit)

        cur.execute(query, params)
        assets = cur.fetchall()
        
    except Exception as e:
        print(f"Error fetching assets: {e}", file=sys.stderr)
    finally:
        if conn: cur.close(); conn.close()
    
    # Calculate totals, which also populates the USD value if it wasn't calculated before
    total_usd, total_inr = calculate_total_values(assets, is_assets=True)
    
    return assets, total_usd, total_inr

def get_expenses(limit=None):
    if not hasattr(g, 'group_id') or not g.group_id: return [], 0.0, 0.0
    
    conn = None
    expenses = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        query = f"""
            SELECT e.id, e.amount, e.currency, e.usd_value, e.category, e.description,
                   TO_CHAR(e.expense_date, 'YYYY-MM-DD') AS expense_date, u.username AS owner_name
            FROM expenses e
            JOIN users u ON e.owner_id = u.id
            WHERE e.activate = TRUE AND e.group_id = %s
            ORDER BY e.expense_date DESC
        """
        
        params = [g.group_id]
        
        if limit:
            query += f" LIMIT %s"
            params.append(limit)

        cur.execute(query, params)
        expenses = cur.fetchall()
        
    except Exception as e:
        print(f"Error fetching expenses: {e}", file=sys.stderr)
    finally:
        if conn: cur.close(); conn.close()

    # Calculate totals
    total_usd, total_inr = calculate_total_values(expenses, is_assets=False)
    
    return expenses, total_usd, total_inr

def get_expense_by_id(expense_id):
    if not hasattr(g, 'group_id') or not g.group_id: return None
    
    conn = None
    expense = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        query = f"""
            SELECT e.*, u.username AS owner_name
            FROM expenses e
            JOIN users u ON e.owner_id = u.id
            WHERE e.id = %s AND e.group_id = %s AND e.activate = TRUE;
        """
        cur.execute(query, (expense_id, g.group_id))
        expense = cur.fetchone()

        if expense:
            # Format date for the form
            if expense['expense_date']:
                 expense['expense_date'] = expense['expense_date'].strftime('%Y-%m-%d')
            
        return expense
        
    except Exception as e:
        print(f"Error fetching expense {expense_id}: {e}", file=sys.stderr)
        return None
    finally:
        if conn: cur.close(); conn.close()

def get_asset_by_id(asset_id):
    if not hasattr(g, 'group_id') or not g.group_id: return None
    
    conn = None
    asset = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Select ALL fields including the encrypted ones.
        query = """
            SELECT a.*, u.username AS owner_name
            FROM assets a
            JOIN users u ON a.owner_id = u.id
            WHERE a.id = %s AND a.group_id = %s AND a.activate = TRUE;
        """
        cur.execute(query, (asset_id, g.group_id))
        asset = cur.fetchone()

        if asset:
            # Decrypt sensitive fields for editing/viewing in detail
            asset['account_no'] = encryptor.decrypt(asset['account_no'])
            asset['contact_phone'] = encryptor.decrypt(asset['contact_phone'])
            asset['document_location'] = encryptor.decrypt(asset['document_location'])
            asset['investment_strategy'] = encryptor.decrypt(asset['investment_strategy'])
            asset['notes'] = encryptor.decrypt(asset['notes'])
            
            # Format date for the form
            if asset['acquisition_date']:
                 asset['acquisition_date'] = asset['acquisition_date'].strftime('%Y-%m-%d')
            
            # NOTE: Rename for Jinja compatibility in the edit form
            asset['description'] = asset['name'] 
            asset['amount'] = asset['value']
            
        return asset
        
    except Exception as e:
        print(f"Error fetching asset {asset_id}: {e}", file=sys.stderr)
        return None
    finally:
        if conn: cur.close(); conn.close()


# --- ROUTES ---

# Placeholder routes (must exist for base template links to work)
@app.route('/login', methods=['GET', 'POST'])
def login(): flash('Login/Registration routes are stubs.', 'info'); return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register(): flash('Login/Registration routes are stubs.', 'info'); return render_template('register.html')

@app.route('/logout')
def logout(): session.clear(); flash('You have been logged out.', 'info'); return redirect(url_for('login'))

@app.route('/profile')
@login_required 
def profile(): flash('User profile coming soon.', 'info'); return render_template('profile.html', user_role=g.user_role)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password(): flash('Password reset coming soon.', 'info'); return render_template('reset_password.html')


# --- DASHBOARD ROUTE ---

@app.route('/')
@login_required
def home():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    # Fetch data
    assets, total_asset_usd, total_asset_inr = get_assets()
    expenses, total_expense_usd, total_expense_inr = get_expenses()
    
    # Calculate Net Worth
    net_usd = total_asset_usd - total_expense_usd if isinstance(total_asset_usd, (int, float)) and isinstance(total_expense_usd, (int, float)) else 'N/A'
    net_inr = total_asset_inr - total_expense_inr if isinstance(total_asset_inr, (int, float)) and isinstance(total_expense_inr, (int, float)) else 'N/A'

    # Get Last 5 Expenses for the dashboard
    last_expenses, _, _ = get_expenses(limit=5)
    
    # Calculate Asset Breakdown by Type (for the chart/list)
    asset_breakdown = {}
    for asset in assets:
        asset_type = asset.get('type', 'Unknown')
        usd_value = asset.get('usd_value', 0.0)
        asset_breakdown[asset_type] = asset_breakdown.get(asset_type, 0.0) + usd_value

    return render_template('home.html', 
                           group_id=g.group_id,
                           total_asset_usd=total_asset_usd,
                           total_asset_inr=total_asset_inr,
                           total_expense_usd=total_expense_usd,
                           total_expense_inr=total_expense_inr,
                           net_usd=net_usd,
                           net_inr=net_inr,
                           last_expenses=last_expenses,
                           asset_breakdown=asset_breakdown)


# --- ASSET MANAGEMENT ROUTES ---

@app.route('/assets')
@login_required
def index():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    assets, total_asset_usd, _ = get_assets()
    
    return render_template('index.html', assets=assets, total_asset_usd=total_asset_usd)


@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = get_common_lists()

    if request.method == 'POST':
        form_data = request.form
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # --- New Field Handling and Encryption ---
            
            # Core data
            owner_id = int(form_data['owner_id'])
            asset_name = form_data['name']
            asset_type = form_data['type']
            value = float(form_data['value'])
            currency = form_data['currency']
            country = form_data['country']
            acquisition_date = form_data.get('acquisition_date') or None

            # Policy/Institution Data
            institution = form_data.get('financial_institution')
            policy_type = form_data.get('policy_or_plan_type')
            beneficiary = form_data.get('beneficiary_name')
            
            # Encrypt Sensitive Fields
            account_no_enc = encryptor.encrypt(form_data.get('account_no'))
            contact_phone_enc = encryptor.encrypt(form_data.get('contact_phone'))
            document_location_enc = encryptor.encrypt(form_data.get('document_location'))
            strategy_enc = encryptor.encrypt(form_data.get('investment_strategy'))
            notes_enc = encryptor.encrypt(form_data.get('notes'))
            
            # Calculate USD Value
            usd_rate = get_exchange_rate(currency, 'USD')
            usd_value = value / usd_rate if usd_rate else 0.0


            # Insertion Query (Updated for new columns)
            insert_query = """
                INSERT INTO assets (
                    group_id, owner_id, name, type, value, currency, usd_value, country,
                    financial_institution, policy_or_plan_type, beneficiary_name,
                    account_no, contact_phone, document_location, investment_strategy, notes, 
                    acquisition_date
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, 
                    %s, %s, %s, %s, %s,
                    %s
                ) RETURNING id;
            """
            
            params = (
                g.group_id, owner_id, asset_name, asset_type, value, currency, usd_value, country,
                institution, policy_type, beneficiary,
                account_no_enc, contact_phone_enc, document_location_enc, strategy_enc, notes_enc,
                acquisition_date
            )
            
            cur.execute(insert_query, params)
            conn.commit()
            flash('Asset recorded successfully!', 'success')
            return redirect(url_for('index'))
            
        except Exception as e:
            if conn: conn.rollback()
            flash(f"Error adding asset: {e}", 'error')
            print(f"Asset insertion error: {e}", file=sys.stderr)
            return redirect(url_for('add_asset'))
        finally:
            if conn: cur.close(); conn.close()

    return render_template('add_asset.html', **lists)


@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash('Asset not found or unauthorized.', 'error')
        return redirect(url_for('index'))

    lists = get_common_lists()

    if request.method == 'POST':
        flash('Asset update functionality coming soon. Please implement the update query.', 'info')
        # Placeholder for real update logic
        return redirect(url_for('index'))
        
    return render_template('edit_asset.html', asset=asset, **lists)


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required 
def delete_asset(asset_id):
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
        flash("Asset successfully removed from portfolio.", 'success')
        return redirect(url_for('index'))
        
    except Exception as e:
        if conn: conn.rollback()
        flash(f"Asset deletion error: {e}", 'error')
        return redirect(url_for('index'))
    finally:
        if conn: cur.close(); conn.close()


# --- EXPENSE MANAGEMENT ROUTES (Restored/Preserved) ---

@app.route('/expenses')
@login_required
def expenses(): 
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    expenses, total_expense_usd, _ = get_expenses()
    
    return render_template('expenses.html', expenses=expenses, total_expense_usd=total_expense_usd)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = get_common_lists()

    if request.method == 'POST':
        form_data = request.form
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()

            owner_id = int(form_data['owner_id'])
            amount = float(form_data['amount'])
            currency = form_data['currency']
            category = form_data['category']
            description = form_data.get('description')
            expense_date = form_data['expense_date']

            # Calculate USD Value
            usd_rate = get_exchange_rate(currency, 'USD')
            usd_value = amount / usd_rate if usd_rate else 0.0

            insert_query = """
                INSERT INTO expenses (group_id, owner_id, amount, currency, usd_value, category, description, expense_date) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id;
            """
            params = (g.group_id, owner_id, amount, currency, usd_value, category, description, expense_date)
            
            cur.execute(insert_query, params)
            conn.commit()
            flash('Expense recorded successfully!', 'success')
            return redirect(url_for('expenses'))
            
        except Exception as e:
            if conn: conn.rollback()
            flash(f"Error adding expense: {e}", 'error')
            print(f"Expense insertion error: {e}", file=sys.stderr)
            return redirect(url_for('add_expense'))
        finally:
            if conn: cur.close(); conn.close()

    return render_template('add_expense.html', **lists)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    expense = get_expense_by_id(expense_id)
    if not expense:
        flash('Expense not found or unauthorized.', 'error')
        return redirect(url_for('expenses'))

    lists = get_common_lists()

    if request.method == 'POST':
        form_data = request.form
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            owner_id = int(form_data['owner_id'])
            amount = float(form_data['amount'])
            currency = form_data['currency']
            category = form_data['category']
            description = form_data.get('description')
            expense_date = form_data['expense_date']

            # Calculate USD Value
            usd_rate = get_exchange_rate(currency, 'USD')
            usd_value = amount / usd_rate if usd_rate else 0.0

            update_query = f"""
                UPDATE expenses SET 
                    owner_id = %s, amount = %s, currency = %s, usd_value = %s, 
                    category = %s, description = %s, expense_date = %s
                WHERE id = %s AND group_id = %s;
            """
            params = (owner_id, amount, currency, usd_value, category, description, expense_date, expense_id, g.group_id)
            
            cur.execute(update_query, params)
            
            if cur.rowcount == 0:
                 flash("Update failed: Expense not found or unauthorized.", 'error')
                 return redirect(url_for('expenses'))

            conn.commit()
            flash('Expense updated successfully!', 'success')
            return redirect(url_for('expenses'))
            
        except Exception as e:
            if conn: conn.rollback()
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
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        cur.execute(f'UPDATE expenses SET activate = FALSE WHERE id = %s {group_filter};', (expense_id,) + group_params)
        
        if cur.rowcount == 0:
            flash("Delete failed: Expense not found or unauthorized.", 'error')
            return redirect(url_for('expenses'))
            
        conn.commit()
        flash("Expense successfully removed.", 'success')
        return redirect(url_for('expenses'))
        
    except Exception as e:
        if conn: conn.rollback()
        flash(f"Expense deletion error: {e}", 'error')
        return redirect(url_for('expenses'))
    finally:
        if conn: cur.close(); conn.close()
