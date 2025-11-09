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
    """Handles field-level encryption and decryption using Fernet."""
    def __init__(self, key):
        if not key:
            # Fallback for environments without the key set
            print("WARNING: FERNET_KEY not set. Using fallback key. DO NOT use in production.", file=sys.stderr)
            key = Fernet.generate_key().decode()
        
        self.f = Fernet(key.encode())

    def encrypt(self, data):
        """Encrypts a string for storage in the DB."""
        if data is None or data == '':
            return None
        # data is encoded to bytes, encrypted, and then decoded to string for DB storage
        return self.f.encrypt(data.encode()).decode()

    def decrypt(self, data):
        """Decrypts a string retrieved from the DB."""
        if data is None or data == '':
            return None
        try:
            # data is expected to be a string from DB, encode to bytes, decrypt, then decode back to string
            return self.f.decrypt(data.encode()).decode()
        except Exception as e:
            # This handles cases where data might be incorrectly formatted or keyed/unencrypted
            # In production, you might log this error more aggressively.
            print(f"Decryption error (returning raw data): {e}", file=sys.stderr)
            return data # Return the original data if decryption fails (as a fallback)

# Instantiate the encryptor globally
try:
    encryptor = Encryptor(FERNET_KEY)
except ValueError as e:
    print(f"Fatal Error during Encryptor init: {e}", file=sys.stderr)
    encryptor = None # Set to None if initialization fails

# --- DATABASE CONNECTION & UTILS ---
def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        print("FATAL: DATABASE_URL is not set.", file=sys.stderr)
        return None 
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}", file=sys.stderr)
        return None

@app.route('/health')
def health_check():
    """Simple health check endpoint."""
    conn = get_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute('SELECT 1')
            cur.close()
            conn.close()
            return 'OK', 200
        except:
            return 'Database Error', 500
    return 'DB Config Error', 500

# --- USER AUTHENTICATION & ACCESS CONTROL UTILS ---

def send_password_reset_email(email, token):
    """
    STUB: In a production environment, this would use an actual email service
    (like SendGrid, Mailgun, or SMTP server).
    """
    reset_link = url_for('reset_password', token=token, _external=True)
    print(f"--- EMAIL STUB ---")
    print(f"TO: {email}")
    print(f"SUBJECT: Password Reset Request")
    print(f"BODY: Click this link to reset your password: {reset_link}")
    print(f"--- END EMAIL STUB ---")
    # For a simple local test, this always 'succeeds'
    return True 


def login_required(view):
    """Decorator to protect routes requiring authentication."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login', next=request.url))
        # Ensure user data is loaded on `g` object before continuing
        if not hasattr(g, 'user_id') or g.user_id is None:
            _load_logged_in_user()
            if g.user_id is None:
                 # User session is invalid (e.g., user deleted)
                 session.clear()
                 flash('Your session is no longer valid. Please log in again.', 'error')
                 return redirect(url_for('login', next=request.url))
        return view(**kwargs)
    return wrapped_view

def _load_logged_in_user():
    """Loads user data from DB into Flask's `g` object if a session exists."""
    user_id = session.get('user_id')
    # Reset g object attributes
    g.user_id = None
    g.username = None
    g.user_role = None
    g.group_id = None

    if user_id is None:
        return

    conn = get_db_connection()
    if conn is None:
        return # Cannot load user without DB

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Fetch only necessary, non-sensitive data
        cur.execute('SELECT id, username, role, group_id FROM users WHERE id = %s AND activate = TRUE', (user_id,))
        user = cur.fetchone()
        cur.close()
        
        if user:
            g.user_id = user['id']
            g.username = user['username']
            g.user_role = user['role']
            g.group_id = user['group_id']
        else:
            # User was found in session but not in DB (e.g., deleted)
            session.clear()

    except Exception as e:
        print(f"Error loading user data: {e}", file=sys.stderr)
    finally:
        if conn: conn.close()


@app.before_request
def load_logged_in_user():
    """Run before every request to check for user session."""
    _load_logged_in_user()

def get_group_filter_clause(user_role, group_id, table_alias=''):
    """
    Generates the SQL WHERE clause and parameters for group-based filtering.
    - Admins see everything (no filter).
    - Group members see only records belonging to their group.
    
    table_alias: Optional table prefix (e.g., 'expenses' or 'u')
    """
    prefix = f"{table_alias}." if table_alias else ""
    
    if user_role == 'admin':
        return "", ()
    elif user_role in ('manager', 'member') and group_id is not None:
        return f" AND {prefix}group_id = %s", (group_id,)
    else:
        # Default case (e.g., user is a member but has no group_id assigned)
        # Filter to ensure they see nothing (safety measure)
        return f" AND {prefix}group_id IS NULL", ()


def check_user_access(required_role='member'):
    """
    Checks if the user is authenticated and has the required role.
    Returns a response tuple (message, status_code) if access is denied, otherwise returns None.
    """
    if g.user_id is None:
        flash('Authentication required.', 'error')
        return redirect(url_for('login'))
    
    # Simple role hierarchy check
    role_hierarchy = {'admin': 3, 'manager': 2, 'member': 1}
    
    user_level = role_hierarchy.get(g.user_role, 0)
    required_level = role_hierarchy.get(required_role, 1) # Default requirement is 'member'
    
    if user_level < required_level:
        flash('Access denied. Insufficient privileges.', 'error')
        return "Access denied. Insufficient privileges.", 403
        
    return None # Access granted

# --- ROUTES: AUTHENTICATION ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user_id is not None:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        if conn is None:
            flash('Database unavailable.', 'error')
            return render_template('login.html')

        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id, password_hash, activate FROM users WHERE username = %s', (username,))
            user = cur.fetchone()
            cur.close()

            if user and user['activate'] and bcrypt.check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                # Redirect to the 'next' URL if provided, otherwise to dashboard
                next_page = request.args.get('next') or url_for('dashboard')
                flash(f'Welcome back, {username}!', 'success')
                return redirect(next_page)
            else:
                flash('Invalid username or password.', 'error')

        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            flash('An unexpected error occurred during login.', 'error')

        finally:
            if conn: conn.close()
            
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        
        if conn is None:
            flash('Database unavailable. Please try again later.', 'error')
            return render_template('forgot_password.html')
            
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            # Fetch user by email
            cur.execute('SELECT id, activate, username FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
            
            if user and user['activate']:
                # Generate a secure token and set expiry time (e.g., 1 hour)
                token = secrets.token_urlsafe(32)
                expiry = datetime.now() + timedelta(hours=1)
                
                # Store the token and expiry time in the database
                cur.execute(
                    """
                    UPDATE users SET password_reset_token = %s, token_expiry = %s
                    WHERE id = %s
                    """,
                    (token, expiry, user['id'])
                )
                conn.commit()
                
                # STUB: Send the email with the token link
                send_password_reset_email(email, token)
                
            # To prevent user enumeration, give a generic success message
            flash('If an account with that email exists, a password reset link has been sent.', 'info')
                
            cur.close()
            
        except Exception as e:
            print(f"Forgot password error: {e}", file=sys.stderr)
            flash('An unexpected error occurred. Please try again.', 'error')
            if conn: conn.rollback()
            
        finally:
            if conn: conn.close()
            
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    user = None

    if conn is None:
        flash('Database unavailable. Please try again later.', 'error')
        return redirect(url_for('login'))
        
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Find the user by the token, ensure it's active and not expired
        cur.execute(
            """
            SELECT id, username FROM users 
            WHERE password_reset_token = %s AND activate = TRUE AND token_expiry > NOW()
            """,
            (token,)
        )
        user = cur.fetchone()
        cur.close()
        
        if not user:
            flash('Invalid or expired password reset token.', 'error')
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            new_password = request.form['password']
            confirm_password = request.form['confirm_password']

            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('reset_password.html', token=token)

            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Update the password and clear the token/expiry
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE users SET password_hash = %s, password_reset_token = NULL, token_expiry = NULL
                WHERE id = %s
                """,
                (hashed_password, user['id'])
            )
            conn.commit()
            cur.close()

            flash('Your password has been successfully reset. Please log in.', 'success')
            return redirect(url_for('login'))

    except Exception as e:
        print(f"Reset password error: {e}", file=sys.stderr)
        flash('An unexpected error occurred during password reset.', 'error')
        if conn: conn.rollback()

    finally:
        if conn: conn.close()
    
    # GET request or POST failure
    return render_template('reset_password.html', token=token)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        conn = get_db_connection()
        if conn is None:
            flash('Database unavailable. Please try again later.', 'error')
            return render_template('register.html')
            
        try:
            cur = conn.cursor()
            
            # Check if username or email already exists (security measure)
            cur.execute('SELECT COUNT(*) FROM users WHERE username = %s OR email = %s', (username, email))
            if cur.fetchone()[0] > 0:
                flash('Username or email already registered.', 'error')
                cur.close()
                return render_template('register.html', username=username, email=email)
            
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Default group_id to NULL, role to 'member', and activate to TRUE
            cur.execute(
                """
                INSERT INTO users (username, password_hash, email, role, activate, group_id)
                VALUES (%s, %s, %s, 'member', TRUE, NULL)
                """,
                (username, hashed_password, email)
            )
            
            conn.commit()
            cur.close()
            
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Registration error: {e}", file=sys.stderr)
            flash('An unexpected error occurred during registration.', 'error')
            if conn: conn.rollback()
            
        finally:
            if conn: conn.close()
            
    return render_template('register.html')


# --- ROUTES: CORE APPLICATION VIEWS ---

def fetch_list_data():
    """Fetches categories, currencies, and owners for forms."""
    conn = get_db_connection()
    lists = {'categories': [], 'currencies': [], 'owners': []}
    
    if conn is None:
        return lists # Return empty lists if DB fails

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Categories (Available to all, but only active ones)
        cur.execute('SELECT id, name FROM categories WHERE activate = TRUE ORDER BY name')
        lists['categories'] = cur.fetchall()
        
        # Currencies (Available to all, but only active ones)
        cur.execute('SELECT code, name FROM currencies WHERE activate = TRUE ORDER BY name')
        lists['currencies'] = cur.fetchall()
        
        # Owners/Users (Visible users based on group or if Admin)
        # Apply filtering for the current user's visibility
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'u')
        
        cur.execute(f'SELECT id, username FROM users u WHERE u.activate = TRUE {group_filter} ORDER BY username', group_params)
        lists['owners'] = cur.fetchall()

    except Exception as e:
        print(f"Error fetching list data: {e}", file=sys.stderr)
    finally:
        if conn: conn.close()
        
    return lists
    

@app.route('/')
@login_required
def dashboard():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    # We'll fetch summary data for the dashboard here
    summary_data = {
        'total_expenses': 0,
        'monthly_total': 0,
        'recent_expenses': []
    }
    
    conn = get_db_connection()
    if conn is None:
        flash('Database unavailable. Cannot load dashboard data.', 'error')
        return render_template('dashboard.html', summary_data=summary_data)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
        
        # 1. Total Expenses (Count)
        cur.execute(f'SELECT COUNT(*) FROM expenses e WHERE e.activate = TRUE {group_filter}', group_params)
        summary_data['total_expenses'] = cur.fetchone()['count']
        
        # 2. Monthly Total (Standardized to Base Currency) 
        base_currency_code = 'EUR' # Assume EUR is the internal base currency
        current_month = datetime.now().strftime('%Y-%m')
        
        cur.execute(
            f"""
            SELECT COALESCE(SUM(e.base_amount), 0) AS monthly_total
            FROM expenses e
            WHERE e.activate = TRUE 
            AND TO_CHAR(e.expense_date, 'YYYY-MM') = %s 
            {group_filter}
            """,
            (current_month,) + group_params
        )
        summary_data['monthly_total'] = round(cur.fetchone()['monthly_total'], 2)
        summary_data['base_currency'] = base_currency_code

        # 3. Recent Expenses (Last 5)
        cur.execute(
            f"""
            SELECT 
                e.id, 
                e.description, 
                e.amount, 
                e.currency, 
                e.expense_date, 
                c.name AS category_name,
                u.username AS owner_username
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            JOIN users u ON e.owner_id = u.id
            WHERE e.activate = TRUE 
            {group_filter}
            ORDER BY e.expense_date DESC, e.id DESC
            LIMIT 5
            """,
            group_params
        )
        recent_expenses = cur.fetchall()
        
        # Decrypt description for recent expenses
        for expense in recent_expenses:
            expense['description'] = encryptor.decrypt(expense['description']) if encryptor else expense['description']
            expense['expense_date_fmt'] = expense['expense_date'].strftime('%Y-%m-%d')
            
        summary_data['recent_expenses'] = recent_expenses
        
    except Exception as e:
        print(f"Dashboard data error: {e}", file=sys.stderr)
        flash('Error loading dashboard summary.', 'error')
        
    finally:
        if conn: conn.close()

    return render_template('dashboard.html', summary_data=summary_data)


@app.route('/expenses')
@login_required
def expenses():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    conn = get_db_connection()
    expenses_list = []
    
    if conn is None:
        flash('Database unavailable. Cannot load expenses.', 'error')
        return render_template('expenses.html', expenses_list=expenses_list)

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Apply group filtering
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
        
        cur.execute(
            f"""
            SELECT 
                e.id, 
                e.description, 
                e.amount, 
                e.currency, 
                e.expense_date, 
                e.notes,
                c.name AS category_name,
                u.username AS owner_username
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            JOIN users u ON e.owner_id = u.id
            WHERE e.activate = TRUE 
            {group_filter}
            ORDER BY e.expense_date DESC, e.id DESC
            """,
            group_params
        )
        expenses_list = cur.fetchall()
        
        # Decrypt sensitive fields
        if encryptor:
            for expense in expenses_list:
                expense['description'] = encryptor.decrypt(expense['description'])
                expense['notes'] = encryptor.decrypt(expense['notes'])
                expense['expense_date_fmt'] = expense['expense_date'].strftime('%Y-%m-%d')
                
    except Exception as e:
        print(f"Error loading expenses: {e}", file=sys.stderr)
        flash('Error loading expenses list.', 'error')
        
    finally:
        if conn: conn.close()
        
    return render_template('expenses.html', expenses_list=expenses_list)


@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    lists = fetch_list_data()

    if request.method == 'POST':
        form_data = request.form
        
        # Input validation (simplified)
        try:
            amount = float(form_data['amount'])
            if amount <= 0:
                flash("Amount must be a positive number.", 'error')
                return render_template('add_expense.html', **lists)
        except ValueError:
            flash("Invalid amount entered.", 'error')
            return render_template('add_expense.html', **lists)

        description = form_data.get('description', '')
        notes = form_data.get('notes', '')
        
        # Encrypt sensitive fields
        if encryptor:
            encrypted_description = encryptor.encrypt(description)
            encrypted_notes = encryptor.encrypt(notes)
        else:
            encrypted_description = description
            encrypted_notes = notes

        conn = None
        try:
            # --- Base Currency Conversion (Simplified/Stubbed) ---
            base_currency_code = 'EUR' 
            exchange_rate = 1.0 # Default if base currency is the same as the expense currency
            
            if form_data['currency'] != base_currency_code:
                # Placeholder for real API call
                exchange_rate = 0.9 # Dummy rate
            
            base_amount = amount * exchange_rate
            
            # --- Database Insertion ---
            conn = get_db_connection()
            if conn is None:
                flash('Database unavailable. Expense not saved.', 'error')
                return render_template('add_expense.html', **lists)
                
            cur = conn.cursor()
            
            # Use g.group_id which is loaded in _load_logged_in_user
            group_id_to_insert = g.group_id if g.group_id is not None else None 
            
            cur.execute(
                """
                INSERT INTO expenses 
                (description, amount, currency, expense_date, notes, category_id, owner_id, group_id, base_amount, base_currency)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    encrypted_description, 
                    amount, 
                    form_data['currency'], 
                    form_data['expense_date'], 
                    encrypted_notes, 
                    form_data['category_id'], 
                    form_data['owner_id'],
                    group_id_to_insert,
                    base_amount,
                    base_currency_code
                )
            )
            
            conn.commit()
            flash('Expense successfully added!', 'success')
            return redirect(url_for('expenses'))
            
        except Exception as e:
            print(f"Expense insertion error: {e}", file=sys.stderr)
            flash(f"Error saving expense: {e}", 'error')
            if conn: conn.rollback()
            return render_template('add_expense.html', **lists)
            
        finally:
            if conn: 
                try: cur.close() 
                except: pass
                conn.close()

    # GET request
    return render_template('add_expense.html', **lists)

# --- ROUTES: UTILITIES / API ---

@app.route('/convert_currency')
@login_required
def convert_currency():
    """
    API endpoint to fetch real-time exchange rate (stubbed out)
    """
    if not EXCHANGE_RATE_API_KEY:
        return {'error': 'API key not configured.'}, 503

    from_currency = request.args.get('from', 'USD')
    to_currency = request.args.get('to', 'EUR')
    
    API_URL = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/pair/{from_currency}/{to_currency}"
    
    try:
        response = requests.get(API_URL)
        response.raise_for_status() 
        data = response.json()
        
        rate = data.get('conversion_rate')
        if rate:
            return {'rate': rate, 'success': True}
        else:
            return {'error': 'Could not retrieve rate.', 'success': False}, 500
            
    except requests.exceptions.RequestException as err:
        print(f"External API Error: {err}", file=sys.stderr)
        return {'error': 'Error communicating with external API.', 'success': False}, 500
        
    except Exception as e:
        print(f"Generic error in convert_currency: {e}", file=sys.stderr)
        return {'error': 'Internal server error.', 'success': False}, 500

# --- ROUTES: EXPENSE MANAGEMENT (CONTINUED) ---
@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    conn = get_db_connection()
    expense = None
    lists = fetch_list_data()

    if conn is None:
        flash('Database unavailable.', 'error')
        return redirect(url_for('expenses'))

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # 1. Fetch Expense Details (GET/Initial POST check)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
        
        cur.execute(
            f"""
            SELECT 
                e.id, 
                e.description, 
                e.amount, 
                e.currency, 
                e.expense_date, 
                e.notes,
                e.category_id, 
                e.owner_id
            FROM expenses e
            WHERE e.id = %s AND e.activate = TRUE {group_filter}
            """,
            (expense_id,) + group_params
        )
        expense = cur.fetchone()

        if not expense:
            flash('Expense not found or unauthorized to view.', 'error')
            cur.close()
            return redirect(url_for('expenses'))
            
        # Decrypt sensitive fields for display
        if encryptor:
            expense['description'] = encryptor.decrypt(expense['description'])
            expense['notes'] = encryptor.decrypt(expense['notes'])
        
        # Format date for HTML input type="date"
        expense['expense_date_fmt'] = expense['expense_date'].strftime('%Y-%m-%d')
        
        # --- Handle POST Request for Update ---
        if request.method == 'POST':
            form_data = request.form
            
            # Input validation (simplified)
            try:
                amount = float(form_data['amount'])
                if amount <= 0:
                    flash("Amount must be a positive number.", 'error')
                    return render_template('edit_expense.html', expense=expense, **lists) 
            except ValueError:
                flash("Invalid amount entered.", 'error')
                return render_template('edit_expense.html', expense=expense, **lists)

            new_description = form_data.get('description', '')
            new_notes = form_data.get('notes', '')
            
            # Encrypt sensitive fields before saving
            if encryptor:
                encrypted_description = encryptor.encrypt(new_description)
                encrypted_notes = encryptor.encrypt(new_notes)
            else:
                encrypted_description = new_description
                encrypted_notes = new_notes

            # Re-calculate base_amount (using the same simplified logic as add_expense)
            base_currency_code = 'EUR' 
            exchange_rate = 1.0 
            
            if form_data['currency'] != base_currency_code:
                exchange_rate = 0.9 # Dummy rate
            
            base_amount = amount * exchange_rate

            # Database Update
            update_query = f"""
                UPDATE expenses SET 
                    description = %s, 
                    amount = %s, 
                    currency = %s, 
                    expense_date = %s, 
                    notes = %s, 
                    category_id = %s, 
                    owner_id = %s, 
                    base_amount = %s, 
                    base_currency = %s
                WHERE id = %s 
                {group_filter}
            """
            
            params = (
                encrypted_description,
                amount,
                form_data['currency'],
                form_data['expense_date'],
                encrypted_notes,
                form_data['category_id'],
                form_data['owner_id'],
                base_amount,
                base_currency_code,
                expense_id
            ) + group_params

            cur.execute(update_query, params)
            
            if cur.rowcount == 0:
                flash("Update failed: Expense not found or unauthorized.", 'error') 
                if conn: conn.rollback()
                return redirect(url_for('expenses'))
                
            conn.commit()
            flash('Expense successfully updated!', 'success')
            return redirect(url_for('expenses'))
        
    except Exception as e:
        flash(f"Error updating expense: {e}", 'error')
        print(f"Expense update error: {e}", file=sys.stderr)
        if conn: conn.rollback()
        return redirect(url_for('expenses'))
        
    finally:
        # Close connection only if it was opened
        if conn: 
            try: cur.close() 
            except: pass
            conn.close()
        
    # GET request: Render the edit form with fetched expense data
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
        print(f"Expense delete error: {e}", file=sys.stderr)
        flash(f"Error deleting expense: {e}", 'error')
        if conn: conn.rollback()
        return redirect(url_for('expenses'))
        
    finally:
        if conn: cur.close(); conn.close()
        
if __name__ == '__main__':
    # NOTE: Set FLASK_ENV=development in your environment for debug=True
    app.run(debug=os.environ.get('FLASK_ENV') == 'development')
