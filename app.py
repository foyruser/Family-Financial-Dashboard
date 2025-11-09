from flask import Flask, request, redirect, url_for, session, g, flash, get_flashed_messages
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
from math import ceil

# --- APPLICATION INITIALIZATION & CONFIG ---
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_long_random_fallback_key') 
bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL') 
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY')
FERNET_KEY = os.environ.get('FERNET_KEY')

# --- CURRENCY CONSTANT ---
# Fallback rate: 1 USD = 83 INR. Rate stored is (1 INR to USD)
INR_PER_USD_FALLBACK = 83.0 

# --- ENCRYPTOR IMPLEMENTATION ---
class Encryptor:
    """Handles field-level encryption using Fernet."""
    def __init__(self, key):
        if not key:
            print("WARNING: FERNET_KEY not set. Using fallback key. DO NOT use in production.", file=sys.stderr)
            key = Fernet.generate_key().decode()
        
        self.f = Fernet(key.encode())

    def encrypt(self, data):
        if not data:
            return None
        return self.f.encrypt(data.encode()).decode()

    def decrypt(self, token):
        if not token:
            return None
        try:
            return self.f.decrypt(token.encode()).decode()
        except Exception:
            return None

encryptor = Encryptor(FERNET_KEY)

# --- TEMPLATE DEFINITIONS (REQUIRED FOR SINGLE-FILE COMPLETENESS) ---

BASE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Financial Tracker - {title}</title>
    <style>
        body {{ font-family: sans-serif; margin: 0; padding: 20px; background-color: #f4f7f6; }}
        .container {{ max-width: 800px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }}
        .header {{ border-bottom: 2px solid #ccc; padding-bottom: 10px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .header a {{ margin-left: 10px; text-decoration: none; color: #007bff; }}
        .flash {{ padding: 10px; margin-bottom: 10px; border-radius: 4px; }}
        .flash.success {{ background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
        .flash.error {{ background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }}
        .flash.warning {{ background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }}
        .flash.info {{ background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }}
        form div {{ margin-bottom: 15px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input[type="text"], input[type="password"], input[type="email"], input[type="date"], input[type="number"], select {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
        button {{ background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background-color: #0056b3; }}
        .expense-list table {{ width: 100%; border-collapse: collapse; }}
        .expense-list th, .expense-list td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        .expense-list th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Financial Tracker</h1>
            <nav>
                {nav_links}
            </nav>
        </div>
        {flashes}
        {content}
    </div>
</body>
</html>
"""

HTML_TEMPLATES = {
    'login.html': {
        'title': 'Login',
        'content': """
        <h2>Login</h2>
        <form method="POST">
            <div>
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Log In</button>
            <p><a href="{register_url}">Register</a> | <a href="{forgot_password_url}">Forgot Password?</a></p>
        </form>
        """
    },
    'register.html': {
        'title': 'Register',
        'content': """
        <h2>Register</h2>
        <form method="POST">
            <div>
                <label for="username">Username (Email)</label>
                <input type="email" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Register</button>
            <p><a href="{login_url}">Back to Login</a></p>
        </form>
        """
    },
    'forgot_password.html': {
        'title': 'Forgot Password',
        'content': """
        <h2>Forgot Password</h2>
        <p>Enter your email address and we'll send you a link to reset your password.</p>
        <form method="POST">
            <div>
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>
            <button type="submit">Send Reset Link</button>
            <p><a href="{login_url}">Back to Login</a></p>
        </form>
        """
    },
    'reset_password.html': {
        'title': 'Reset Password',
        'content': """
        <h2>Reset Password</h2>
        <form method="POST">
            <div>
                <label for="password">New Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Set New Password</button>
        </form>
        """
    },
    'home.html': {
        'title': 'Dashboard',
        'content': """
        <h2>Welcome, {username}!</h2>
        <p>Your role: <strong>{role}</strong> | Group ID: <strong>{group_id}</strong></p>
        <hr>
        <h3>Overview</h3>
        <p>Total active expenses in your group: <strong>{expense_count}</strong></p>
        <p><a href="{expenses_url}">View All Expenses</a> | <a href="{create_expense_url}">Record New Expense</a></p>
        """
    },
    'expenses.html': {
        'title': 'Expense List',
        'content': """
        <h2>Group Expenses</h2>
        <p><a href="{create_expense_url}">Record New Expense</a></p>
        <div class="expense-list">
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Category</th>
                        <th>Description</th>
                        <th>Amount</th>
                        <th>USD Equivalent</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {expense_rows}
                </tbody>
            </table>
        </div>
        """
    },
    'create_expense.html': {
        'title': 'Record New Expense',
        'content': """
        <h2>New Expense</h2>
        <form method="POST">
            <div>
                <label for="date">Date</label>
                <input type="date" id="date" name="date" required value="{today}">
            </div>
            <div>
                <label for="category">Category</label>
                <select id="category" name="category" required>
                    <option value="">Select Category</option>
                    {category_options}
                </select>
            </div>
            <div>
                <label for="description">Description (Encrypted)</label>
                <input type="text" id="description" name="description" required>
            </div>
            <div>
                <label for="amount">Amount</label>
                <input type="number" id="amount" name="amount" step="0.01" required>
            </div>
            <div>
                <label for="currency">Currency</label>
                <select id="currency" name="currency" required>
                    {currency_options}
                </select>
            </div>
            <button type="submit">Save Expense</button>
            <p><a href="{expenses_url}">Back to Expenses</a></p>
        </form>
        """
    },
    'edit_expense.html': {
        'title': 'Edit Expense',
        'content': """
        <h2>Edit Expense #{expense_id}</h2>
        <form method="POST">
            <div>
                <label for="date">Date</label>
                <input type="date" id="date" name="date" required value="{expense_date}">
            </div>
            <div>
                <label for="category">Category</label>
                <select id="category" name="category" required>
                    {category_options}
                </select>
            </div>
            <div>
                <label for="description">Description (Encrypted)</label>
                <input type="text" id="description" name="description" required value="{expense_description}">
            </div>
            <div>
                <label for="amount">Amount</label>
                <input type="number" id="amount" name="amount" step="0.01" required value="{expense_amount}">
            </div>
            <div>
                <label for="currency">Currency</label>
                <select id="currency" name="currency" required>
                    {currency_options}
                </select>
            </div>
            <button type="submit">Update Expense</button>
            <p><a href="{expenses_url}">Back to Expenses</a></p>
        </form>
        <form method="POST" action="{delete_expense_url}" style="margin-top: 10px;">
            <button type="submit" style="background-color: #dc3545;">Delete Expense (Soft)</button>
        </form>
        """
    }
}

def render_template(template_name, **context):
    """
    Custom function to simulate Flask's render_template using embedded HTML strings.
    FIXED: Passes pre-calculated URLs to the template context to resolve KeyError.
    """
    if template_name not in HTML_TEMPLATES:
        return f"<h1>Template '{template_name}' not found</h1>"

    template_data = HTML_TEMPLATES[template_name]
    title = template_data['title']
    content = template_data['content']
    
    # --- URL CONTEXT INJECTION (THE FIX) ---
    # Inject all necessary URLs into the context for use in the template strings
    context['login_url'] = url_for('login')
    context['register_url'] = url_for('register')
    context['forgot_password_url'] = url_for('forgot_password')
    context['home_url'] = url_for('home')
    context['expenses_url'] = url_for('expenses')
    context['create_expense_url'] = url_for('create_expense')
    
    # Handle specific dynamic content/loops
    
    # a. expenses.html list
    if template_name == 'expenses.html':
        expense_rows = ""
        if context.get('expenses'):
            for exp in context['expenses']:
                # Decrypt description on retrieval
                decrypted_desc = encryptor.decrypt(exp['description']) if exp['description'] else 'N/A'
                edit_url = url_for('edit_expense', expense_id=exp['id'])

                expense_rows += f"""
                <tr>
                    <td>{exp['date'].strftime('%Y-%m-%d')}</td>
                    <td>{exp['category']}</td>
                    <td>{decrypted_desc}</td>
                    <td>{exp['amount']} {exp['currency']}</td>
                    <td>{exp['converted_amount']:.2f} USD</td>
                    <td><a href="{edit_url}">Edit</a></td>
                </tr>
                """
        else:
            expense_rows = '<tr><td colspan="6">No expenses found.</td></tr>'
        content = content.replace('{expense_rows}', expense_rows)

    # b. create_expense.html / edit_expense.html options
    if template_name in ['create_expense.html', 'edit_expense.html']:
        category_options = "".join([f'<option value="{c}"{(" selected" if context.get("expense") and context["expense"]["category"] == c else "")}>{c}</option>' for c in context.get('categories', [])])
        currency_options = "".join([f'<option value="{c}"{(" selected" if context.get("expense") and context["expense"]["currency"] == c else "")}>{c}</option>' for c in context.get('currencies', [])])
        
        content = content.replace('{category_options}', category_options)
        content = content.replace('{currency_options}', currency_options)
        context['today'] = datetime.now().strftime('%Y-%m-%d')

        if template_name == 'edit_expense.html' and context.get('expense'):
            exp = context['expense']
            context['expense_id'] = str(exp['id'])
            context['expense_date'] = exp['date'].strftime('%Y-%m-%d')
            context['expense_description'] = encryptor.decrypt(exp['description']) if exp['description'] else '' # Decrypt for display/edit
            context['expense_amount'] = str(exp['amount'])
            context['delete_expense_url'] = url_for('delete_expense', expense_id=exp['id']) # Specific URL needed here
    
    # c. home.html data
    if template_name == 'home.html':
        context['username'] = g.user['username'] if g.user else 'Guest'
        context['role'] = g.user_role
        context['group_id'] = str(g.group_id) if g.group_id else 'None'


    # --- 1. Navigation Links ---
    if g.user:
        nav_links = f'<a href="{context["home_url"]}">Dashboard</a> | <a href="{context["expenses_url"]}">Expenses</a> | <a href="{url_for("logout")}">Logout ({context["username"]})</a>'
    else:
        nav_links = f'<a href="{context["login_url"]}">Login</a> | <a href="{context["register_url"]}">Register</a>'

    # --- 2. Flash Messages ---
    flashes = ""
    for category, message in get_flashed_messages(with_categories=True):
        flashes += f'<div class="flash {category}">{message}</div>'
    
    # --- 3. Final Content Rendering & Variable Substitution ---
    # Ensure all context variables are strings before format()
    context_str = {k: str(v) for k, v in context.items()}
    final_content = content.format(**context_str)

    # Final BASE_HTML injection
    return BASE_HTML.format(
        title=title,
        nav_links=nav_links,
        flashes=flashes,
        content=final_content
    )


# --- EXTERNAL SERVICE UTILITY FUNCTIONS ---

def get_exchange_rate(base_currency, target_currency):
    """
    Fetches the exchange rate (base -> target) using an external API.
    Implements robust error handling and conditional fallback for INR.
    """
    if base_currency.upper() == target_currency.upper():
        return 1.0

    # Define a default fallback rate for use in exception blocks
    fallback_rate = 1.0
    fallback_msg = " (Using rate of 1.0)"
    
    # Conditional INR fallback check (INR -> USD only)
    if base_currency.upper() == 'INR' and target_currency.upper() == 'USD':
        # 1 INR = 1 / 83 USD
        fallback_rate = 1.0 / INR_PER_USD_FALLBACK 
        fallback_msg = f" (Using fixed fallback rate: 1 INR = {fallback_rate:.5f} USD)"

    # Check for API Key unavailability
    if not EXCHANGE_RATE_API_KEY or EXCHANGE_RATE_API_KEY == 'DUMMY_API_KEY_REPLACE_ME':
        flash(f"Exchange rate service is unavailable (API key missing or dummy).{fallback_msg}", 'warning')
        return fallback_rate

    # API Request setup
    url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/pair/{base_currency}/{target_currency}"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)

        data = response.json()

        if data.get('result') == 'success':
            rate = data.get('conversion_rate')
            if rate is not None:
                return rate
            else:
                flash(f"Error fetching rate: 'conversion_rate' missing in response.{fallback_msg}", 'warning')
                print(f"API Data Error: 'conversion_rate' missing from response for {base_currency}/{target_currency}. Response: {data}", file=sys.stderr)
                return fallback_rate
        else:
            error_type = data.get('error-type', 'Unknown API Error')
            flash(f"Exchange Rate API failed: {error_type}.{fallback_msg}", 'error')
            print(f"API Error ({error_type}): Failed to get rate for {base_currency}/{target_currency}. Response: {data}", file=sys.stderr)
            return fallback_rate

    except requests.exceptions.Timeout:
        flash(f"External API connection timed out.{fallback_msg}", 'error')
        print(f"API Error: Request timed out for {base_currency}/{target_currency}.", file=sys.stderr)
        return fallback_rate
    except requests.exceptions.RequestException as e:
        flash(f"Could not connect to exchange rate service.{fallback_msg}", 'error')
        print(f"API Network Error: Failed to fetch rate for {base_currency}/{target_currency}. Error: {e}", file=sys.stderr)
        return fallback_rate
    except Exception as e:
        flash(f"An unexpected error occurred while processing currency data.{fallback_msg}", 'error')
        print(f"Unexpected API Processing Error: {e}", file=sys.stderr)
        return fallback_rate


# --- DATABASE CONNECTION UTILITY ---

def get_db_connection():
    """Establishes and returns a PostgreSQL database connection."""
    if not DATABASE_URL:
        print("FATAL: DATABASE_URL environment variable is not set.", file=sys.stderr)
        # Note: In a live environment, this should raise a config error, 
        # but here we'll simulate a failure that the caller can catch.
        flash("Database configuration is missing. Cannot connect.", 'error')
        raise ValueError("Database configuration missing.")

    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}", file=sys.stderr)
        flash("Could not connect to the database. Please check configuration.", 'error')
        raise


# --- AUTHENTICATION & GROUP UTILITIES ---

def get_group_filter_clause(role, group_id, table_name):
    """Constructs the WHERE clause for group access based on user role."""
    if role == 'admin':
        return '', ()
    elif group_id:
        return f' AND {table_name}.group_id = %s', (group_id,)
    else:
        return ' AND 1 = 0', ()

def login_required(view):
    """Decorator to require login for a route."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to view this page.", 'info')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def check_user_access():
    """Checks if the user has a group_id or is an admin."""
    # This check is only needed for features beyond the dashboard/login
    if g.user_role != 'admin' and g.group_id is None:
        flash('Access Denied: You must be assigned to a family group to use the financial tracker features.', 'error')
        return redirect(url_for('home'))
    return None

def check_admin_required(view):
    """Decorator to require admin role for a route."""
    @functools.wraps(view)
    @login_required
    def wrapped_view(**kwargs):
        if g.user_role != 'admin':
            flash("Access Denied: Admin privileges required.", 'error')
            return redirect(url_for('home'))
        return view(**kwargs)
    return wrapped_view


# --- BEFORE REQUEST HOOK ---

@app.before_request
def load_logged_in_user():
    """Loads user data into the Flask global object 'g' before processing a request."""
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
        g.user_role = 'guest'
        g.group_id = None
    else:
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                'SELECT id, username, role, group_id FROM users WHERE id = %s;', (user_id,)
            )
            user = cur.fetchone()
            
            if user:
                g.user = user
                g.user_role = user['role']
                g.group_id = user['group_id']
            else:
                session.clear()
                g.user = None
                g.user_role = 'guest'
                g.group_id = None
                
        except Exception as e:
            print(f"Database error during user load: {e}", file=sys.stderr)
            g.user = None
            g.user_role = 'guest'
            g.group_id = None
        finally:
            if conn: conn.close()


# --- STUB EMAIL FUNCTION (For Password Reset) ---

def send_reset_email(user_email, token):
    """Stub function to simulate sending a password reset email."""
    reset_link = url_for('reset_password', token=token, _external=True)
    print(f"--- PASSWORD RESET EMAIL STUB ---", file=sys.stderr)
    print(f"To: {user_email}", file=sys.stderr)
    print(f"Body: Click the following link to reset your password: {reset_link}", file=sys.stderr)
    print(f"--- END STUB ---", file=sys.stderr)
    return True


# --- AUTHENTICATION ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id, password FROM users WHERE username = %s;', (username,))
            user = cur.fetchone()
            
            # CRITICAL FIX: Ensure user exists AND the password field is not NULL before checking the hash
            if user and user.get('password') and bcrypt.check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password.', 'error')
        except Exception as e:
            flash(f"An error occurred during login: {e}", 'error')
            print(f"Login error: {e}", file=sys.stderr)
        finally:
            if conn: conn.close()
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute('SELECT id FROM users WHERE username = %s;', (username,))
            if cur.fetchone():
                flash('Username already exists. Please choose a different one.', 'error')
                # Need to use the render_template path again if registration fails
                return render_template('register.html')
            
            # Note: New users are created with role 'user' and a NULL group_id
            cur.execute(
                'INSERT INTO users (username, password, role) VALUES (%s, %s, %s);',
                (username, hashed_password, 'user')
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred during registration: {e}", 'error')
            print(f"Registration error: {e}", file=sys.stderr)
        finally:
            if conn: conn.close()
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        user_email = request.form['email']
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id FROM users WHERE username = %s;', (user_email,))
            user = cur.fetchone()

            if user:
                token = secrets.token_urlsafe(32)
                expires = datetime.now() + timedelta(hours=1)
                
                cur.execute(
                    'UPDATE users SET reset_token = %s, token_expiration = %s WHERE id = %s;',
                    (token, expires, user['id'])
                )
                conn.commit()
                send_reset_email(user_email, token)
                
            flash("If an account with that email exists, a password reset link has been sent.", 'info')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"An error occurred: {e}", 'error')
            print(f"Forgot password error: {e}", file=sys.stderr)
        finally:
            if conn: conn.close()
            
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute(
            'SELECT id FROM users WHERE reset_token = %s AND token_expiration > %s;',
            (token, datetime.now())
        )
        user = cur.fetchone()
        
        if not user:
            flash('Invalid or expired token.', 'error')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            new_password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            
            cur.execute(
                'UPDATE users SET password = %s, reset_token = NULL, token_expiration = NULL WHERE id = %s;',
                (hashed_password, user['id'])
            )
            conn.commit()
            flash('Your password has been reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
            
    except Exception as e:
        flash(f"An error occurred during password reset: {e}", 'error')
        print(f"Reset password error: {e}", file=sys.stderr)
    finally:
        if conn: conn.close()

    return render_template('reset_password.html', token=token)


# --- CORE APPLICATION ROUTES ---

@app.route('/')
@login_required
def home():
    """Main dashboard/home page."""
    conn = None
    expense_count = 0
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        cur.execute(f"SELECT COUNT(*) FROM expenses WHERE activate = TRUE {group_filter};", group_params)
        expense_count = cur.fetchone()[0]

    except Exception as e:
        flash(f"Error loading dashboard data: {e}", 'error')
        print(f"Dashboard loading error: {e}", file=sys.stderr)
        # Set count to 0 if DB connection fails
        expense_count = 0
    finally:
        if conn: conn.close()

    return render_template('home.html', expense_count=expense_count)


@app.route('/expenses', methods=['GET'])
@login_required
def expenses():
    """Displays a list of all active expenses for the user's group."""
    conn = None
    expenses_list = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        
        cur.execute(
            f"SELECT * FROM expenses WHERE activate = TRUE {group_filter} ORDER BY date DESC;", group_params
        )
        expenses_list = cur.fetchall()
        
        # NOTE: Sorting by date is handled in the SQL query (ORDER BY) for efficiency, 
        # but the original Python sort is left commented out as a fallback.
        # expenses_list.sort(key=lambda x: x['date'], reverse=True)

    except Exception as e:
        flash(f"Error loading expenses: {e}", 'error')
        print(f"Expense loading error: {e}", file=sys.stderr)
    finally:
        if conn: conn.close()
        
    return render_template('expenses.html', expenses=expenses_list)


@app.route('/create_expense', methods=['GET', 'POST'])
@login_required
def create_expense():
    """Handles expense creation, including currency conversion with API fallback."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = {
        'categories': ['Travel', 'Software', 'Meals', 'Office Supplies', 'Rent'],
        'currencies': ['USD', 'EUR', 'GBP', 'CAD', 'JPY', 'INR', 'AUD'],
    }
    
    if request.method == 'POST':
        date = request.form['date']
        category = request.form['category']
        # Encrypt the description before storing
        description_text = request.form['description']
        description = encryptor.encrypt(description_text)
        amount = request.form['amount']
        currency = request.form['currency'].upper()
        
        base_currency = 'USD' 
        conversion_rate = 1.0
        converted_amount = amount 

        if currency != base_currency:
            conversion_rate = get_exchange_rate(currency, base_currency) 
            try:
                converted_amount = float(amount) * conversion_rate
            except ValueError:
                flash("Invalid amount entered.", 'error')
                return redirect(url_for('create_expense'))
        
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute(
                """
                INSERT INTO expenses 
                (user_id, date, category, description, amount, currency, converted_amount, conversion_rate, group_id, activate) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE);
                """,
                (g.user['id'], date, category, description, amount, currency, converted_amount, conversion_rate, g.group_id)
            )
            
            conn.commit()
            flash("Expense successfully recorded!", 'success')
            return redirect(url_for('expenses'))

        except Exception as e:
            flash(f"Error saving expense: {e}", 'error')
            print(f"Expense saving error: {e}", file=sys.stderr)
            return redirect(url_for('create_expense'))
        finally:
            if conn: conn.close()
    
    return render_template('create_expense.html', **lists)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    """Handles editing an existing expense."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    lists = {
        'categories': ['Travel', 'Software', 'Meals', 'Office Supplies', 'Rent'],
        'currencies': ['USD', 'EUR', 'GBP', 'CAD', 'JPY', 'INR', 'AUD']
    }
    
    conn = None
    expense = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        cur.execute(f"SELECT * FROM expenses WHERE id = %s {group_filter};", (expense_id,) + group_params)
        expense = cur.fetchone()
        
        if expense is None:
            flash("Expense not found or unauthorized.", 'error')
            return redirect(url_for('expenses'))
            
    except Exception as e:
        flash(f"Error loading expense for edit: {e}", 'error')
        print(f"Expense loading error: {e}", file=sys.stderr)
        return redirect(url_for('expenses'))
    finally:
        if conn: conn.close()
        
    if request.method == 'POST':
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            date = request.form['date']
            category = request.form['category']
            # Re-encrypt the potentially modified description
            description_text = request.form['description']
            description = encryptor.encrypt(description_text)
            amount = request.form['amount']
            currency = request.form['currency'].upper()

            base_currency = 'USD' 
            conversion_rate = 1.0
            converted_amount = amount 
            
            if currency != base_currency:
                conversion_rate = get_exchange_rate(currency, base_currency)
                try:
                    converted_amount = float(amount) * conversion_rate
                except ValueError:
                    flash("Invalid amount entered.", 'error')
                    # Pass lists and expense data back if validation fails
                    return render_template('edit_expense.html', expense=expense, **lists)

            
            group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')

            cur.execute(
                f"""
                UPDATE expenses 
                SET date = %s, category = %s, description = %s, amount = %s, currency = %s, converted_amount = %s, conversion_rate = %s
                WHERE id = %s {group_filter};
                """,
                (date, category, description, amount, currency, converted_amount, conversion_rate, expense_id) + group_params
            )
            
            if cur.rowcount == 0:
                flash("Update failed: Expense not found or unauthorized.", 'error')
                return redirect(url_for('expenses'))
                
            conn.commit()
            flash("Expense successfully updated.", 'success')
            return redirect(url_for('expenses'))
            
        except Exception as e:
            flash(f"Error updating expense: {e}", 'error')
            print(f"Expense update error: {e}", file=sys.stderr)
            return redirect(url_for('edit_expense', expense_id=expense_id))
        finally:
            if conn: conn.close()
    
    # Decrypt description for GET display only
    display_expense = expense.copy()
    display_expense['description'] = encryptor.decrypt(display_expense['description'])
    
    return render_template('edit_expense.html', expense=display_expense, **lists)


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    """Performs a soft delete on an expense."""
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
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
        if conn: conn.close()

# The database setup is crucial for first-time use in a real environment
# This route is usually for initial admin setup and is protected by @check_admin_required
@app.route('/setup_db')
@check_admin_required
def setup_db():
    """Initializes necessary database tables and roles (Simplified for this file)."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # This is a stub for the full setup script. 
        # In a real environment, this would execute DDL to create users, expenses, and groups tables.
        
        flash("Database setup sequence initiated. (Assuming tables created successfully).", 'success')
        return redirect(url_for('home'))
    except Exception as e:
        flash(f"Database setup failed: {e}", 'error')
        print(f"DB Setup Error: {e}", file=sys.stderr)
        return redirect(url_for('home'))
    finally:
        if conn: conn.close()


# Main entry point for local development
if __name__ == '__main__':
    # Set default environment variables for local testing if not already set
    if 'DATABASE_URL' not in os.environ:
        os.environ['DATABASE_URL'] = 'postgresql://user:password@localhost/mydb'
    if 'FLASK_SECRET_KEY' not in os.environ:
        os.environ['FLASK_SECRET_KEY'] = 'dev_fallback_secret_key'
    # NOTE: DUMMY_API_KEY_REPLACE_ME will trigger the fallback logic.
    if 'EXCHANGE_RATE_API_KEY' not in os.environ:
         os.environ['EXCHANGE_RATE_API_KEY'] = 'DUMMY_API_KEY_REPLACE_ME' 
    if 'FERNET_KEY' not in os.environ:
         os.environ['FERNET_KEY'] = Fernet.generate_key().decode()

    # The actual Flask run command starts the application
    app.run(debug=True)
