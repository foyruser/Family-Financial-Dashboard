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

# --- SECURITY CONFIGURATION ---
# CRITICAL: CHANGE THIS TO A LONG, RANDOM STRING FOR PRODUCTION
app.secret_key = 'Hellohowareyoudoingiamdoingfineokaythankyou' 
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
    key = EXCHANGE_RATE_API_KEY # Use the securely read environment variable
    
    if not key:
        print("WARNING: EXCHANGE_RATE_API_KEY not set. Currency conversion disabled.", file=sys.stderr)
        return None
    
    # Using the ExchangeRate-API free tier (USD base)
    url = f"https://v6.exchangerate-api.com/v6/{key}/latest/USD"
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()
        
        if data['result'] == 'success':
            return data['conversion_rates']
        else:
            print(f"API Error: {data.get('error-type', 'Unknown error')}", file=sys.stderr)
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"Error fetching exchange rates: {e}", file=sys.stderr)
        return None
    
def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        raise ConnectionError("DATABASE_URL environment variable is not set.")
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        return conn
    except Exception as e:
        # Log the connection error details
        print(f"Database connection failed: {e}", file=sys.stderr)
        raise ConnectionError("Could not connect to the database.") from e

# --- AUTH DECORATOR ---

def login_required(view):
    """Decorator that ensures a user is logged in before allowing access to a view."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        # 1. Check if user_id is in session
        if session.get('user_id') is None:
            return redirect(url_for('login'))
        
        # 2. Check for approval (after successful login)
        user_id = session['user_id']
        is_approved = False
        conn_check = None
        try:
            conn_check = get_db_connection()
            cur_check = conn_check.cursor()
            cur_check.execute('SELECT is_approved FROM users WHERE id = %s;', (user_id,))
            is_approved_tuple = cur_check.fetchone()
            if is_approved_tuple and is_approved_tuple['is_approved']:
                is_approved = True
        except Exception as e:
            print(f"Approval check failed: {e}", file=sys.stderr)
        finally:
            if conn_check is not None:
                conn_check.close()
                
        if not is_approved:
            return redirect(url_for('pending_approval'))

        return view(**kwargs)
    return wrapped_view

# --- ROUTES ---

@app.route('/')
@login_required
def index():
    user_id = session.get('user_id')
    # CRITICAL FIX: Ensure group_id is an integer from session
    group_id = session.get('group_id')
    
    if group_id is None:
        # This should ideally not happen if login_required passed, but good safeguard
        return redirect(url_for('login'))
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. Fetch Assets
        try:
            cur.execute('''
                SELECT id, name, type, description, current_value, currency, notes, last_updated 
                FROM assets 
                WHERE group_id = %s AND active = TRUE
                ORDER BY name;
            ''', (group_id,))
            assets = cur.fetchall()
        except psycopg2.ProgrammingError as e:
            if 'column "description" does not exist' in str(e) or 'column "current_value" does not exist' in str(e) or 'column "notes" does not exist' in str(e):
                # We trap the specific error here to remind the user of the manual DB fix
                print(f"Database Schema Mismatch Error: {e}", file=sys.stderr)
                return "Error fetching assets: Database schema mismatch. Please ensure columns 'description', 'current_value', and 'notes' exist in the 'assets' table.", 500
            elif 'invalid input syntax for type integer' in str(e):
                # New Check: If group_id is not an integer
                print(f"Data Type Error: group_id in session is not an integer. Value: {group_id}", file=sys.stderr)
                return "Error fetching assets: group_id in session is not an integer. Log out and log back in to correct the session data.", 500
            else:
                raise # Re-raise other programming errors
        except Exception as e:
            print(f"Error fetching assets: {e}", file=sys.stderr)
            return f"Error fetching assets: {e}", 500


        # 2. Fetch Expenses (last 30 days)
        cur.execute('''
            SELECT e.id, e.amount, e.description, e.date, c.name as category_name, u.username as user_name
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            JOIN users u ON e.user_id = u.id
            WHERE e.group_id = %s AND e.activate = TRUE AND e.date >= NOW() - INTERVAL '30 days'
            ORDER BY e.date DESC, e.created_at DESC;
        ''', (group_id,))
        recent_expenses = cur.fetchall()

        # 3. Calculate Expense Totals by Category for the month
        cur.execute('''
            SELECT c.name as category_name, SUM(e.amount) as total_spent
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            WHERE e.group_id = %s 
            AND e.activate = TRUE 
            AND EXTRACT(YEAR FROM e.date) = EXTRACT(YEAR FROM CURRENT_DATE)
            AND EXTRACT(MONTH FROM e.date) = EXTRACT(MONTH FROM CURRENT_DATE)
            GROUP BY c.name
            ORDER BY total_spent DESC;
        ''', (group_id,))
        category_totals = cur.fetchall()
        
        # 4. Fetch Budgets
        cur.execute('''
            SELECT b.monthly_limit, c.name as category_name
            FROM budgets b
            JOIN categories c ON b.category_id = c.id
            WHERE b.group_id = %s AND b.active = TRUE;
        ''', (group_id,))
        budgets = cur.fetchall()

        # 5. Fetch Savings Goals
        cur.execute('''
            SELECT id, name, target_amount, current_amount, target_date
            FROM savings_goals
            WHERE group_id = %s AND active = TRUE
            ORDER BY target_date;
        ''', (group_id,))
        goals = cur.fetchall()

        # Combine totals and budgets for dashboard display
        budget_summary = {}
        for b in budgets:
            budget_summary[b['category_name']] = {'limit': b['monthly_limit'], 'spent': 0}
            
        for t in category_totals:
            if t['category_name'] in budget_summary:
                budget_summary[t['category_name']]['spent'] = t['total_spent']
            else:
                # Category exists but has no budget set
                budget_summary[t['category_name']] = {'limit': None, 'spent': t['total_spent']}

        # Calculate Net Worth (Assets - Debts)
        net_worth = 0
        for asset in assets:
            if asset['type'] and 'Debt' in asset['type']:
                net_worth -= asset['current_value']
            else:
                net_worth += asset['current_value']

        return render_template('index.html', 
                               assets=assets, 
                               recent_expenses=recent_expenses,
                               budget_summary=budget_summary,
                               goals=goals,
                               net_worth=net_worth)

    except ConnectionError as e:
        # ConnectionError is custom, handles missing DATABASE_URL or psycopg2 failure
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        # Catch-all for other unhandled exceptions
        print(f"Error in index route: {e}", file=sys.stderr)
        return f"An unexpected error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

# --- LOGIN/LOGOUT/APPROVAL ROUTES ---

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = None
        error = None
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Fetch user details including hashed password and group ID
            cur.execute(
                'SELECT id, hashed_password, group_id, is_approved FROM users WHERE username = %s;',
                (username,)
            )
            user = cur.fetchone()

            if user is None:
                error = 'Incorrect username.'
            elif not bcrypt.check_password_hash(user['hashed_password'], password):
                error = 'Incorrect password.'
            else:
                # Login SUCCESS
                session.clear()
                session['user_id'] = user['id']
                # *** CRITICAL FIX: Ensure the INTEGER group_id is stored ***
                if user['group_id'] is not None:
                    session['group_id'] = user['group_id']
                else:
                    # Handle case where user is registered but not yet assigned to a group (should be handled at registration)
                    error = 'User not assigned to a group. Contact an admin.'
                    
                if error is None:
                    # Check approval status immediately
                    if user['is_approved']:
                        return redirect(url_for('index'))
                    else:
                        return redirect(url_for('pending_approval'))

        except ConnectionError:
            error = "Database connection failed. Please try again later."
        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            error = f"An unexpected error occurred during login: {e}"
        finally:
            if conn is not None:
                conn.close()

        if error:
            return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        group_name = request.form['group_name'] # User provides existing group name or new name

        conn = None
        error = None
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # 1. Check if username is already taken
            cur.execute('SELECT id FROM users WHERE username = %s;', (username,))
            if cur.fetchone() is not None:
                error = f'User {username} is already registered.'

            # 2. Check for existing group or create new one
            group_id = None
            cur.execute('SELECT id FROM groups WHERE name = %s;', (group_name,))
            group_row = cur.fetchone()
            
            if group_row:
                # Group exists, user is joining it. They will need admin approval.
                group_id = group_row['id']
                is_admin = False # Joining user is not admin
                is_approved = False # Joining user needs approval
            else:
                # Group does not exist, user is creating a new one and is the admin.
                cur.execute('INSERT INTO groups (name) VALUES (%s) RETURNING id;', (group_name,))
                group_id = cur.fetchone()['id']
                is_admin = True
                is_approved = True # Admin is automatically approved

            # 3. Hash password and insert user
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            if group_id is not None:
                cur.execute(
                    '''
                    INSERT INTO users (username, hashed_password, group_id, is_admin, is_approved) 
                    VALUES (%s, %s, %s, %s, %s) 
                    RETURNING id;
                    ''',
                    (username, hashed_password, group_id, is_admin, is_approved)
                )
                user_id = cur.fetchone()['id']
                
                # 4. If new group, update group's admin_user_id
                if is_admin:
                    cur.execute(
                        'UPDATE groups SET admin_user_id = %s WHERE id = %s;',
                        (user_id, group_id)
                    )
                    
                conn.commit()
                
                # Registration Success - Set session and redirect
                session.clear()
                session['user_id'] = user_id
                # *** CRITICAL FIX: Ensure the INTEGER group_id is stored ***
                session['group_id'] = group_id
                
                if is_approved:
                    return redirect(url_for('index'))
                else:
                    return redirect(url_for('pending_approval'))

        except psycopg2.IntegrityError as e:
            conn.rollback()
            if 'duplicate key value violates unique constraint' in str(e):
                error = 'A user with that username already exists.'
            else:
                error = 'An integrity error occurred. Please check your inputs.'
        except ConnectionError:
            error = "Database connection failed. Please try again later."
        except Exception as e:
            conn.rollback()
            print(f"Registration error: {e}", file=sys.stderr)
            error = f"An unexpected error occurred during registration: {e}"
        finally:
            if conn is not None:
                conn.close()

        return render_template('register.html', error=error)

# ... (other routes follow)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/pending_approval')
def pending_approval():
    return render_template('pending_approval.html')


@app.route('/categories')
@login_required
def categories():
    group_id = session.get('group_id')
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT id, name FROM categories WHERE group_id = %s ORDER BY name;', (group_id,))
        categories = cur.fetchall()
        return render_template('categories.html', categories=categories)
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Error fetching categories: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    group_id = session.get('group_id')
    category_name = request.form['name'].strip()
    
    if not category_name:
        return redirect(url_for('categories'))
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO categories (group_id, name) VALUES (%s, %s);', (group_id, category_name))
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        # Handle case where category name is not unique within the group
        return render_template('categories.html', categories=[], error=f"Category '{category_name}' already exists in your group."), 400
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error adding category: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('categories'))

@app.route('/delete_category/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Check if the category is used in any active expense or budget
        cur.execute('SELECT id FROM expenses WHERE category_id = %s AND activate = TRUE LIMIT 1;', (category_id,))
        if cur.fetchone():
            return render_template('categories.html', categories=[], error="Cannot delete category: It is currently used in active expenses. Please re-assign expenses first."), 400

        cur.execute('SELECT id FROM budgets WHERE category_id = %s AND active = TRUE LIMIT 1;', (category_id,))
        if cur.fetchone():
             return render_template('categories.html', categories=[], error="Cannot delete category: It is currently used in an active budget."), 400
             
        # Delete the category
        cur.execute('DELETE FROM categories WHERE id = %s;', (category_id,))
        conn.commit()
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error deleting category: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('categories'))

@app.route('/expenses')
@login_required
def expenses():
    group_id = session.get('group_id')
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch all active expenses for the group
        cur.execute('''
            SELECT 
                e.id, 
                e.amount, 
                e.description, 
                e.date, 
                c.name as category_name, 
                u.username as user_name
            FROM expenses e
            JOIN categories c ON e.category_id = c.id
            JOIN users u ON e.user_id = u.id
            WHERE e.group_id = %s AND e.activate = TRUE
            ORDER BY e.date DESC, e.created_at DESC;
        ''', (group_id,))
        all_expenses = cur.fetchall()

        # Fetch categories and users for the form
        cur.execute('SELECT id, name FROM categories WHERE group_id = %s ORDER BY name;', (group_id,))
        categories = cur.fetchall()
        
        # Only fetch users who are part of the current group
        cur.execute('SELECT id, username FROM users WHERE group_id = %s AND is_approved = TRUE ORDER BY username;', (group_id,))
        users = cur.fetchall()

        return render_template('expenses.html', 
                               all_expenses=all_expenses, 
                               categories=categories,
                               users=users)
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Error fetching expenses data: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    group_id = session.get('group_id')
    user_id = session.get('user_id') # Current logged in user is the default expense creator

    try:
        amount = float(request.form['amount'])
        description = request.form['description'].strip()
        date = request.form['date']
        category_id = request.form['category_id']
        
        # Optional: allow the user to submit an expense on behalf of another user in the group
        expense_user_id = request.form.get('expense_user_id', user_id) 

    except ValueError:
        return "Invalid amount or data format.", 400
    
    if amount <= 0:
        return "Amount must be positive.", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            '''
            INSERT INTO expenses (group_id, user_id, amount, description, date, category_id)
            VALUES (%s, %s, %s, %s, %s, %s);
            ''',
            (group_id, expense_user_id, amount, description, date, category_id)
        )
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error adding expense: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('expenses'))


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    """Marks an expense as inactive (soft delete)."""
    
    # NEW CHECK: Reroute unapproved users
    user_id = session.get('user_id')
    if user_id:
        conn_check = None
        try:
            conn_check = get_db_connection()
            cur_check = conn_check.cursor()
            cur_check.execute('SELECT is_approved FROM users WHERE id = %s;', (user_id,))
            is_approved_tuple = cur_check.fetchone()
            if not is_approved_tuple or not is_approved_tuple['is_approved']: 
                return redirect(url_for('pending_approval'))
        except Exception as e:
            print(f"Delete expense route approval check failed: {e}", file=sys.stderr)
        finally:
            if conn_check is not None:
                conn_check.close()
                
    # Proceed with original logic...
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
            conn.close()
            
    return redirect(url_for('expenses'))


@app.route('/budgets')
@login_required
def budgets():
    group_id = session.get('group_id')
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Fetch active budgets with category names
        cur.execute('''
            SELECT b.id, b.monthly_limit, c.name as category_name
            FROM budgets b
            JOIN categories c ON b.category_id = c.id
            WHERE b.group_id = %s AND b.active = TRUE
            ORDER BY c.name;
        ''', (group_id,))
        active_budgets = cur.fetchall()
        
        # 2. Fetch categories that DO NOT currently have an active budget for the form
        cur.execute('''
            SELECT c.id, c.name
            FROM categories c
            LEFT JOIN budgets b ON c.id = b.category_id AND b.group_id = %s AND b.active = TRUE
            WHERE c.group_id = %s AND b.id IS NULL
            ORDER BY c.name;
        ''', (group_id, group_id))
        available_categories = cur.fetchall()

        return render_template('budgets.html', 
                               active_budgets=active_budgets, 
                               available_categories=available_categories)
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Error fetching budgets data: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

@app.route('/add_budget', methods=['POST'])
@login_required
def add_budget():
    group_id = session.get('group_id')
    
    try:
        category_id = request.form['category_id']
        monthly_limit = float(request.form['monthly_limit'])
    except ValueError:
        return "Invalid amount or data format.", 400
    
    if monthly_limit <= 0:
        return "Budget limit must be positive.", 400
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Insert new budget (assuming active=TRUE and start_date=CURRENT_DATE)
        cur.execute(
            '''
            INSERT INTO budgets (group_id, category_id, monthly_limit, start_date, active)
            VALUES (%s, %s, %s, CURRENT_DATE, TRUE);
            ''',
            (group_id, category_id, monthly_limit)
        )
        conn.commit()

    except psycopg2.IntegrityError:
        conn.rollback()
        return "A budget already exists for this category.", 400
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error adding budget: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('budgets'))


@app.route('/delete_budget/<int:budget_id>', methods=['POST'])
@login_required
def delete_budget(budget_id):
    """Deactivates a budget (soft delete)."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Simply mark as inactive instead of deleting permanently
        cur.execute('UPDATE budgets SET active = FALSE WHERE id = %s;', (budget_id,))
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error deleting budget: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('budgets'))

# --- ASSETS ROUTES ---

@app.route('/assets')
@login_required
def assets():
    group_id = session.get('group_id')
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch all active assets for the group
        # NOTE: This is the query that threw the error. It needs the integer group_id.
        cur.execute('''
            SELECT id, name, type, description, current_value, currency, notes, last_updated 
            FROM assets 
            WHERE group_id = %s AND active = TRUE
            ORDER BY name;
        ''', (group_id,))
        all_assets = cur.fetchall()

        # Define asset types for the form/template
        asset_types = ['Checking', 'Savings', 'Investment', 'Cash', 'Debt (Credit Card)', 'Debt (Loan)', 'Other']

        return render_template('assets.html', 
                               all_assets=all_assets,
                               asset_types=asset_types)
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        # Check for the specific error to provide a more helpful message
        if 'invalid input syntax for type integer' in str(e):
             print(f"Data Type Error: group_id in session is not an integer. Value: {session.get('group_id')}", file=sys.stderr)
             return "Error fetching assets: group_id in session is not an integer. Log out and log back in to correct the session data.", 500

        print(f"Error fetching assets data: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

@app.route('/add_asset', methods=['POST'])
@login_required
def add_asset():
    group_id = session.get('group_id')
    
    try:
        name = request.form['name'].strip()
        asset_type = request.form['type'].strip()
        current_value = float(request.form['current_value'])
        description = request.form.get('description', '').strip()
        notes = request.form.get('notes', '').strip()
        currency = request.form.get('currency', 'USD').strip()
    except ValueError:
        return "Invalid current value format.", 400
    
    if not name or not asset_type:
        return "Asset name and type are required.", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            '''
            INSERT INTO assets (group_id, name, type, description, current_value, notes, currency)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
            ''',
            (group_id, name, asset_type, description, current_value, notes, currency)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        return "An asset with that name already exists in your group.", 400
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error adding asset: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('assets'))


@app.route('/update_asset_value/<int:asset_id>', methods=['POST'])
@login_required
def update_asset_value(asset_id):
    group_id = session.get('group_id')
    
    try:
        new_value = float(request.form['new_value'])
    except ValueError:
        return "Invalid value format.", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Ensure the asset belongs to the user's group before updating
        cur.execute('SELECT id FROM assets WHERE id = %s AND group_id = %s;', (asset_id, group_id))
        if cur.fetchone() is None:
            return "Asset not found or unauthorized.", 403
            
        cur.execute(
            '''
            UPDATE assets SET current_value = %s, last_updated = CURRENT_TIMESTAMP
            WHERE id = %s;
            ''',
            (new_value, asset_id)
        )
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error updating asset value: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('assets'))


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    """Marks an asset as inactive (soft delete)."""
    group_id = session.get('group_id')

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Ensure the asset belongs to the user's group before deleting
        cur.execute('SELECT id FROM assets WHERE id = %s AND group_id = %s;', (asset_id, group_id))
        if cur.fetchone() is None:
            return "Asset not found or unauthorized.", 403
            
        cur.execute(
            '''
            UPDATE assets SET active = FALSE
            WHERE id = %s;
            ''',
            (asset_id,)
        )
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error deleting asset: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('assets'))


# --- SAVINGS GOALS ROUTES ---

@app.route('/goals')
@login_required
def goals():
    group_id = session.get('group_id')
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch all active savings goals for the group
        cur.execute('''
            SELECT id, name, target_amount, current_amount, target_date
            FROM savings_goals
            WHERE group_id = %s AND active = TRUE
            ORDER BY target_date;
        ''', (group_id,))
        all_goals = cur.fetchall()

        return render_template('goals.html', 
                               all_goals=all_goals)
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Error fetching goals data: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

@app.route('/add_goal', methods=['POST'])
@login_required
def add_goal():
    group_id = session.get('group_id')
    
    try:
        name = request.form['name'].strip()
        target_amount = float(request.form['target_amount'])
        target_date = request.form['target_date']
        # Current amount can be optional, default to 0.00
        current_amount = float(request.form.get('current_amount', 0.00)) 
    except ValueError:
        return "Invalid amount or data format.", 400
    
    if target_amount <= 0:
        return "Target amount must be positive.", 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            '''
            INSERT INTO savings_goals (group_id, name, target_amount, current_amount, target_date)
            VALUES (%s, %s, %s, %s, %s);
            ''',
            (group_id, name, target_amount, current_amount, target_date)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        return "A goal with that name already exists in your group.", 400
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error adding goal: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('goals'))


@app.route('/update_goal_amount/<int:goal_id>', methods=['POST'])
@login_required
def update_goal_amount(goal_id):
    group_id = session.get('group_id')
    
    try:
        # Use 'add_amount' to incrementally update the goal
        add_amount = float(request.form['add_amount'])
    except ValueError:
        return "Invalid amount format.", 400
        
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Ensure the goal belongs to the user's group before updating
        cur.execute('SELECT id FROM savings_goals WHERE id = %s AND group_id = %s;', (goal_id, group_id))
        if cur.fetchone() is None:
            return "Goal not found or unauthorized.", 403
            
        # Update the current_amount by adding the new contribution
        cur.execute(
            '''
            UPDATE savings_goals 
            SET current_amount = current_amount + %s
            WHERE id = %s;
            ''',
            (add_amount, goal_id)
        )
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error updating goal amount: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('goals'))


@app.route('/delete_goal/<int:goal_id>', methods=['POST'])
@login_required
def delete_goal(goal_id):
    """Marks a goal as inactive (soft delete)."""
    group_id = session.get('group_id')

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Ensure the goal belongs to the user's group before deleting
        cur.execute('SELECT id FROM savings_goals WHERE id = %s AND group_id = %s;', (goal_id, group_id))
        if cur.fetchone() is None:
            return "Goal not found or unauthorized.", 403
            
        cur.execute(
            '''
            UPDATE savings_goals SET active = FALSE
            WHERE id = %s;
            ''',
            (goal_id,)
        )
        conn.commit()
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error deleting goal: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('goals'))

# --- USER MANAGEMENT ROUTES ---

@app.route('/admin/users')
@login_required
def admin_users():
    group_id = session.get('group_id')
    user_id = session.get('user_id')
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Check if the current user is an admin
        cur.execute('SELECT is_admin FROM users WHERE id = %s AND group_id = %s;', (user_id, group_id))
        user_row = cur.fetchone()
        if not user_row or not user_row['is_admin']:
            return "Access Denied: You must be an administrator to view this page.", 403
            
        # 2. Fetch all users in the group
        cur.execute('''
            SELECT id, username, is_admin, is_approved 
            FROM users 
            WHERE group_id = %s 
            ORDER BY is_approved DESC, username;
        ''', (group_id,))
        users = cur.fetchall()

        return render_template('admin_users.html', users=users)
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        print(f"Error fetching admin user data: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()

@app.route('/admin/approve_user/<int:user_to_approve_id>', methods=['POST'])
@login_required
def approve_user(user_to_approve_id):
    group_id = session.get('group_id')
    admin_user_id = session.get('user_id')

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Security check: Must be an admin AND the target user must be in the same group
        cur.execute('SELECT is_admin FROM users WHERE id = %s AND group_id = %s;', (admin_user_id, group_id))
        admin_row = cur.fetchone()
        
        if not admin_row or not admin_row['is_admin']:
            return "Access Denied: Not an administrator.", 403
            
        # Perform the approval
        cur.execute(
            'UPDATE users SET is_approved = TRUE WHERE id = %s AND group_id = %s;',
            (user_to_approve_id, group_id)
        )
        conn.commit()
        
    except ConnectionError as e:
        return f"Database Connection Error: {e}", 500
    except Exception as e:
        conn.rollback()
        print(f"Error approving user: {e}", file=sys.stderr)
        return f"An error occurred: {e}", 500
    finally:
        if conn is not None:
            conn.close()
            
    return redirect(url_for('admin_users'))

# --- MAIN RUN BLOCK ---

if __name__ == '__main__':
    # This is useful for debugging locally, but the production environment (Render) 
    # will handle the running of the application.
    app.run(debug=True)
