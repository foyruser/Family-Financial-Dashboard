from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_bcrypt import Bcrypt
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools
import os
import sys


# --- APPLICATION INITIALIZATION & CONFIG ---
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_long_random_fallback_key') 
bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL') 
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY')


# --- CONNECTION HELPER FUNCTIONS ---

class ConnectionError(Exception):
    pass

def get_exchange_rates():
    """Fetches the latest exchange rates from USD base or uses fallback."""
    key = EXCHANGE_RATE_API_KEY
    fallback_rates = {'USD': 1.0, 'INR': 83.0, 'EUR': 0.9, 'GBP': 0.8}
    if not key:
        print("WARNING: EXCHANGE_RATE_API_KEY is missing. Using fallback rates.", file=sys.stderr)
        return fallback_rates
        
    url = f'https://v6.exchangerate-api.com/v6/{key}/latest/USD'
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data.get('result') == 'success':
            return data['conversion_rates']
        print(f"ERROR: API call failed. Status: {data.get('result')}. Using fallback rates.", file=sys.stderr)
        return fallback_rates
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to connect to exchange rate API: {e}. Using fallback rates.", file=sys.stderr)
        return fallback_rates

def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        raise ConnectionError("DATABASE_URL environment variable not found.")
    try:
        return psycopg2.connect(DATABASE_URL)
    except Exception as e:
        print(f"Database connection failed: {e}", file=sys.stderr)
        raise ConnectionError(f"Failed to connect to database: {e}")

# --- SECURITY & RBAC HELPERS ---

def get_user_info(user_id):
    """Fetches role and group_id."""
    if not user_id: return None, None
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT role, group_id FROM users WHERE id = %s;', (user_id,))
        info = cur.fetchone()
        return info[0], info[1] if info else (None, None)
    except Exception as e:
        print(f"CRITICAL: Failed to fetch user info for ID {user_id}: {e}", file=sys.stderr)
        return None, None 
    finally:
        if conn: conn.close()

def get_group_filter_clause(user_role, group_id, table_alias):
    """Returns WHERE clause for strict group segregation."""
    if not group_id or group_id == 'pending-group':
        return f"AND 1=0", ()
    return f"AND {table_alias}.group_id = %s", (group_id,)

def check_user_access():
    """Checks role, sets g.group_id/g.user_role, and redirects if unauthorized."""
    user_id = session.get('user_id')
    g.user_role, g.group_id = get_user_info(user_id)
    
    if g.user_role is None:
        session.pop('user_id', None)
        session.pop('username', None)
        return redirect(url_for('login'), 307)
    
    if g.user_role == 'pending':
        return redirect(url_for('pending_approval'), 307)
        
    return None

def login_required(view):
    """Decorator for authentication check."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    """Decorator for admin role check (for management tasks only)."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if get_user_info(session.get('user_id'))[0] != 'admin':
            return render_template('error.html', message="Access Denied: Admin required."), 403
        return view(**kwargs)
    return wrapped_view

# --- DATA HELPERS ---
def get_owners():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id, name FROM owners ORDER BY name;')
        return cur.fetchall()
    except ConnectionError:
        return []
    finally:
        if conn: conn.close()

def get_asset_type_distribution():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
        query = f"""
            SELECT type, SUM(value) as total_value
            FROM assets
            WHERE activate = TRUE {group_filter}
            GROUP BY type
            ORDER BY total_value DESC
        """
        cur.execute(query, group_params)
        return cur.fetchall()
    except ConnectionError:
        return []
    finally:
        if conn: conn.close()

# --- AUTH ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            # ASSIGNMENT 1: Initial role='pending', group_id='pending-group'
            cur.execute('INSERT INTO users (username, password_hash, role, group_id) VALUES (%s, %s, %s, %s) RETURNING id;', 
                        (username, password_hash, 'pending', 'pending-group'))
            session['user_id'], session['username'] = cur.fetchone()[0], username
            conn.commit()
            return redirect(url_for('pending_approval')) 
        except psycopg2.IntegrityError:
            return render_template('register.html', error='Username taken.')
        except Exception as e:
            return render_template('register.html', error=f'Error: {e}')
        finally:
            if conn: conn.close()
    return render_template('register.html', error=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute('SELECT id, password_hash, role FROM users WHERE username = %s;', (request.form['username'],))
            user = cur.fetchone()
            if user and bcrypt.check_password_hash(user['password_hash'], request.form['password']):
                session['user_id'], session['username'] = user['id'], request.form['username']
                return redirect(url_for('pending_approval') if user.get('role') == 'pending' else url_for('home'))
            return render_template('login.html', error='Invalid credentials.')
        except Exception as e:
            return render_template('login.html', error=f'Login error: {e}')
        finally:
            if conn: conn.close()
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('user_id', None); session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/pending')
@login_required 
def pending_approval():
    if get_user_info(session.get('user_id'))[0] in ['user', 'admin']:
        return redirect(url_for('home'))
    return render_template('pending_approval.html')

@app.route('/admin/approve', methods=['GET', 'POST'])
@login_required 
@admin_required 
def admin_approve_users():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        if request.method == 'POST':
            user_id_to_approve, new_group_id = request.form.get('user_id'), request.form.get('group_id')
            if user_id_to_approve and new_group_id:
                # ASSIGNMENT 2: Update role and set the final group_id
                cur.execute('UPDATE users SET role = %s, group_id = %s WHERE id = %s AND role = %s;', 
                            ('user', new_group_id, user_id_to_approve, 'pending'))
                conn.commit()

        cur.execute("SELECT id, username FROM users WHERE role = 'pending' ORDER BY id;")
        return render_template('admin_approve_users.html', pending_users=cur.fetchall())
    except Exception as e:
        if conn: conn.rollback()
        return f"Admin approval error: {e}", 500
    finally:
        if conn: conn.close()

# --- PROTECTED APPLICATION ROUTES (STRICTLY GROUP FILTERED) ---

@app.route('/home')
@login_required
def home():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

    group_filter_a, group_params_a = get_group_filter_clause(g.user_role, g.group_id, 'a')
    group_filter_e, group_params_e = get_group_filter_clause(g.user_role, g.group_id, 'e')
    conn, total_asset_usd, total_expense_usd = None, 0, 0

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        asset_query = f'SELECT a.* FROM assets a JOIN owners o ON a.owner_id = o.id WHERE a.activate = TRUE {group_filter_a};'
        cur.execute(asset_query, group_params_a)
        assets = cur.fetchall()
        expense_query = f'SELECT e.* FROM expenses e JOIN owners o ON e.owner_id = o.id WHERE e.activate = TRUE {group_filter_e};'
        cur.execute(expense_query, group_params_e)
        expenses = cur.fetchall()
    except ConnectionError: return "Database Connection Error.", 500
    finally:
        if conn: conn.close()

    rates = get_exchange_rates()
    for item in assets + expenses:
        cur_currency = item['currency']
        value = float(item.get('value', item.get('amount', 0.00)))
        rate_to_usd = rates.get(cur_currency, 0)
        value_usd = value if cur_currency == 'USD' else round(value / rate_to_usd, 2) if rate_to_usd else 0
        if item.get('value') is not None: total_asset_usd += value_usd
        if item.get('amount') is not None: total_expense_usd += value_usd
        
    net_usd = round(total_asset_usd - total_expense_usd, 2)
    net_inr = round(net_usd * rates.get('INR', 83), 2)

    return render_template('home.html',
        total_asset_usd=round(total_asset_usd, 2),
        total_asset_inr=round(total_asset_usd * rates.get('INR', 83), 2),
        total_expense_usd=round(total_expense_usd, 2),
        total_expense_inr=round(total_expense_usd * rates.get('INR', 83), 2),
        net_usd=net_usd,
        net_inr=net_inr,
        asset_type_data=get_asset_type_distribution()
    )


@app.route('/')
@login_required
def index():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response 

    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'a')
    sort_by, order = request.args.get('sort_by', 'value_usd'), request.args.get('order', 'desc')
    db_sorts = {'id': 'a.id', 'type': 'a.type', 'name': 'a.name', 'value': 'a.value', 'owner_name': 'o.name'}
    sort_column = db_sorts.get(sort_by, 'a.id')
    order_db = 'ASC' if order.lower() == 'asc' else 'DESC'
    
    conn, total_usd, total_inr = None, 0, 0
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        query = f'SELECT a.*, o.name AS owner_name FROM assets a JOIN owners o ON a.owner_id = o.id WHERE a.activate = TRUE {group_filter} ORDER BY {sort_column} {order_db};'
        cur.execute(query, group_params)
        assets = cur.fetchall()
    except ConnectionError: return "Database Connection Error.", 500
    finally:
        if conn: conn.close()
    
    rates = get_exchange_rates()
    for asset in assets:
        value = float(asset.get('value', 0.00))
        rate_to_usd = rates.get(asset['currency'], 0)
        asset['value_usd'] = round(value / rate_to_usd, 2) if rate_to_usd and asset['currency'] != 'USD' else value
        asset['value_inr'] = round(asset['value_usd'] * rates.get('INR', 83), 2)
        total_usd += asset['value_usd']
        total_inr += asset['value_inr']

    if sort_by == 'value_usd':
        assets.sort(key=lambda a: a.get('value_usd', 0.00), reverse=(order_db == 'DESC'))
    
    return render_template('index.html', assets=assets, total_usd=round(total_usd, 2), total_inr=round(total_inr, 2), sort_by=sort_by, order=order_db.lower())


@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response

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
    except ConnectionError: return "Database Connection Error.", 500
    finally:
        if conn and request.method == 'GET': conn.close()

    if request.method == 'POST':
        form_data = request.form
        value = float(form_data.get('value', 0.00))
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO assets (owner_id, type, name, country, currency, value, account_no, last_updated, notes, activate, financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location, investment_strategy, group_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_DATE, %s, TRUE, %s, %s, %s, %s, %s, %s, %s)
            """, (
                form_data['owner_id'], form_data['type'], form_data['name'], form_data['country'], form_data['currency'], value, form_data['account_no'], form_data['notes'],
                form_data['financial_institution'], form_data['beneficiary_name'], form_data['policy_or_plan_type'], form_data['contact_phone'], form_data['document_location'], form_data['investment_strategy'], g.group_id 
            ))
            conn.commit()
            return redirect('/')
        except Exception as e:
            if conn: conn.rollback()
            return f"Asset insertion error: {e}", 500
        finally:
            if conn: conn.close()

    return render_template('add_asset.html', asset_types=asset_types, countries=countries, currencies=currencies, owners=owners)


@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT type_name FROM asset_types ORDER BY type_name;'); asset_types = [row['type_name'] for row in cur.fetchall()]
        cur.execute('SELECT country_name FROM countries ORDER BY country_name;'); countries = [row['country_name'] for row in cur.fetchall()]
        cur.execute('SELECT currency_code FROM currencies ORDER BY currency_code;'); currencies = [row['currency_code'] for row in cur.fetchall()]
        owners = get_owners() 
        
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
        cur.execute(f'SELECT * FROM assets WHERE id=%s {group_filter};', (asset_id,) + group_params)
        asset = cur.fetchone()
        if asset is None: return "Asset not found or access denied", 404
    except Exception as e: return f"Error fetching asset: {e}", 500
    finally:
        if conn and request.method == 'GET': cur.close(); conn.close()

    if request.method == 'POST':
        form_data = request.form; value = float(form_data.get('value', 0.00))
        try:
            cur = conn.cursor()
            group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
            update_query = f"""
                UPDATE assets SET owner_id=%s, type=%s, name=%s, country=%s, currency=%s, value=%s, account_no=%s, notes=%s, last_updated=CURRENT_DATE,
                financial_institution=%s, beneficiary_name=%s, policy_or_plan_type=%s, contact_phone=%s, document_location=%s, investment_strategy=%s
                WHERE id=%s {group_filter}
            """
            params = (
                form_data['owner_id'], form_data['type'], form_data['name'], form_data['country'], form_data['currency'], value, form_data['account_no'], form_data['notes'],
                form_data['financial_institution'], form_data['beneficiary_name'], form_data['policy_or_plan_type'], form_data['contact_phone'], form_data['document_location'], form_data['investment_strategy'],
                asset_id
            ) + group_params
            cur.execute(update_query, params)
            if cur.rowcount == 0: return "Update failed: Unauthorized.", 403
            conn.commit()
            return redirect('/')
        except Exception as e:
            if conn: conn.rollback()
            return f"Asset update error: {e}", 500
        finally:
            if conn: cur.close(); conn.close()

    return render_template('edit_asset.html', asset=asset, asset_types=asset_types, countries=countries, currencies=currencies, owners=owners)


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required 
def delete_asset(asset_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'assets')
        cur.execute(f'UPDATE assets SET activate = FALSE WHERE id = %s {group_filter};', (asset_id,) + group_params)
        if cur.rowcount == 0: return "Delete failed: Unauthorized.", 403
        conn.commit()
        return redirect('/')
    except Exception as e:
        if conn: conn.rollback()
        return f"Deletion error: {e}", 500
    finally:
        if conn: conn.close()


# --- EXPENSES ROUTES ---

@app.route('/expenses')
@login_required
def expenses():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'e')
    sort_by, order = request.args.get('sort_by', 'expense_date'), request.args.get('order', 'desc')
    sort_column = {'id': 'e.id', 'description': 'e.description', 'category': 'e.category', 'amount': 'e.amount', 'owner_name': 'o.name'}.get(sort_by, 'e.expense_date')
    order = 'ASC' if order.lower() == 'asc' else 'DESC'

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        query = f'SELECT e.*, o.name AS owner_name FROM expenses e JOIN owners o ON e.owner_id = o.id WHERE e.activate = TRUE {group_filter} ORDER BY {sort_column} {order};'
        cur.execute(query, group_params)
        return render_template('expenses.html', expenses=cur.fetchall(), sort_by=sort_by, order=order.lower())
    except Exception as e:
        return f"Error fetching expenses: {e}", 500
    finally:
        if conn: conn.close()


@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
    
    categories = ['Travel', 'Office Supplies', 'Utilities', 'Salary', 'Miscellaneous']
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'JPY']
    owners = get_owners()

    if request.method == 'POST':
        form_data = request.form; amount = float(form_data.get('amount', 0.00))
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO expenses (owner_id, description, category, amount, currency, expense_date, notes, activate, group_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE, %s)
            """, (form_data['owner_id'], form_data['description'], form_data['category'], amount, form_data['currency'], form_data['expense_date'], form_data['notes'], g.group_id))
            conn.commit()
            return redirect('/expenses')
        except Exception as e:
            if conn: conn.rollback()
            return f"Expense insertion error: {e}", 500
        finally:
            if conn: conn.close()

    return render_template('add_expense.html', categories=categories, currencies=currencies, owners=owners)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required 
def edit_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    categories = ['Travel', 'Office Supplies', 'Utilities', 'Salary', 'Miscellaneous']
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'JPY']
    owners = get_owners() 
    conn = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        cur.execute(f'SELECT * FROM expenses WHERE id=%s {group_filter};', (expense_id,) + group_params)
        expense = cur.fetchone()
        if expense is None: return "Expense not found or access denied", 404
    except Exception as e: return f"Error fetching expense: {e}", 500
    finally:
        if conn and request.method == 'GET': cur.close(); conn.close()

    if request.method == 'POST':
        form_data = request.form; amount = float(form_data.get('amount', 0.00))
        try:
            cur = conn.cursor()
            group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
            update_query = f'UPDATE expenses SET owner_id=%s, description=%s, category=%s, amount=%s, currency=%s, expense_date=%s, notes=%s WHERE id=%s {group_filter}'
            params = (form_data['owner_id'], form_data['description'], form_data['category'], amount, form_data['currency'], form_data['expense_date'], form_data['notes'], expense_id) + group_params
            cur.execute(update_query, params)
            if cur.rowcount == 0: return "Update failed: Unauthorized.", 403
            conn.commit()
            return redirect('/expenses')
        except Exception as e:
            if conn: conn.rollback()
            return f"Expense update error: {e}", 500
        finally:
            if conn: cur.close(); conn.close()

    return render_template('edit_expense.html', expense=expense, categories=categories, currencies=currencies, owners=owners)


@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required 
def delete_expense(expense_id):
    access_denied_response = check_user_access()
    if access_denied_response: return access_denied_response
                
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, 'expenses')
        cur.execute(f'UPDATE expenses SET activate = FALSE WHERE id = %s {group_filter};', (expense_id,) + group_params)
        if cur.rowcount == 0: return "Delete failed: Unauthorized.", 403
        conn.commit()
        return redirect('/expenses')
    except Exception as e:
        if conn: conn.rollback()
        return f"Deletion error: {e}", 500
    finally:
        if conn: conn.close()


if __name__ == '__main__':
    app.run(debug=True)
