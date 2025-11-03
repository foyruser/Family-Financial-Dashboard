from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_bcrypt import Bcrypt
from collections import Counter
import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import functools # For the login_required decorator
import locale # For numeric sorting


# Set locale for proper number sorting (optional, but good practice)
locale.setlocale(locale.LC_ALL, 'C')


app = Flask(__name__)


# --- SECURITY CONFIGURATION ---
# CRITICAL: CHANGE THIS TO A LONG, RANDOM STRING FOR PRODUCTION
app.secret_key = 'Hellohowareyoudoingiamdoingfineokaythankyou' 
bcrypt = Bcrypt(app)
# ------------------------------


conn_params = {
    'dbname': 'postgres',
    'user': 'postgres',
    'password': 'Kavin@074',
    'host': 'localhost',
    'port': '7450'
}


# NOTE: This API key is used for the currency exchange rate service.
API_KEY = '131d158eefb0d3cdb3a4557a'


def get_exchange_rates():
    """Fetches the latest exchange rates from USD base."""
    url = f'https://v6.exchangerate-api.com/v6/{API_KEY}/latest/USD'
    response = requests.get(url)
    data = response.json()
    if data.get('result') == 'success':
        return data['conversion_rates']
    else:
        # Fallback rates if API call fails
        return {'USD': 1.0, 'INR': 83.0, 'EUR': 0.9, 'GBP': 0.8}


def get_db_connection():
    """Establishes and returns a connection to the PostgreSQL database."""
    return psycopg2.connect(**conn_params)


# --- AUTHENTICATION DECORATOR ---
def login_required(view):
    """Decorator that ensures a user is logged in before allowing access."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            # Redirect to the login page if not logged in
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


# --- AUTH ROUTES ---


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration and password hashing."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password securely
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')


        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id;', (username, password_hash))
            user_id = cur.fetchone()[0]
            conn.commit()
            cur.close()
            conn.close()


            # Automatically log in the user after successful registration
            session['user_id'] = user_id
            session['username'] = username
            return redirect(url_for('home'))


        except psycopg2.IntegrityError:
            # Handle case where username already exists
            return render_template('register.html', error='Username already taken. Please choose another.')
        except Exception as e:
            # Log and handle other errors
            print(f"Registration error: {e}")
            return render_template('register.html', error=f'An error occurred: {e}')


    return render_template('register.html', error=None)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and session creation."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']


        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT id, password_hash FROM users WHERE username = %s;', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()


        if user and bcrypt.check_password_hash(user['password_hash'], password):
            # Login successful
            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('home'))
        else:
            # Login failed
            return render_template('login.html', error='Invalid username or password.')


    return render_template('login.html', error=None)


@app.route('/logout')
def logout():
    """Clears the session and logs the user out."""
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


# --- HELPER FUNCTION: Get Owners ---
def get_owners():
    """Fetches all owner records (id and name) from the database."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT id, name FROM owners ORDER BY name;')
    owners = cur.fetchall()
    cur.close()
    conn.close()
    return owners
# ----------------------------------------

# --- ADDITION for asset type pie chart ---
def get_asset_type_distribution():
    """Fetches total asset value grouped by asset type (for pie chart)."""
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
    conn.close()
    return data
# ----------------------------------------


# --- PROTECTED APPLICATION ROUTES ---


@app.route('/home')
@login_required # PROTECTED
def home():
    """Dashboard view showing aggregated assets, expenses, and net worth."""
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


    # --- ADDITION: fetch asset type distribution for pie chart ---
    asset_type_data = get_asset_type_distribution()
    # -------------------------------------------------------------


    cur.close()
    conn.close()


    net_usd = round(total_asset_usd - total_expense_usd, 2)
    net_inr = round(total_asset_inr - total_expense_inr, 2)


    # --- ADDITION: include asset_type_data in template context ---
    return render_template('home.html',
        total_asset_usd=round(total_asset_usd, 2),
        total_asset_inr=round(total_asset_inr, 2),
        total_expense_usd=round(total_expense_usd, 2),
        total_expense_inr=round(total_expense_inr, 2),
        net_usd=net_usd,
        net_inr=net_inr,
        asset_type_data=asset_type_data
    )
    # -------------------------------------------------------------



# --- INDEX/ASSETS LISTING ROUTE ---
@app.route('/')
@login_required # PROTECTED
def index():
    """Lists all active assets with sorting and currency conversion."""
    sort_by = request.args.get('sort_by', 'value_usd')
    order = request.args.get('order', 'desc')


    # Allowed columns for database sorting (native columns)
    db_sort_columns = ['id', 'type', 'name', 'country', 'currency', 'value', 'last_updated']
    # Columns for Python/in-memory sorting (calculated values)
    python_sort_columns = ['owner_name', 'value_usd'] 


    # Check if sorting on a database column
    if sort_by in db_sort_columns:
        sort_column = f'a.{sort_by}'
        db_sort = True
    elif sort_by == 'owner_name':
        sort_column = 'o.name'
        db_sort = True
    else:
        # Default to DB sorting by ID if calculated field is requested first
        sort_column = 'a.id'
        db_sort = False # Will use Python sorting later if needed
    
    order_db = 'asc' if order.lower() == 'asc' else 'desc'
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # Always query for all active assets, sort by ID or requested DB column
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
    conn.close()


    rates = get_exchange_rates()


    total_usd = 0
    total_inr = 0


    # 1. Calculate Converted Values
    for asset in assets:
        cur_currency = asset['currency']
        try:
            # Ensure safe conversion to float from database value (which might be Decimal or String)
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
                asset['value_usd'] = 0.00 # Use 0.00 for calculation purposes
                asset['value_usd_display'] = "N/A" # Use a separate key for display
        
        # Calculate INR value
        if 'value_usd_display' not in asset:
             asset['value_usd_display'] = round(asset['value_usd'], 2)
             asset['value_inr'] = round(asset['value_usd'] * rates.get('INR', 83), 2)
             total_usd += asset['value_usd']
             total_inr += asset['value_inr']
        else:
             asset['value_inr'] = 0.00
             asset['value_inr_display'] = "N/A" # Separate key for INR display


    # 2. Python Sorting for Calculated Fields (value_usd)
    if sort_by in python_sort_columns:
        reverse_sort = order_db == 'desc'
        
        # For calculated values, sort by the numeric field
        assets.sort(key=lambda a: a.get(sort_by, 0.00), reverse=reverse_sort)


    total_usd = round(total_usd, 2)
    total_inr = round(total_inr, 2)
    
    return render_template('index.html', assets=assets, total_usd=total_usd, total_inr=total_inr, sort_by=sort_by, order=order_db)


# --- ADD ASSET ROUTE (CRITICAL FIX APPLIED) ---
@app.route('/add_asset', methods=['GET', 'POST'])
@login_required # PROTECTED
def add_asset():
    """Displays form and handles submission for adding a new asset."""
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
    conn.close()


    if request.method == 'POST':
        # Existing Fields
        owner_id = request.form['owner_id']
        type = request.form['type']
        name = request.form['name']
        country = request.form['country']
        currency = request.form['currency']
        
        # FIX: Ensure 'value' is a float before inserting into the database
        value_str = request.form['value']
        try:
            value = float(value_str)
        except (ValueError, TypeError):
            # If conversion fails (e.g., empty string, bad text), set to 0.00
            value = 0.00 
            
        account_no = request.form['account_no']
        notes = request.form['notes']
        
        # New Fields
        financial_institution = request.form['financial_institution']
        beneficiary_name = request.form['beneficiary_name']
        policy_or_plan_type = request.form['policy_or_plan_type']
        contact_phone = request.form['contact_phone']
        document_location = request.form['document_location']
        investment_strategy = request.form['investment_strategy']



        conn = get_db_connection()
        cur = conn.cursor()
        try:
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
        except Exception as e:
            conn.rollback()
            print(f"Database insertion error in add_asset: {e}")
            # You might want to flash an error message here, but for now, just print and redirect
        finally:
            cur.close()
            conn.close()
        return redirect('/')


    return render_template('add_asset.html', asset_types=asset_types, countries=countries, currencies=currencies, owners=owners)


# --- EDIT ASSET ROUTE (Updated for 6 new fields) ---
@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required # PROTECTED
def edit_asset(asset_id):
    """Displays form and handles submission for editing an existing asset."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)


    cur.execute('SELECT type_name FROM asset_types ORDER BY type_name;')
    asset_types = [row['type_name'] for row in cur.fetchall()]


    cur.execute('SELECT country_name FROM countries ORDER BY country_name;')
    countries = [row['country_name'] for row in cur.fetchall()]


    cur.execute('SELECT currency_code FROM currencies ORDER BY currency_code;')
    currencies = [row['currency_code'] for row in cur.fetchall()]


    owners = get_owners() 


    if request.method == 'POST':
        # Existing Fields
        owner_id = request.form['owner_id']
        type = request.form['type']
        name = request.form['name']
        country = request.form['country']
        currency = request.form['currency']
        
        # FIX: Ensure 'value' is a float before inserting into the database
        value_str = request.form['value']
        try:
            value = float(value_str)
        except (ValueError, TypeError):
            value = 0.00 
            
        account_no = request.form['account_no']
        notes = request.form['notes']


        # New Fields
        financial_institution = request.form['financial_institution']
        beneficiary_name = request.form['beneficiary_name']
        policy_or_plan_type = request.form['policy_or_plan_type']
        contact_phone = request.form['contact_phone']
        document_location = request.form['document_location']
        investment_strategy = request.form['investment_strategy']


        try:
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
        except Exception as e:
            conn.rollback()
            print(f"Database update error in edit_asset: {e}")
        finally:
            cur.close()
            conn.close()
            
        return redirect('/')


    # GET request - fetch existing asset data
    cur.execute('SELECT * FROM assets WHERE id=%s;', (asset_id,))
    asset = cur.fetchone()
    cur.close()
    conn.close()


    if asset is None:
        return "Asset not found", 404


    return render_template('edit_asset.html', asset=asset, asset_types=asset_types, countries=countries, currencies=currencies, owners=owners)


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required # PROTECTED
def delete_asset(asset_id):
    """Marks an asset as inactive (soft delete)."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE assets SET activate = FALSE WHERE id = %s;', (asset_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect('/')


# --- EXPENSES ROUTES (All Updated) ---
@app.route('/expenses')
@login_required # PROTECTED
def expenses():
    """Lists all active expenses with sorting."""
    sort_by = request.args.get('sort_by', 'expense_date')
    order = request.args.get('order', 'desc')


    allowed_sort_columns = ['id', 'description', 'category', 'amount', 'currency', 'expense_date', 'owner_name']
    if sort_by not in allowed_sort_columns:
        sort_by = 'expense_date'
    order = 'asc' if order.lower() == 'asc' else 'desc'


    sort_column = 'o.name' if sort_by == 'owner_name' else f'e.{sort_by}'


    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    query = f'''
        SELECT e.*, o.name AS owner_name
        FROM expenses e
        JOIN owners o ON e.owner_id = o.id
        WHERE e.activate = TRUE 
        ORDER BY {sort_column} {order};
    '''
    cur.execute(query)
    expenses = cur.fetchall()
    cur.close()
    conn.close()


    return render_template('expenses.html', expenses=expenses, sort_by=sort_by, order=order)


@app.route('/add_expense', methods=['GET', 'POST'])
@login_required # PROTECTED
def add_expense():
    """Displays form and handles submission for adding a new expense."""
    categories = ['Travel', 'Office Supplies', 'Utilities', 'Salary', 'Miscellaneous']
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'JPY']
    
    owners = get_owners()


    if request.method == 'POST':
        owner_id = request.form['owner_id']
        description = request.form['description']
        category = request.form['category']
        
        # Ensure 'amount' is a safe number
        amount_str = request.form['amount']
        try:
            amount = float(amount_str)
        except (ValueError, TypeError):
            amount = 0.00
            
        currency = request.form['currency']
        expense_date = request.form['expense_date']
        notes = request.form['notes']


        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO expenses (owner_id, description, category, amount, currency, expense_date, notes, activate)
            VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE)
        """, (owner_id, description, category, amount, currency, expense_date, notes))
        conn.commit()
        cur.close()
        conn.close()
        return redirect('/expenses')


    return render_template('add_expense.html', categories=categories, currencies=currencies, owners=owners)


@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required # PROTECTED
def edit_expense(expense_id):
    """Displays form and handles submission for editing an existing expense."""
    categories = ['Travel', 'Office Supplies', 'Utilities', 'Salary', 'Miscellaneous']
    currencies = ['USD', 'INR', 'EUR', 'GBP', 'JPY']
    
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)


    owners = get_owners() 


    if request.method == 'POST':
        owner_id = request.form['owner_id']
        description = request.form['description']
        category = request.form['category']
        
        # Ensure 'amount' is a safe number
        amount_str = request.form['amount']
        try:
            amount = float(amount_str)
        except (ValueError, TypeError):
            amount = 0.00
            
        currency = request.form['currency']
        expense_date = request.form['expense_date']
        notes = request.form['notes']


        cur.execute("""
            UPDATE expenses
            SET owner_id=%s, description=%s, category=%s, amount=%s, currency=%s, expense_date=%s, notes=%s
            WHERE id=%s
        """, (owner_id, description, category, amount, currency, expense_date, notes, expense_id))
        
        conn.commit()
        cur.close()
        conn.close()
        return redirect('/expenses')


    cur.execute('SELECT * FROM expenses WHERE id=%s;', (expense_id,))
    expense = cur.fetchone()
    cur.close()
    conn.close()


    if expense is None:
        return "Expense not found", 404


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
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('UPDATE expenses SET activate = FALSE WHERE id = %s;', (expense_id,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect('/expenses')



if __name__ == '__main__':
    app.run(debug=True)
