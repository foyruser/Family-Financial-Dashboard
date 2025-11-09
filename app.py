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
from email.message import EmailMessage
from urllib.parse import urljoin

# -------------------------------------------------
# App Setup & Config
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or os.environ.get('SECRET_KEY', 'a_long_random_fallback_key')

bcrypt = Bcrypt(app)
DATABASE_URL = os.environ.get('DATABASE_URL')

# Exchange rate api (optional)
EXCHANGE_RATE_API_KEY = os.environ.get('EXCHANGE_RATE_API_KEY', 'YOUR_API_KEY_HERE')

# Encryption key
FERNET_KEY = os.environ.get('FERNET_KEY', Fernet.generate_key().decode())

# SMTP config (Render env)
MAIL_SERVER = os.environ.get('MAIL_SERVER')
MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_USE_TLS = (os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true')
MAIL_SENDER = os.environ.get('MAIL_SENDER', MAIL_USERNAME or 'no-reply@example.com')

# -------------------------------------------------
# Encryptor
# -------------------------------------------------
class Encryptor:
    def __init__(self, key):
        if not key:
            print("WARNING: FERNET_KEY not set. Using fallback key. DO NOT use in production.", file=sys.stderr)
            key = Fernet.generate_key().decode()
        self.f = Fernet(key.encode())

    def encrypt(self, data):
        if data is None or data == '': 
            return None
        return self.f.encrypt(str(data).encode()).decode()

    def decrypt(self, data):
        if data is None or data == '':
            return ''
        try:
            return self.f.decrypt(data.encode()).decode()
        except Exception:
            # Avoid breaking the UI on corrupt legacy values
            print(f"Decryption failed for value (truncated): {str(data)[:20]}...", file=sys.stderr)
            return '[Decryption Error]'

encryptor = Encryptor(FERNET_KEY)

# -------------------------------------------------
# DB Helpers
# -------------------------------------------------
def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable is not set.")
    return psycopg2.connect(DATABASE_URL)

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please log in.', 'info')
            return redirect(url_for('login'))
        if g.user_role != 'Admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('home'))
        return view(**kwargs)
    return wrapped_view

def get_group_filter_clause(user_role, group_id, table_alias=''):
    if table_alias and not table_alias.endswith('.'):
        table_alias += '.'
    if user_role == 'Admin':
        return '', ()
    elif group_id is not None:
        return f'AND {table_alias}group_id = %s', (group_id,)
    else:
        return 'AND 1=0', ()

# -------------------------------------------------
# User Context
# -------------------------------------------------
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user_id = None
    g.user_role = None
    g.group_id = None
    g.username = None
    g.user_name = None  # keep for templates using g.user_name

    if user_id is not None:
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            # Use username (not user_name)
            cur.execute("SELECT username, email, user_role, group_id, activate FROM users WHERE id = %s;", (user_id,))
            user = cur.fetchone()
            if user:
                if not user['activate']:
                    # If not activated yet, force pending screen
                    session['username'] = user['username']
                    return
                g.user_id = user_id
                g.user_role = user['user_role']
                g.group_id = user['group_id']
                g.username = user['username']
                g.user_name = user['username']
            else:
                session.clear()
        except Exception as e:
            print(f"Database error in before_request: {e}", file=sys.stderr)
        finally:
            if conn: 
                try: cur.close()
                except: pass
                conn.close()

# -------------------------------------------------
# Currency Helpers
# -------------------------------------------------
def get_exchange_rate(from_currency, to_currency='USD'):
    if EXCHANGE_RATE_API_KEY and EXCHANGE_RATE_API_KEY != 'YOUR_API_KEY_HERE':
        try:
            url = f"https://v6.exchangerate-api.com/v6/{EXCHANGE_RATE_API_KEY}/latest/{from_currency}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            if data.get('result') == 'success':
                return data['conversion_rates'].get(to_currency, 1.0)
        except Exception as e:
            print(f"Exchange Rate API failed: {e}", file=sys.stderr)
    return 1.0

def convert_to_usd(amount, currency):
    if currency == 'USD':
        return float(amount)
    rate_to_usd = get_exchange_rate(currency, 'USD')
    return float(amount) / rate_to_usd if rate_to_usd else 0.0

# -------------------------------------------------
# Common Lists for Forms
# -------------------------------------------------
def get_common_lists():
    return {
        'currencies': ['USD', 'EUR', 'INR', 'GBP', 'JPY', 'CAD'],
        'expense_categories': ['Travel', 'Food', 'Utilities', 'Software', 'Salary', 'Misc'],
        'asset_types': ['Bank Account', 'Brokerage', 'Mutual Fund', 'Stock', 'Bond', 'Insurance', 'Real Estate', 'Crypto', 'Other'],
        'countries': ['USA', 'India', 'UK', 'Canada', 'Germany', 'Japan', 'Australia'],
        # For owner dropdowns; you can later fetch these from DB if you maintain an owners table
        'owners': [{'id': 1, 'name': 'Primary'}, {'id': 2, 'name': 'Spouse'}, {'id': 3, 'name': 'Child'}],
    }

# -------------------------------------------------
# Home / Dashboard
# -------------------------------------------------
@app.route('/')
@login_required
def home():
    # Build summary (USD totals with INR display)
    summary = {
        'total_assets_usd': 0.0,
        'total_expenses_usd': 0.0,
        'total_assets_inr': 'N/A',
        'total_expenses_inr': 'N/A',
        'net_balance_usd': 0.0,
        'net_balance_inr': 'N/A',
    }

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        usd_to_inr_rate = get_exchange_rate('USD', 'INR')
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)

        # assets: use your assets table with 'current_value' if present; fallback to 'value'
        cur.execute(f"""
            SELECT COALESCE(current_value, value) AS amount, currency 
            FROM assets WHERE activate = TRUE {group_filter};
        """, group_params)
        assets = cur.fetchall()

        cur.execute(f"""
            SELECT amount, currency 
            FROM expenses WHERE activate = TRUE {group_filter};
        """, group_params)
        expenses = cur.fetchall()

        total_assets_usd = sum(convert_to_usd(a['amount'], a['currency']) for a in assets)
        total_expenses_usd = sum(convert_to_usd(e['amount'], e['currency']) for e in expenses)
        summary['total_assets_usd'] = total_assets_usd
        summary['total_expenses_usd'] = total_expenses_usd
        summary['net_balance_usd'] = total_assets_usd - total_expenses_usd

        if usd_to_inr_rate and usd_to_inr_rate > 0:
            summary['total_assets_inr'] = total_assets_usd * usd_to_inr_rate
            summary['total_expenses_inr'] = total_expenses_usd * usd_to_inr_rate
            summary['net_balance_inr'] = summary['net_balance_usd'] * usd_to_inr_rate

    except Exception as e:
        flash(f"Error loading dashboard: {e}", 'error')
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

    # You provided both dashboard.html and home.html; keep home.html for now
    return render_template('home.html', summary=summary, user_role=g.user_role, group_id=g.group_id)

# Optional alternate dashboard page if you want to use dashboard.html
@app.route('/dashboard')
@login_required
def dashboard():
    # Example simple summary_data for your dashboard.html
    conn = None
    summary_data = {
        'total_expenses': 0,
        'monthly_total': 0.0,
        'base_currency': 'USD',
        'recent_expenses': []
    }
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        # total count
        cur.execute(f"SELECT COUNT(*) AS c FROM expenses WHERE activate=TRUE {group_filter};", group_params)
        summary_data['total_expenses'] = cur.fetchone()['c']
        # month total
        cur.execute(f"""
            SELECT COALESCE(SUM(amount),0) AS s
            FROM expenses
            WHERE activate=TRUE
              AND date_incurred >= date_trunc('month', NOW()) {group_filter};
        """, group_params)
        summary_data['monthly_total'] = float(cur.fetchone()['s'] or 0)
        # recent items (decrypt description)
        cur.execute(f"""
            SELECT id, description, amount, currency, date_incurred
            FROM expenses
            WHERE activate=TRUE
            ORDER BY date_incurred DESC
            LIMIT 5;
        """)
        recent = cur.fetchall()
        arr = []
        for r in recent:
            arr.append({
                'id': r['id'],
                'description': encryptor.decrypt(r['description']),
                'amount': float(r['amount']),
                'currency': r['currency'],
                'expense_date_fmt': r['date_incurred'].strftime('%Y-%m-%d')
            })
        summary_data['recent_expenses'] = arr
    except Exception as e:
        print(f"dashboard error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template('dashboard.html', summary_data=summary_data)

# -------------------------------------------------
# Auth
# -------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Your login.html uses username (not email)
        username = request.form['username']
        password = request.form['password']
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, password_hash, activate FROM users WHERE username = %s;", (username,))
            user = cur.fetchone()
            if user and bcrypt.check_password_hash(user['password_hash'], password):
                if not user['activate']:
                    session['user_id'] = user['id']
                    session['username'] = username
                    return redirect(url_for('pending_approval'))
                session['user_id'] = user['id']
                flash('Login successful.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password.', 'error')
        except Exception as e:
            flash('An error occurred during login.', 'error')
            print(f"Login error: {e}", file=sys.stderr)
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Your register.html has only username + password.
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # store username also as email if you like; or keep email NULL
        email = username  # since your UI implies username is unique email
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        role = 'Member'
        # New users start inactivate, require admin approval + group assignment
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (username, email, password_hash, user_role, group_id, activate)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id;
            """, (username, email, password_hash, role, None, False))
            user_id = cur.fetchone()[0]
            conn.commit()
            session['user_id'] = user_id
            session['username'] = username
            return redirect(url_for('pending_approval'))
        except psycopg2.IntegrityError:
            flash('That username already exists.', 'error')
        except Exception as e:
            flash('An unexpected error occurred during registration.', 'error')
            print(f"Registration error: {e}", file=sys.stderr)
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template('register.html')

@app.route('/pending_approval')
@login_required
def pending_approval():
    return render_template('pending_approval.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# -------------------------------------------------
# Forgot / Reset Password (SMTP email)
# -------------------------------------------------
def send_email(to_email, subject, html_body):
    if not MAIL_SERVER or not MAIL_USERNAME or not MAIL_PASSWORD:
        print("SMTP not configured; skipping send.", file=sys.stderr)
        return False
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = MAIL_SENDER
    msg['To'] = to_email
    msg.set_content("Please view this email in an HTML-capable client.")
    msg.add_alternative(html_body, subtype='html')
    try:
        if MAIL_USE_TLS:
            server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email send failed: {e}", file=sys.stderr)
        return False

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    # Your template posts "username" which is also the email identifier in DB
    if request.method == 'POST':
        username = request.form['username']
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, email FROM users WHERE username = %s;", (username,))
            user = cur.fetchone()
            if not user:
                flash("If the account exists, a reset link has been sent.", "success")
                return render_template('forgot_password.html')
            token = secrets.token_urlsafe(32)
            expiration = datetime.now() + timedelta(hours=1)
            cur2 = conn.cursor()
            cur2.execute("UPDATE users SET reset_token=%s, token_expiration=%s WHERE id=%s;", (token, expiration, user['id']))
            conn.commit()
            # Build absolute reset URL
            base = request.url_root  # e.g., https://your-app.onrender.com/
            reset_url = urljoin(base, url_for('reset_password', token=token))
            html = f"""
            <h3>Password Reset</h3>
            <p>Click the link below to reset your password (valid for 1 hour):</p>
            <p><a href="{reset_url}">{reset_url}</a></p>
            """
            # Send email to stored email (we set email=username on register)
            ok = send_email(user['email'] or username, "Password Reset", html)
            if ok:
                flash("Password reset link sent! Check your email.", "success")
            else:
                flash("Could not send email (SMTP not configured).", "error")
        except Exception as e:
            print(f"Forgot password error: {e}", file=sys.stderr)
            flash("Error generating reset link.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE reset_token=%s AND token_expiration > NOW();", (token,))
        user = cur.fetchone()
        if not user:
            flash("Invalid or expired token.", "error")
            return redirect(url_for('login'))
        if request.method == 'POST':
            password = request.form['password']
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            cur2 = conn.cursor()
            cur2.execute("UPDATE users SET password_hash=%s, reset_token=NULL, token_expiration=NULL WHERE id=%s;", (password_hash, user['id']))
            conn.commit()
            flash("Password reset successful.", "success")
            return redirect(url_for('login'))
    except Exception as e:
        print(f"Reset password error: {e}", file=sys.stderr)
        flash("Password reset failed.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template('reset_password.html')

# -------------------------------------------------
# Change Password (logged-in)
# -------------------------------------------------
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']
        if new != confirm:
            flash("New passwords do not match.", "error")
            return render_template('change_password.html')
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT password_hash FROM users WHERE id=%s;", (g.user_id,))
            row = cur.fetchone()
            if not row or not bcrypt.check_password_hash(row['password_hash'], current):
                flash("Current password is incorrect.", "error")
                return render_template('change_password.html')
            new_hash = bcrypt.generate_password_hash(new).decode('utf-8')
            cur2 = conn.cursor()
            cur2.execute("UPDATE users SET password_hash=%s WHERE id=%s;", (new_hash, g.user_id))
            conn.commit()
            flash("Password updated.", "success")
            return redirect(url_for('profile'))
        except Exception as e:
            print(f"change_password error: {e}", file=sys.stderr)
            flash("Password change failed.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template('change_password.html')

# -------------------------------------------------
# Profile
# -------------------------------------------------
@app.route('/profile')
@login_required
def profile():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT username, email, group_id FROM users WHERE id=%s;", (g.user_id,))
        user = cur.fetchone()
    except Exception as e:
        print(f"profile error: {e}", file=sys.stderr)
        user = {'username': g.username, 'email': None, 'group_id': g.group_id}
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template('profile.html', user=user)

# -------------------------------------------------
# Group management
# -------------------------------------------------
@app.route('/group')
@login_required
def group_management():
    is_default = g.group_id is None
    return render_template('group_management.html', username=g.username, group_id=g.group_id, is_default_group=is_default)

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    # Simple approach: generate a random group token and set on user
    new_gid = f"family-{secrets.token_urlsafe(4)}"
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET group_id=%s WHERE id=%s;", (new_gid, g.user_id))
        conn.commit()
        flash("New group created.", "success")
    except Exception as e:
        print(f"create_group error: {e}", file=sys.stderr)
        flash("Failed to create group.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for('group_management'))

@app.route('/join_group', methods=['POST'])
@login_required
def join_group():
    target_gid = request.form.get('target_group_id')
    if not target_gid:
        flash("Group ID required.", "error")
        return redirect(url_for('group_management'))
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET group_id=%s WHERE id=%s;", (target_gid, g.user_id))
        conn.commit()
        flash("Joined group.", "success")
    except Exception as e:
        print(f"join_group error: {e}", file=sys.stderr)
        flash("Failed to join group.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for('group_management'))

# -------------------------------------------------
# Admin: Approve Users
# -------------------------------------------------
@app.route('/admin/approve_users', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_approve_users():
    conn = None
    try:
        conn = get_db_connection()
        if request.method == 'POST':
            user_id = request.form.get('user_id')
            group_id = request.form.get('group_id')
            cur = conn.cursor()
            cur.execute("UPDATE users SET activate=TRUE, group_id=%s WHERE id=%s;", (group_id, user_id))
            conn.commit()
            flash("User approved and group assigned.", "success")
            return redirect(url_for('admin_approve_users'))

        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username FROM users WHERE activate=FALSE;")
        pending = cur.fetchall()
        return render_template('admin_approve_users.html', pending_users=pending)
    except Exception as e:
        print(f"admin_approve_users error: {e}", file=sys.stderr)
        flash("Admin action failed.", "error")
        return redirect(url_for('home'))
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

# -------------------------------------------------
# Expenses
# -------------------------------------------------
@app.route('/expenses')
@login_required
def expenses():
    conn = None
    expenses_list = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, table_alias='e')
        cur.execute(f"""
            SELECT e.id, e.description, e.amount, e.currency, e.category, e.date_incurred AS expense_date, e.activate
            FROM expenses e
            WHERE e.activate = TRUE {group_filter}
            ORDER BY e.date_incurred DESC;
        """, group_params)
        rows = cur.fetchall()
        for r in rows:
            r['description'] = encryptor.decrypt(r['description']) if r['description'] else ''
            r['amount'] = float(r['amount'])
            r['expense_date'] = r['expense_date'].strftime('%Y-%m-%d') if r['expense_date'] else ''
            expenses_list.append(r)
    except Exception as e:
        flash(f"Error loading expenses: {e}", 'error')
        print(f"Expenses list error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template('expenses.html', expenses=expenses_list)

@app.route('/add_expense', methods=['GET', 'POST'])
@login_required
def add_expense():
    lists = get_common_lists()
    if request.method == 'POST':
        description = request.form['description']
        amount = request.form['amount']
        currency = request.form['currency']
        category = request.form['category']
        # HTML field is expense_date; DB column is date_incurred
        expense_date = request.form['expense_date']

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            encrypted_description = encryptor.encrypt(description)
            cur.execute("""
                INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by, activate)
                VALUES (%s, %s, %s, %s, %s, %s, %s, TRUE);
            """, (g.group_id, encrypted_description, amount, currency, category, expense_date, g.user_id))
            conn.commit()
            flash('Expense successfully added.', 'success')
            return redirect(url_for('expenses'))
        except Exception as e:
            flash(f"Error adding expense: {e}", 'error')
            print(f"Expense creation error: {e}", file=sys.stderr)
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()
    return render_template('add_expense.html', categories=lists['expense_categories'], currencies=lists['currencies'])

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    lists = get_common_lists()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, table_alias='e')
        cur.execute(f"""
            SELECT e.id, e.description, e.amount, e.currency, e.category, e.date_incurred AS expense_date
            FROM expenses e
            WHERE e.id=%s AND e.activate=TRUE {group_filter};
        """, (expense_id,) + group_params)
        expense = cur.fetchone()
        if not expense:
            flash("Expense not found or unauthorized.", 'error')
            return redirect(url_for('expenses'))

        if request.method == 'POST':
            description = request.form['description']
            amount = request.form['amount']
            currency = request.form['currency']
            category = request.form['category']
            expense_date = request.form['expense_date']
            encrypted_description = encryptor.encrypt(description)

            cur2 = conn.cursor()
            cur2.execute(f"""
                UPDATE expenses
                SET description=%s, amount=%s, currency=%s, category=%s, date_incurred=%s
                WHERE id=%s AND activate=TRUE {group_filter};
            """, (encrypted_description, amount, currency, category, expense_date, expense_id) + group_params)
            if cur2.rowcount == 0:
                flash("Update failed: not found or unauthorized.", 'error')
            else:
                conn.commit()
                flash('Expense successfully updated.', 'success')
                return redirect(url_for('expenses'))

        # decrypt for display in form
        expense['description'] = encryptor.decrypt(expense['description'])
        expense['amount'] = float(expense['amount'])
        expense['expense_date'] = expense['expense_date'].strftime('%Y-%m-%d') if expense['expense_date'] else ''
        return render_template('edit_expense.html', expense=expense, categories=lists['expense_categories'], currencies=lists['currencies'])
    except Exception as e:
        flash(f"Error editing expense: {e}", 'error')
        print(f"Expense edit error: {e}", file=sys.stderr)
        return redirect(url_for('expenses'))
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        cur.execute(f"UPDATE expenses SET activate=FALSE WHERE id=%s {group_filter};", (expense_id,) + group_params)
        if cur.rowcount == 0:
            flash("Delete failed: not found or unauthorized.", 'error')
        else:
            conn.commit()
            flash("Expense removed.", 'success')
    except Exception as e:
        flash(f"Error deleting expense: {e}", 'error')
        print(f"Expense delete error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for('expenses'))

# -------------------------------------------------
# Assets (rich schema with encryption for sensitive fields)
# -------------------------------------------------
SENSITIVE_ASSET_FIELDS = ['account_no', 'beneficiary_name', 'contact_phone', 'document_location', 'description']

def enc(v): return encryptor.encrypt(v) if v not in (None, '') else None
def dec(v): return encryptor.decrypt(v) if v not in (None, '') else ''

@app.route('/assets')
@login_required
def assets():
    conn = None
    rows = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, table_alias='a')
        cur.execute(f"""
            SELECT a.id, a.user_id, a.type, a.name, a.country, a.currency, a.value, a.account_no,
                   a.last_updated, a.notes, a.activate, a.owner, a.owner_id, a.financial_institution,
                   a.beneficiary_name, a.policy_or_plan_type, a.contact_phone, a.document_location,
                   a.investment_strategy, a.current_value, a.description, a.added_date, a.group_id
            FROM assets a
            WHERE a.activate=TRUE {group_filter}
            ORDER BY a.last_updated DESC NULLS LAST, a.added_date DESC NULLS LAST, a.id DESC;
        """, group_params)
        rows = cur.fetchall()
        # decrypt sensitive fields
        for r in rows:
            r['account_no'] = dec(r['account_no'])
            r['beneficiary_name'] = dec(r['beneficiary_name'])
            r['contact_phone'] = dec(r['contact_phone'])
            r['document_location'] = dec(r['document_location'])
            r['description'] = dec(r['description'])
            # Normalize dates
            if r.get('last_updated'):
                r['last_updated'] = r['last_updated'].strftime('%Y-%m-%d')
            if r.get('added_date'):
                r['added_date'] = r['added_date'].strftime('%Y-%m-%d')
    except Exception as e:
        flash(f"Error loading assets: {e}", 'error')
        print(f"Assets load error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    # You can create a simple assets.html list, or reuse edit pages from a detail link.
    return render_template('assets.html', assets=rows) if os.path.exists('templates/assets.html') else "Assets list page (create templates/assets.html to render a table)."

@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    lists = get_common_lists()
    if request.method == 'POST':
        # Required core fields
        owner_id = request.form.get('owner_id')
        atype = request.form.get('type')
        name = request.form.get('name')
        account_no = request.form.get('account_no')
        value = request.form.get('value')
        currency = request.form.get('currency')
        country = request.form.get('country')

        # Policy & critical
        financial_institution = request.form.get('financial_institution')
        policy_or_plan_type = request.form.get('policy_or_plan_type')
        beneficiary_name = request.form.get('beneficiary_name')
        contact_phone = request.form.get('contact_phone')
        document_location = request.form.get('document_location')

        # Notes/strategy
        investment_strategy = request.form.get('investment_strategy')
        notes = request.form.get('notes')

        now = datetime.now()
        added_date = now.date()
        last_updated = now

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO assets
                    (user_id, type, name, country, currency, value, account_no, last_updated, notes, activate,
                     owner, owner_id, financial_institution, beneficiary_name, policy_or_plan_type, contact_phone,
                     document_location, investment_strategy, current_value, description, added_date, group_id)
                VALUES
                    (%s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE,
                     %s, %s, %s, %s, %s, %s,
                     %s, %s, %s, %s, %s, %s);
            """, (
                g.user_id, atype, name, country, currency, value, enc(account_no), last_updated, notes,
                None, owner_id, enc(financial_institution), enc(beneficiary_name), policy_or_plan_type, enc(contact_phone),
                enc(document_location), investment_strategy, value, enc(''), added_date, g.group_id
            ))
            conn.commit()
            flash("Asset saved.", "success")
            return redirect(url_for('assets'))
        except Exception as e:
            print(f"add_asset error: {e}", file=sys.stderr)
            flash("Failed to save asset.", "error")
        finally:
            if conn:
                try: cur.close()
                except: pass
                conn.close()

    return render_template('add_asset.html',
                           owners=lists['owners'],
                           asset_types=lists['asset_types'],
                           currencies=lists['currencies'],
                           countries=lists['countries'])

@app.route('/edit_asset/<int:asset_id>', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    lists = get_common_lists()
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id, table_alias='a')
        cur.execute(f"""
            SELECT a.*
            FROM assets a
            WHERE a.id=%s AND a.activate=TRUE {group_filter};
        """, (asset_id,) + group_params)
        asset = cur.fetchone()
        if not asset:
            flash("Asset not found or unauthorized.", "error")
            return redirect(url_for('assets'))

        if request.method == 'POST':
            owner_id = request.form.get('owner_id')
            atype = request.form.get('type')
            name = request.form.get('name')
            account_no = request.form.get('account_no')
            value = request.form.get('value')
            currency = request.form.get('currency')
            country = request.form.get('country')
            financial_institution = request.form.get('financial_institution')
            policy_or_plan_type = request.form.get('policy_or_plan_type')
            beneficiary_name = request.form.get('beneficiary_name')
            contact_phone = request.form.get('contact_phone')
            document_location = request.form.get('document_location')
            investment_strategy = request.form.get('investment_strategy')
            notes = request.form.get('notes')
            last_updated = datetime.now()

            cur2 = conn.cursor()
            cur2.execute(f"""
                UPDATE assets
                SET owner_id=%s, type=%s, name=%s, account_no=%s, value=%s, currency=%s, country=%s,
                    financial_institution=%s, policy_or_plan_type=%s, beneficiary_name=%s, contact_phone=%s,
                    document_location=%s, investment_strategy=%s, notes=%s, last_updated=%s
                WHERE id=%s AND activate=TRUE {group_filter};
            """, (
                owner_id, atype, name, enc(account_no), value, currency, country,
                enc(financial_institution), policy_or_plan_type, enc(beneficiary_name), enc(contact_phone),
                enc(document_location), investment_strategy, notes, last_updated,
                asset_id
            ) + group_params)
            if cur2.rowcount == 0:
                flash("Update failed: not found or unauthorized.", "error")
            else:
                conn.commit()
                flash("Asset updated.", "success")
                return redirect(url_for('assets'))

        # decrypt for form display
        for f in SENSITIVE_ASSET_FIELDS:
            asset[f] = dec(asset.get(f))
        return render_template('edit_asset.html',
                               asset=asset,
                               owners=lists['owners'],
                               asset_types=lists['asset_types'],
                               currencies=lists['currencies'],
                               countries=lists['countries'])
    except Exception as e:
        print(f"edit_asset error: {e}", file=sys.stderr)
        flash("Failed to load asset.", "error")
        return redirect(url_for('assets'))
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        group_filter, group_params = get_group_filter_clause(g.user_role, g.group_id)
        cur.execute(f"UPDATE assets SET activate=FALSE WHERE id=%s {group_filter};", (asset_id,) + group_params)
        if cur.rowcount == 0:
            flash("Delete failed: not found or unauthorized.", "error")
        else:
            conn.commit()
            flash("Asset removed.", "success")
    except Exception as e:
        print(f"delete_asset error: {e}", file=sys.stderr)
        flash("Failed to delete asset.", "error")
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return redirect(url_for('assets'))

# -------------------------------------------------
# Misc placeholder routes so nav links don't 404
# -------------------------------------------------
@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html') if os.path.exists('templates/reports.html') else "Reports coming soon."

@app.route('/currencies')
@login_required
def currencies():
    return render_template('currencies.html') if os.path.exists('templates/currencies.html') else "Currencies view coming soon."

@app.route('/users')
@login_required
@admin_required
def users():
    # Simple admin users list
    conn = None
    out = []
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, username, email, user_role, group_id, activate FROM users ORDER BY id;")
        out = cur.fetchall()
    except Exception as e:
        print(f"users list error: {e}", file=sys.stderr)
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()
    return render_template('users.html', users=out) if os.path.exists('templates/users.html') else "Users list (create templates/users.html)."

# -------------------------------------------------
# Optional: init_db (use only for dev)
# -------------------------------------------------
@app.route('/init_db')
def init_db():
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
        -- Drop tables for dev only
        DROP TABLE IF EXISTS expenses;
        DROP TABLE IF EXISTS assets;
        DROP TABLE IF EXISTS users;

        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(100),
            password_hash VARCHAR(128) NOT NULL,
            user_role VARCHAR(50) NOT NULL DEFAULT 'Member',
            group_id VARCHAR(100),
            reset_token TEXT,
            token_expiration TIMESTAMP,
            activate BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE expenses (
            id SERIAL PRIMARY KEY,
            group_id VARCHAR(100),
            description TEXT NOT NULL,
            amount NUMERIC(15, 2) NOT NULL,
            currency VARCHAR(10) NOT NULL,
            category VARCHAR(50) NOT NULL,
            date_incurred DATE NOT NULL,
            created_by INTEGER REFERENCES users(id),
            activate BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()
        );

        CREATE TABLE assets (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            type VARCHAR(100),
            name VARCHAR(255),
            country VARCHAR(100),
            currency VARCHAR(10),
            value NUMERIC(15,2),
            account_no TEXT,
            last_updated TIMESTAMP,
            notes TEXT,
            activate BOOLEAN NOT NULL DEFAULT TRUE,
            owner VARCHAR(100),
            owner_id INTEGER,
            financial_institution TEXT,
            beneficiary_name TEXT,
            policy_or_plan_type VARCHAR(100),
            contact_phone TEXT,
            document_location TEXT,
            investment_strategy TEXT,
            current_value NUMERIC(15,2),
            description TEXT,
            added_date DATE,
            group_id VARCHAR(100)
        );
        """)

        # Sample admin
        sample_hash = bcrypt.generate_password_hash('password').decode('utf-8')
        cur.execute("""
            INSERT INTO users (username, email, password_hash, user_role, group_id, activate)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING id;
        """, ('admin', 'admin@example.com', sample_hash, 'Admin', 'family-demo', True))
        admin_id = cur.fetchone()[0]

        # Sample data
        cur.execute("""
            INSERT INTO expenses (group_id, description, amount, currency, category, date_incurred, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """, ('family-demo', encryptor.encrypt('Office Rental Payment'), 1200.00, 'USD', 'Utilities', datetime.now().date(), admin_id))

        cur.execute("""
            INSERT INTO assets (user_id, type, name, country, currency, value, account_no, last_updated, notes, owner, owner_id,
                                financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location,
                                investment_strategy, current_value, description, added_date, group_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s);
        """, (admin_id, 'Bank Account', 'Checking - Demo', 'USA', 'USD', 5000.00, encryptor.encrypt('****1234'),
              'Sample notes', 'Admin User', 1, encryptor.encrypt('Demo Bank'), encryptor.encrypt('Spouse'),
              'Checking', encryptor.encrypt('+1-800-111-2222'), encryptor.encrypt('Locker A1'),
              'Keep $3k buffer', 5000.00, encryptor.encrypt('Main household account'),
              datetime.now().date(), 'family-demo'))

        conn.commit()
        return "Initialized. Admin login: admin / password"
    except Exception as e:
        print(f"init_db error: {e}", file=sys.stderr)
        return f"init_db failed: {e}", 500
    finally:
        if conn:
            try: cur.close()
            except: pass
            conn.close()

# -------------------------------------------------
# App start (Render will use gunicorn app:app)
# -------------------------------------------------
if __name__ == '__main__':
    app.run(debug=True)
