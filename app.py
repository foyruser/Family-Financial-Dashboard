from flask import Flask, render_template, request, redirect, url_for, session, g, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

import os
import sys
import functools
import secrets
import smtplib
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from email.message import EmailMessage
from datetime import datetime, timedelta
from urllib.parse import urljoin
from decimal import Decimal

from cryptography.fernet import Fernet

# -------------------------------------------------
# App & Config
# -------------------------------------------------
app = Flask(__name__)

# Secret keys (provide via Render env)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY", "a_long_random_fallback_key")

# Secure cookies in prod
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
)

# Respect proxy headers for real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="moving-window"
)

# Email configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'no-reply@localhost')

# Encryption setup
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    # CRITICAL: Fail if the FERNET_KEY is not provided via environment variable.
    # This prevents the hardcoded key exposure that GitGuardian flagged.
    print("FATAL ERROR: FERNET_KEY environment variable is NOT set. Cannot run application securely.", file=sys.stderr)
    sys.exit(1) # Stop application if essential security key is missing.
    
f = Fernet(FERNET_KEY.encode())

def enc(data):
    """Encrypts data."""
    if data is None:
        return None
    # Ensure data is string, then encode, then encrypt
    return f.encrypt(str(data).encode()).decode()

def dec(data):
    """Decrypts data."""
    if data is None:
        return None
    try:
        # Decode, decrypt, then decode back to string
        return f.decrypt(data.encode()).decode()
    except Exception as e:
        # Log decryption error but return a safe string
        print(f"Decryption failed for data: {data[:10]}... Error: {e}", file=sys.stderr)
        return "Decryption Error" 


# -------------------------------------------------
# Database Connection
# -------------------------------------------------
def get_db_connection():
    """Establishes and returns a database connection."""
    if 'db_conn' not in g:
        try:
            database_url = os.environ.get('DATABASE_URL')
            if not database_url:
                # This will stop the app if DATABASE_URL is essential
                raise ValueError("DATABASE_URL environment variable is not set.")
                
            g.db_conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
        except Exception as e:
            print(f"Database connection error: {e}", file=sys.stderr)
            # Log the error and re-raise
            raise
    return g.db_conn

@app.teardown_appcontext
def close_db_connection(exception):
    """Closes the database connection at the end of the request."""
    conn = g.pop('db_conn', None)
    if conn is not None:
        conn.close()

# -------------------------------------------------
# Utility Functions
# -------------------------------------------------

def send_email(to, subject, body):
    """Sends an email using configured SMTP settings."""
    if not all([app.config['MAIL_SERVER'], app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']]):
        print("Email not sent: SMTP configuration missing.", file=sys.stderr)
        return False
        
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = to

    try:
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as s:
            if app.config['MAIL_USE_TLS']:
                s.starttls()
            s.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email to {to}: {e}", file=sys.stderr)
        return False

def fetch_assets(user_id):
    """Fetches all assets for a given user and decrypts sensitive fields."""
    conn = None
    assets = []
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM assets WHERE user_id = %s ORDER BY name;", (user_id,))
        assets = cur.fetchall()
        cur.close()

        # Decrypt sensitive fields for display
        for asset in assets:
            # Check for existence and handle None/Decryption failure safely
            asset['account_no_decrypted'] = dec(asset.get('account_no'))
            asset['owner_id_decrypted'] = dec(asset.get('owner_id'))
            asset['beneficiary_name_decrypted'] = dec(asset.get('beneficiary_name'))
            asset['contact_phone_decrypted'] = dec(asset.get('contact_phone'))
            asset['document_location_decrypted'] = dec(asset.get('document_location'))
            # description is an encrypted field in the schema
            asset['description_decrypted'] = dec(asset.get('description')) 
                
    except Exception as e:
        print(f"Error fetching assets: {e}", file=sys.stderr)
        flash("Could not load assets due to a database error.", "error")
        
    return assets

def calculate_net_worth(assets):
    """Calculates the total current value of assets."""
    net_worth = Decimal(0)
    try:
        for asset in assets:
            # Safely get current_value or fallback to value, then try to convert to Decimal
            value_str = asset.get('current_value') or asset.get('value', 0)
            if value_str is not None:
                try:
                    net_worth += Decimal(str(value_str))
                except Exception:
                    print(f"Warning: Non-numeric value found in asset: {value_str}", file=sys.stderr)
                    pass
    except Exception as e:
        print(f"Error calculating net worth: {e}", file=sys.stderr)
        return Decimal(0)
    return net_worth

def fetch_asset_groups(user_id):
    """Fetches all asset groups for a given user."""
    conn = None
    groups = []
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, name FROM asset_groups WHERE user_id = %s ORDER BY name;", (user_id,))
        groups = cur.fetchall()
        cur.close()
    except Exception as e:
        print(f"Error fetching asset groups: {e}", file=sys.stderr)
    return groups

# -------------------------------------------------
# Utility and Decorators
# -------------------------------------------------
def login_required(view):
    """Decorator to require user login."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if session.get('user_id') is None:
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.before_request
def load_logged_in_user():
    """Loads user info into the global 'g' object if logged in."""
    user_id = session.get('user_id')
    g.user = None
    if user_id is not None:
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            # Fetch user info by ID
            cur.execute("SELECT id, username, email FROM users WHERE id = %s;", (user_id,))
            g.user = cur.fetchone()
            cur.close()
        except Exception as e:
            # Handle case where DB connection might fail mid-request
            print(f"Error loading user: {e}", file=sys.stderr)

# -------------------------------------------------
# Auth Routes
# -------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if g.user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password or len(password) < 8:
            flash("All fields are required, and password must be at least 8 characters.", "error")
            return render_template('register.html', username=username, email=email)

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s;", (username, email))
            if cur.fetchone():
                flash("Username or email already exists.", "error")
                return render_template('register.html', username=username, email=email)

            cur.execute("""
                INSERT INTO users (username, email, password_hash, created_at, role, status) 
                VALUES (%s, %s, %s, NOW(), 'user', 'active') RETURNING id;
            """, (username, email, password_hash))
            
            new_user_id = cur.fetchone()['id']
            conn.commit()
            cur.close()

            session.clear()
            session['user_id'] = new_user_id
            flash("Registration successful! You are now logged in.", "success")
            return redirect(url_for('index'))
            
        except psycopg2.IntegrityError:
             flash("Username or email already exists. Please choose another.", "error")
             if conn: conn.rollback()
        except Exception as e:
            print(f"Registration error: {e}", file=sys.stderr)
            flash("An unexpected error occurred during registration. Please try again.", "error")
            if conn: conn.rollback()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    """Handles user login."""
    if g.user:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute("SELECT id, password_hash, status FROM users WHERE username = %s;", (username,))
            user = cur.fetchone()
            cur.close()

            if not user:
                 flash("Invalid username or password.", "error")
            elif user['status'] != 'active':
                 flash("Your account is not active. Please contact support.", "error")
            elif bcrypt.check_password_hash(user['password_hash'], password):
                session.clear()
                session['user_id'] = user['id']
                flash(f"Welcome back, {username}!", "success")
                return redirect(url_for('index'))
            else:
                flash("Invalid username or password.", "error")
        except Exception as e:
            print(f"Login error: {e}", file=sys.stderr)
            flash("An error occurred during login. Please try again.", "error")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """Handles request to reset password. Requires email configuration."""
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form['email']
        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            cur.execute("SELECT id, username FROM users WHERE email = %s;", (email,))
            user = cur.fetchone()
            
            if user:
                # 1. Generate unique token and set expiration time
                token = secrets.token_urlsafe(32)
                expires_at = datetime.now() + timedelta(hours=1)
                
                # 2. Store token in database (assumes a password_reset_tokens table exists)
                cur.execute("""
                    INSERT INTO password_reset_tokens (user_id, token, expires_at)
                    VALUES (%s, %s, %s);
                """, (user['id'], token, expires_at))
                conn.commit()
                
                # 3. Construct the reset URL
                reset_url = urljoin(request.url_root, url_for('reset_password', token=token))
                subject = "Password Reset Request"
                body = f"""
                Hello {user['username']},

                You requested a password reset. Click the link below to reset your password:
                {reset_url}

                This link will expire in 1 hour. If you did not request this, please ignore this email.

                Sincerely,
                The Financial App Team
                """
                # 4. Send the email
                send_email(email, subject, body)
            
            # Prevent user enumeration by sending generic success message regardless of existence
            flash("If an account with that email exists, a password reset link has been sent.", "info")
            
        except Exception as e:
            print(f"Forgot password error: {e}", file=sys.stderr)
            flash("An error occurred while processing your request.", "error")
            if conn: conn.rollback()
        
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Handles the password reset process via token."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Validate token and expiration
        cur.execute("""
            SELECT user_id FROM password_reset_tokens 
            WHERE token = %s AND expires_at > NOW();
        """, (token,))
        
        token_data = cur.fetchone()
        
        if not token_data:
            flash("Invalid or expired password reset token.", "error")
            return redirect(url_for('forgot_password'))
            
        user_id = token_data['user_id']
        
        if request.method == 'POST':
            password = request.form['password']
            
            if not password or len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return render_template('reset_password.html', token=token)
                
            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # 2. Update password
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s;", (password_hash, user_id))
            
            # 3. Invalidate/delete the token
            cur.execute("DELETE FROM password_reset_tokens WHERE token = %s;", (token,))
            
            conn.commit()
            flash("Your password has been reset successfully. You can now log in.", "success")
            return redirect(url_for('login'))

    except Exception as e:
        print(f"Reset password error: {e}", file=sys.stderr)
        flash("An error occurred during password reset.", "error")
        if conn: conn.rollback()
        return redirect(url_for('forgot_password'))

    return render_template('reset_password.html', token=token)


# -------------------------------------------------
# Asset Management Routes
# -------------------------------------------------

@app.route('/')
@login_required
def index():
    """Renders the main dashboard with assets and net worth."""
    user_id = g.user['id']
    assets = fetch_assets(user_id)
    net_worth = calculate_net_worth(assets)
    groups = fetch_asset_groups(user_id)
    
    # Pass assets and calculated data to the template
    return render_template('index.html', 
                           username=g.user['username'],
                           assets=assets,
                           net_worth=net_worth,
                           groups=groups)

@app.route('/assets/add', methods=['POST'])
@login_required
def add_asset():
    """Adds a new asset for the logged-in user."""
    conn = None
    try:
        data = request.form
        user_id = g.user['id']
        
        # Mandatory fields validation (matching the comprehensive schema)
        required_fields = ['type', 'name', 'country', 'currency', 'value', 'account_no', 
                           'owner', 'owner_id', 'financial_institution', 'beneficiary_name', 
                           'policy_or_plan_type', 'contact_phone', 'document_location', 
                           'investment_strategy', 'description', 'group_id']
        
        if not all(field in data for field in required_fields):
            missing_fields = [field for field in required_fields if field not in data]
            raise KeyError(f"Missing form fields: {', '.join(missing_fields)}")

        # Data preparation
        asset_type = data['type']
        name = data['name']
        country = data['country']
        currency = data['currency']
        notes = data.get('notes', '')
        owner = data['owner']
        financial_institution = data['financial_institution']
        policy_or_plan_type = data['policy_or_plan_type']
        investment_strategy = data['investment_strategy']
        
        # Convert numeric fields
        value = Decimal(data['value'])
        current_value = Decimal(data.get('current_value', data['value'])) 
        
        # Encrypted fields
        account_no = enc(data['account_no']) 
        owner_id = enc(data['owner_id'])
        beneficiary_name = enc(data['beneficiary_name'])
        contact_phone = enc(data['contact_phone'])
        document_location = enc(data['document_location'])
        description = enc(data['description'])
        group_id = data['group_id']

        # Database Insertion
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO assets (user_id, type, name, country, currency, value, account_no, last_updated, notes, owner, owner_id,
                                financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location,
                                investment_strategy, current_value, description, added_date, group_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, NOW(), %s) RETURNING id;
        """, (user_id, asset_type, name, country, currency, value, account_no, 
              notes, owner, owner_id, financial_institution, beneficiary_name, 
              policy_or_plan_type, contact_phone, document_location, 
              investment_strategy, current_value, description, group_id))
        
        conn.commit()
        flash("Asset added successfully!", "success")
        return redirect(url_for('index'))

    except KeyError as e:
        flash(f"Missing required form field(s). Please ensure your form is complete: {e}", "error")
    except ValueError:
        flash("Value and Current Value must be valid numbers.", "error")
    except psycopg2.IntegrityError as e:
        print(f"PostgreSQL Integrity Error adding asset: {e}", file=sys.stderr)
        flash("Failed to add asset due to a database constraint error (e.g., missing required field).", "error")
        if conn: conn.rollback()
    except Exception as e:
        print(f"General Error adding asset: {e}", file=sys.stderr)
        flash("An unexpected error occurred while adding the asset.", "error")
        if conn: conn.rollback()
        
    return redirect(url_for('index'))

@app.route('/assets/<int:asset_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_asset(asset_id):
    """Allows editing of an existing asset."""
    user_id = g.user['id']
    conn = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Fetch the asset to edit, ensuring it belongs to the user
        cur.execute("SELECT * FROM assets WHERE id = %s AND user_id = %s;", (asset_id, user_id))
        asset = cur.fetchone()

        if not asset:
            flash("Asset not found or you do not have permission to edit it.", "error")
            return redirect(url_for('index'))

        # Decrypt fields for pre-filling the form
        asset['account_no'] = dec(asset['account_no'])
        asset['owner_id'] = dec(asset['owner_id'])
        asset['beneficiary_name'] = dec(asset['beneficiary_name'])
        asset['contact_phone'] = dec(asset['contact_phone'])
        asset['document_location'] = dec(asset['document_location'])
        asset['description'] = dec(asset['description'])
        
        groups = fetch_asset_groups(user_id)

        if request.method == 'POST':
            data = request.form

            # Data preparation and encryption
            # Note: Assuming all fields from the add_asset route are present for a full update
            update_fields = {
                'type': data['type'],
                'name': data['name'],
                'country': data['country'],
                'currency': data['currency'],
                'value': Decimal(data['value']),
                'current_value': Decimal(data.get('current_value', data['value'])),
                'notes': data.get('notes', ''),
                'owner': data['owner'],
                'financial_institution': data['financial_institution'],
                'policy_or_plan_type': data['policy_or_plan_type'],
                'investment_strategy': data['investment_strategy'],
                'group_id': data['group_id'],
                'account_no': enc(data['account_no']),
                'owner_id': enc(data['owner_id']),
                'beneficiary_name': enc(data['beneficiary_name']),
                'contact_phone': enc(data['contact_phone']),
                'document_location': enc(data['document_location']),
                'description': enc(data['description']),
            }
            
            # Construct dynamic SQL update statement
            set_clauses = [f"{k} = %s" for k in update_fields.keys()]
            set_params = list(update_fields.values())
            
            # Add last_updated timestamp
            set_clauses.append("last_updated = NOW()")

            sql = f"""
                UPDATE assets 
                SET {', '.join(set_clauses)}
                WHERE id = %s AND user_id = %s;
            """
            
            cur.execute(sql, set_params + [asset_id, user_id])
            conn.commit()
            
            flash("Asset updated successfully!", "success")
            return redirect(url_for('index'))

        cur.close()
        # Render the edit form (edit_asset.html needs to be created)
        return render_template('edit_asset.html', asset=asset, groups=groups)

    except KeyError as e:
        flash(f"Missing required form field(s). Please ensure your form is complete: {e}", "error")
    except ValueError:
        flash("Value and Current Value must be valid numbers.", "error")
    except psycopg2.IntegrityError as e:
        print(f"PostgreSQL Integrity Error updating asset: {e}", file=sys.stderr)
        flash("Failed to update asset due to a database constraint error.", "error")
        if conn: conn.rollback()
    except Exception as e:
        print(f"General Error updating/fetching asset: {e}", file=sys.stderr)
        flash("An unexpected error occurred.", "error")
        if conn: conn.rollback()
        
    return redirect(url_for('index'))

@app.route('/assets/<int:asset_id>/delete', methods=['POST'])
@login_required
def delete_asset(asset_id):
    """Deletes an asset for the logged-in user."""
    conn = None
    try:
        user_id = g.user['id']
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("DELETE FROM assets WHERE id = %s AND user_id = %s;", (asset_id, user_id))
        
        if cur.rowcount == 1:
            conn.commit()
            flash("Asset deleted successfully.", "success")
        else:
            flash("Asset not found or you do not have permission to delete it.", "error")
            
    except Exception as e:
        print(f"Error deleting asset: {e}", file=sys.stderr)
        flash("An error occurred while deleting the asset.", "error")
        if conn: conn.rollback()

    return redirect(url_for('index'))

@app.route('/groups/add', methods=['POST'])
@login_required
def add_group():
    """Adds a new asset group."""
    conn = None
    try:
        group_name = request.form['group_name']
        description = request.form.get('description', '')
        user_id = g.user['id']

        if not group_name:
            flash("Group name is required.", "error")
            return redirect(url_for('index'))

        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            INSERT INTO asset_groups (user_id, name, description, created_at)
            VALUES (%s, %s, %s, NOW());
        """, (user_id, group_name, description))
        
        conn.commit()
        flash("Asset group added successfully!", "success")

    except KeyError:
        flash("Missing group name field.", "error")
    except psycopg2.IntegrityError:
        flash("A group with that name may already exist.", "error")
        if conn: conn.rollback()
    except Exception as e:
        print(f"Error adding group: {e}", file=sys.stderr)
        flash("An unexpected error occurred while adding the group.", "error")
        if conn: conn.rollback()

    return redirect(url_for('index'))


@app.route('/groups/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    """Deletes an asset group and optionally moves assets."""
    conn = None
    try:
        user_id = g.user['id']
        move_assets_to_group_id = request.form.get('move_to_group_id') # Can be None or a group ID

        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Update assets belonging to this group, if a target is provided
        if move_assets_to_group_id:
            cur.execute("""
                UPDATE assets SET group_id = %s 
                WHERE group_id = %s AND user_id = %s;
            """, (move_assets_to_group_id, group_id, user_id))

        # 2. Delete the group
        cur.execute("DELETE FROM asset_groups WHERE id = %s AND user_id = %s;", (group_id, user_id))
        
        if cur.rowcount == 1:
            conn.commit()
            flash("Asset group deleted successfully.", "success")
        else:
            flash("Asset group not found or you do not have permission to delete it.", "error")
            
    except Exception as e:
        print(f"Error deleting group: {e}", file=sys.stderr)
        flash("An error occurred while deleting the asset group.", "error")
        if conn: conn.rollback()

    return redirect(url_for('index'))


# -------------------------------------------------
# App Execution
# -------------------------------------------------
if __name__ == '__main__':
    # This block is for local development only.
    if not os.environ.get('DATABASE_URL'):
        print("Warning: DATABASE_URL not set. Running in development mode (requires local PostgreSQL setup).")
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
