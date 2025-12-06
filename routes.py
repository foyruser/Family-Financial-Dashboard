from flask import render_template, request, redirect, url_for, g, flash, session
from datetime import datetime
import sys
import json
import re # For input validation

# Import application instances and helper functions
from .config import app, bcrypt, enc, dec
from .db import get_db, init_db # Import init_db for the setup route
from .utils import login_required, admin_required, approval_required, notify_admin_new_user, get_asset_by_id, get_group_members

# -------------------------------------------------
# Home and Core Pages
# -------------------------------------------------

@app.route('/')
@approval_required
def index():
    """Home page. Displays the list of assets for the user's group."""
    db = get_db()
    cur = db.cursor()
    assets = []
    total_value = 0.0
    group_members = []
    group_name = "Personal Assets" # Default for non-group users

    try:
        if g.user['group_id']:
            # Fetch group name
            cur.execute("SELECT name FROM groups WHERE id = %s;", (g.user['group_id'],))
            group_name_data = cur.fetchone()
            if group_name_data:
                group_name = group_name_data['name']
            
            # Fetch assets belonging to the user's group
            cur.execute("""
                SELECT id, name, type, country, currency, value, current_value, owner, added_date, last_updated
                FROM assets
                WHERE group_id = %s
                ORDER BY name;
            """, (g.user['group_id'],))
            assets = cur.fetchall()
            
            # Calculate total value and ensure numeric types
            for asset in assets:
                try:
                    asset['value'] = float(asset['value'])
                    asset['current_value'] = float(asset['current_value'])
                    total_value += asset['current_value']
                except (TypeError, ValueError):
                    asset['value'] = 0.0
                    asset['current_value'] = 0.0
            
            # Fetch group members for display
            group_members = get_group_members(g.user['group_id'])
            
    except Exception as e:
        flash(f"Error fetching assets: {e}", "danger")
        print(f"Error fetching assets: {e}", file=sys.stderr)
    finally:
        cur.close()

    return render_template('index.html', assets=assets, total_value=total_value, 
                           group_name=group_name, group_members=group_members)

@app.route('/pending')
def pending_approval():
    """Page displayed to users whose accounts are registered but not yet approved."""
    if g.user and g.user['is_approved']:
        # If user is approved, redirect to home
        return redirect(url_for('index'))
    return render_template('pending_approval.html')

# -------------------------------------------------
# Authentication Routes
# -------------------------------------------------

@app.route('/register', methods=('GET', 'POST'))
def register():
    """Handles user registration."""
    if g.user is not None:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        error = None

        if not username or not email or not password or not password_confirm:
            error = 'All fields are required.'
        elif password != password_confirm:
            error = 'Passwords do not match.'
        elif len(username) < 3 or len(password) < 8:
            error = 'Username must be at least 3 characters and password must be at least 8 characters.'
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            error = 'Invalid email format.'

        db = get_db()
        cur = db.cursor()

        if error is None:
            try:
                password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                
                # is_approved defaults to FALSE. is_admin defaults to FALSE.
                cur.execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
                    (username, email, password_hash)
                )
                user_id = cur.fetchone()['id']
                db.commit()

                # Notify administrator for approval
                notify_admin_new_user(user_id, username, email)
                
                flash("Registration successful. Your account is pending administrator approval. You will be notified via email when you can log in.", "success")
                return redirect(url_for('login'))
            except psycopg2.errors.UniqueViolation as e:
                error = f"User with that username or email already exists. ({e.diag.message_primary})"
                db.rollback()
            except Exception as e:
                error = f"Database error during registration: {e}"
                db.rollback()
            finally:
                cur.close()

        flash(error, "danger")

    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
# Limiter for brute-force protection (configured in config.py)
# Limit to 5 attempts per minute per IP address
@app.limiter.limit("5/minute", methods=['POST'], error_message="Too many login attempts. Please wait a minute and try again.")
def login():
    """Handles user login."""
    if g.user is not None:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        cur = db.cursor()
        error = None
        user = None

        try:
            cur.execute(
                'SELECT id, username, password_hash, is_admin, is_approved, failed_login_attempts, lockout_until FROM users WHERE username = %s',
                (username,)
            )
            user = cur.fetchone()

            if user is None:
                error = 'Incorrect username or password.'
            elif user.get('lockout_until') and user['lockout_until'] > datetime.now():
                error = 'This account is temporarily locked due to too many failed login attempts.'
            elif not bcrypt.check_password_hash(user['password_hash'], password):
                error = 'Incorrect username or password.'

            if error is not None:
                # Handle failed login attempt for the user if they exist
                if user:
                    failed_attempts = user.get('failed_login_attempts', 0) + 1
                    lockout_until = None
                    
                    # Lockout after 5 failures
                    if failed_attempts >= 5:
                        lockout_duration = timedelta(minutes=15)
                        lockout_until = datetime.now() + lockout_duration
                        error += f" Account locked for {lockout_duration.seconds // 60} minutes."
                        
                    cur.execute(
                        "UPDATE users SET failed_login_attempts = %s, lockout_until = %s WHERE id = %s",
                        (failed_attempts, lockout_until, user['id'])
                    )
                    db.commit()
                
                flash(error, "danger")
            else:
                # Successful login
                # Reset failed attempts and update last login time
                cur.execute(
                    "UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, last_login = %s WHERE id = %s",
                    (datetime.now(), user['id'])
                )
                db.commit()

                session['user_id'] = user['id']

                # Check approval status and redirect
                if not user['is_approved'] and not user['is_admin']:
                    flash("Your account is pending admin approval.", "info")
                    return redirect(url_for('pending_approval'))
                
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('index'))

        except Exception as e:
            flash("An unexpected error occurred during login. Please try again.", "danger")
            print(f"Login error: {e}", file=sys.stderr)
            db.rollback()
        finally:
            cur.close()

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logs out the current user."""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# -------------------------------------------------
# Asset Management Routes
# -------------------------------------------------

@app.route('/assets/add', methods=('GET', 'POST'))
@approval_required
def add_asset():
    """Adds a new financial asset."""
    if request.method == 'POST':
        form_data = request.form.to_dict()
        error = None

        required_fields = ['name', 'type', 'value', 'owner']
        if any(not form_data.get(field) for field in required_fields):
            error = 'Asset Name, Type, Value, and Owner are required fields.'
        
        # Basic type validation
        try:
            value = float(form_data.get('value', 0))
            current_value = float(form_data.get('current_value', value))
        except ValueError:
            error = "Value and Current Value must be valid numbers."

        db = get_db()
        cur = db.cursor()

        if error is None:
            try:
                # Encrypt sensitive fields before storage
                account_no_enc = enc(form_data.get('account_no', ''))
                institution_enc = enc(form_data.get('financial_institution', ''))
                beneficiary_enc = enc(form_data.get('beneficiary_name', ''))
                phone_enc = enc(form_data.get('contact_phone', ''))
                document_loc_enc = enc(form_data.get('document_location', ''))

                cur.execute("""
                    INSERT INTO assets (user_id, group_id, type, name, description, country, currency, value, account_no, 
                                        financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, 
                                        document_location, investment_strategy, current_value, owner, notes, owner_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (g.user['id'], g.user['group_id'], form_data.get('type'), form_data.get('name'), 
                      form_data.get('description', ''), form_data.get('country', ''), form_data.get('currency', ''),
                      value, account_no_enc, institution_enc, beneficiary_enc, 
                      form_data.get('policy_or_plan_type', ''), phone_enc, document_loc_enc,
                      form_data.get('investment_strategy', ''), current_value, 
                      form_data.get('owner'), form_data.get('notes', ''), g.user['id']))
                
                db.commit()
                flash(f"Asset '{form_data['name']}' successfully added.", "success")
                return redirect(url_for('index'))
            except Exception as e:
                flash(f"Database error while adding asset: {e}", "danger")
                print(f"Error adding asset: {e}", file=sys.stderr)
                db.rollback()
            finally:
                cur.close()
        
        flash(error, "danger")

    # Pass group members for the Owner dropdown
    group_members = get_group_members(g.user['group_id']) if g.user and g.user['group_id'] else []
    return render_template('add_edit_asset.html', asset=None, group_members=group_members, form_title="Add New Asset")

@app.route('/assets/edit/<int:asset_id>', methods=('GET', 'POST'))
@approval_required
def edit_asset(asset_id):
    """Edits an existing financial asset."""
    # Ensure the asset belongs to the user's group
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash("Asset not found or you do not have permission to view it.", "danger")
        return redirect(url_for('index'))

    # Decrypt sensitive fields for display/editing
    asset['account_no'] = dec(asset['account_no'])
    asset['financial_institution'] = dec(asset['financial_institution'])
    asset['beneficiary_name'] = dec(asset['beneficiary_name'])
    asset['contact_phone'] = dec(asset['contact_phone'])
    asset['document_location'] = dec(asset['document_location'])

    if request.method == 'POST':
        form_data = request.form.to_dict()
        error = None

        required_fields = ['name', 'type', 'value', 'owner']
        if any(not form_data.get(field) for field in required_fields):
            error = 'Asset Name, Type, Value, and Owner are required fields.'

        try:
            value = float(form_data.get('value', 0))
            current_value = float(form_data.get('current_value', value))
        except ValueError:
            error = "Value and Current Value must be valid numbers."

        db = get_db()
        cur = db.cursor()

        if error is None:
            try:
                # Encrypt sensitive fields before storage
                account_no_enc = enc(form_data.get('account_no', ''))
                institution_enc = enc(form_data.get('financial_institution', ''))
                beneficiary_enc = enc(form_data.get('beneficiary_name', ''))
                phone_enc = enc(form_data.get('contact_phone', ''))
                document_loc_enc = enc(form_data.get('document_location', ''))
                
                cur.execute("""
                    UPDATE assets SET 
                        type = %s, name = %s, description = %s, country = %s, currency = %s, 
                        value = %s, account_no = %s, financial_institution = %s, 
                        beneficiary_name = %s, policy_or_plan_type = %s, contact_phone = %s, 
                        document_location = %s, investment_strategy = %s, current_value = %s, 
                        owner = %s, notes = %s, last_updated = NOW()
                    WHERE id = %s AND group_id = %s;
                """, (form_data.get('type'), form_data.get('name'), form_data.get('description', ''), 
                      form_data.get('country', ''), form_data.get('currency', ''), value, 
                      account_no_enc, institution_enc, beneficiary_enc, form_data.get('policy_or_plan_type', ''), 
                      phone_enc, document_loc_enc, form_data.get('investment_strategy', ''), 
                      current_value, form_data.get('owner'), form_data.get('notes', ''), 
                      asset_id, g.user['group_id']))
                
                db.commit()
                flash(f"Asset '{form_data['name']}' successfully updated.", "success")
                return redirect(url_for('index'))
            except Exception as e:
                flash(f"Database error while updating asset: {e}", "danger")
                print(f"Error updating asset {asset_id}: {e}", file=sys.stderr)
                db.rollback()
            finally:
                cur.close()
        
        flash(error, "danger")

    group_members = get_group_members(g.user['group_id']) if g.user and g.user['group_id'] else []
    return render_template('add_edit_asset.html', asset=asset, group_members=group_members, form_title=f"Edit Asset: {asset['name']}")

@app.route('/assets/delete/<int:asset_id>', methods=('POST',))
@approval_required
def delete_asset(asset_id):
    """Deletes an existing financial asset."""
    # Ensure the asset belongs to the user's group
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash("Asset not found or you do not have permission to delete it.", "danger")
        return redirect(url_for('index'))

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(
            "DELETE FROM assets WHERE id = %s AND group_id = %s;",
            (asset_id, g.user['group_id'])
        )
        db.commit()
        flash(f"Asset '{asset['name']}' successfully deleted.", "success")
    except Exception as e:
        flash(f"Database error while deleting asset: {e}", "danger")
        print(f"Error deleting asset {asset_id}: {e}", file=sys.stderr)
        db.rollback()
    finally:
        cur.close()

    return redirect(url_for('index'))

@app.route('/assets/view/<int:asset_id>')
@approval_required
def view_asset(asset_id):
    """Displays the full details of a single asset."""
    asset = get_asset_by_id(asset_id)
    if not asset:
        flash("Asset not found or you do not have permission to view it.", "danger")
        return redirect(url_for('index'))

    # Decrypt ALL sensitive fields for viewing
    try:
        asset['account_no'] = dec(asset['account_no'])
        asset['financial_institution'] = dec(asset['financial_institution'])
        asset['beneficiary_name'] = dec(asset['beneficiary_name'])
        asset['contact_phone'] = dec(asset['contact_phone'])
        asset['document_location'] = dec(asset['document_location'])
    except Exception as e:
        flash("Error decrypting sensitive data for this asset.", "warning")
        print(f"Decryption error for asset {asset_id}: {e}", file=sys.stderr)
        # Use placeholders if decryption fails
        asset['account_no'] = "Decryption Failed"

    return render_template('view_asset.html', asset=asset)


# -------------------------------------------------
# Admin Routes
# -------------------------------------------------

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard landing page."""
    db = get_db()
    cur = db.cursor()
    stats = {}
    
    try:
        # User Count
        cur.execute("SELECT COUNT(*) AS total_users FROM users;")
        stats['total_users'] = cur.fetchone()['total_users']
        cur.execute("SELECT COUNT(*) AS pending_users FROM users WHERE is_approved = FALSE;")
        stats['pending_users'] = cur.fetchone()['pending_users']
        
        # Asset Count
        cur.execute("SELECT COUNT(*) AS total_assets FROM assets;")
        stats['total_assets'] = cur.fetchone()['total_assets']
        
        # Group Count
        cur.execute("SELECT COUNT(*) AS total_groups FROM groups;")
        stats['total_groups'] = cur.fetchone()['total_groups']
        
    except Exception as e:
        print(f"Error fetching admin stats: {e}", file=sys.stderr)
        flash("Error fetching admin statistics.", "danger")
    finally:
        cur.close()

    return render_template('admin/dashboard.html', stats=stats)

@app.route('/admin/users', methods=('GET', 'POST'))
@admin_required
def admin_users():
    """Admin page for managing users (approval, group assignment)."""
    db = get_db()
    cur = db.cursor()
    users = []
    groups = []

    try:
        # Fetch all users
        cur.execute("SELECT id, username, email, is_admin, is_approved, group_id, last_login, created_at FROM users ORDER BY created_at DESC;")
        users = cur.fetchall()
        
        # Fetch all groups
        cur.execute("SELECT id, name FROM groups ORDER BY name;")
        groups = cur.fetchall()
        
    except Exception as e:
        flash(f"Error fetching users or groups: {e}", "danger")
        print(f"Error fetching users/groups: {e}", file=sys.stderr)
    
    # Handle POST request for user approval/group change
    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')
        
        if action == 'approve' or action == 'group_change':
            new_group_id = request.form.get('group_id')
            
            cur = db.cursor()
            try:
                # Get current user status before update
                cur.execute("SELECT is_approved, username FROM users WHERE id = %s;", (user_id,))
                user_data = cur.fetchone()
                
                if user_data:
                    # Determine new approval status
                    is_approved_new = (action == 'approve') or user_data['is_approved']
                    
                    # Update user
                    cur.execute("""
                        UPDATE users SET is_approved = %s, group_id = %s
                        WHERE id = %s;
                    """, (is_approved_new, new_group_id if new_group_id != 'none' else None, user_id))
                    db.commit()

                    if action == 'approve' and not user_data['is_approved']:
                        # Notify if approval status changed from FALSE to TRUE
                        flash(f"User {user_data['username']} approved and assigned to group {new_group_id}.", "success")
                        # notify_admin_user_approved(user_data['username'], g.user['username'], new_group_id)
                        # NOTE: notify_admin_user_approved is currently designed to notify *other* admins, which isn't strictly necessary for a single-admin system, but included for completeness.
                    elif action == 'group_change':
                        flash(f"Group for user {user_data['username']} updated.", "success")
                    
                    # Redirect to prevent re-POST and show updated list
                    return redirect(url_for('admin_users'))
                else:
                    flash("User not found.", "danger")
            except Exception as e:
                flash(f"Database error during user update: {e}", "danger")
                print(f"Error updating user {user_id}: {e}", file=sys.stderr)
                db.rollback()
            finally:
                cur.close()

    # Re-fetch users and groups if POST failed or for GET request
    cur = db.cursor()
    try:
        cur.execute("SELECT id, username, email, is_admin, is_approved, group_id, last_login, created_at FROM users ORDER BY created_at DESC;")
        users = cur.fetchall()
        cur.execute("SELECT id, name FROM groups ORDER BY name;")
        groups = cur.fetchall()
    except Exception as e:
        print(f"Error re-fetching users/groups: {e}", file=sys.stderr)
    finally:
        cur.close()

    return render_template('admin/users.html', users=users, groups=groups)

@app.route('/admin/groups', methods=('GET', 'POST'))
@admin_required
def admin_groups():
    """Admin page for managing groups."""
    db = get_db()
    cur = db.cursor()
    groups = []

    # Handle POST request for adding a group
    if request.method == 'POST':
        group_name = request.form.get('group_name', '').strip()
        group_id = request.form.get('group_id', '').strip().lower().replace(' ', '-')
        error = None
        
        if not group_name or not group_id:
            error = "Both Group Name and a URL-friendly Group ID are required."
        elif not re.match(r'^[a-z0-9-]+$', group_id):
            error = "Group ID can only contain lowercase letters, numbers, and hyphens."
        
        if error is None:
            try:
                cur.execute("""
                    INSERT INTO groups (id, name, created_by_user_id)
                    VALUES (%s, %s, %s);
                """, (group_id, group_name, g.user['id']))
                db.commit()
                flash(f"Group '{group_name}' created successfully.", "success")
                return redirect(url_for('admin_groups'))
            except psycopg2.errors.UniqueViolation:
                error = "A group with that ID already exists. Please choose a different ID."
                db.rollback()
            except Exception as e:
                error = f"Database error creating group: {e}"
                db.rollback()
            finally:
                cur.close()
        
        flash(error, "danger")

    # Fetch all groups for display
    cur = db.cursor()
    try:
        cur.execute("SELECT g.id, g.name, u.username AS created_by, g.created_at, (SELECT COUNT(*) FROM users WHERE group_id = g.id) AS member_count FROM groups g JOIN users u ON g.created_by_user_id = u.id ORDER BY g.created_at DESC;")
        groups = cur.fetchall()
    except Exception as e:
        flash(f"Error fetching groups: {e}", "danger")
        print(f"Error fetching groups: {e}", file=sys.stderr)
    finally:
        cur.close()
        
    return render_template('admin/groups.html', groups=groups)

# -------------------------------------------------
# Setup Route (Run once for initial database setup)
# -------------------------------------------------

@app.route('/setup')
def setup():
    """Initializes the database schema and sample data."""
    # NOTE: This route should ideally be protected or removed after first run
    result = init_db()
    flash(result, "info")
    return redirect(url_for('login'))

# -------------------------------------------------
# Error Handling
# -------------------------------------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(429)
def too_many_requests(e):
    return render_template('429.html'), 429
