
import functools
import smtplib
from email.message import EmailMessage
from datetime import datetime
from flask import g, request, redirect, url_for, flash

from .config import app, SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, ADMIN_NOTIFY_EMAILS, APP_BASE_URL
from .db import get_db

# -------------------------------------------------
# Authentication and Authorization Decorators
# -------------------------------------------------

def login_required(view):
    """Decorator to require a user to be logged in."""
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("You must be logged in to view this page.", "warning")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    """Decorator to require the user to be an admin."""
    @functools.wraps(view)
    @login_required
    def wrapped_view(**kwargs):
        if not g.user['is_admin']:
            flash("You do not have permission to access the admin area.", "danger")
            return redirect(url_for('index'))
        return view(**kwargs)
    return wrapped_view

def approval_required(view):
    """Decorator to require the user to be approved by an admin."""
    @functools.wraps(view)
    @login_required
    def wrapped_view(**kwargs):
        if not g.user['is_approved']:
            flash("Your account is pending admin approval. Please wait or contact an administrator.", "info")
            # Redirect to a pending page instead of index
            return redirect(url_for('pending_approval'))
        return view(**kwargs)
    return wrapped_view

# -------------------------------------------------
# Email Notification Helpers
# -------------------------------------------------

def send_email(to_addr: str, subject: str, html_content: str):
    """
    Sends an email using the configured SMTP server.
    """
    if not SMTP_SERVER or not SMTP_USER or not SMTP_PASSWORD:
        print("WARNING: Email configuration missing. Skipping email send.", file=sys.stderr)
        return

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_USER
    msg['To'] = to_addr
    msg.set_content(html_content, subtype='html')

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure the connection
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"SMTP error sending email to {to_addr}: {e}", file=sys.stderr)
        # In a real app, you might want to log this failure more robustly

def notify_admin_new_user(user_id: int, username: str, email: str | None = None):
    """
    Notifies all configured admin emails about a new user registration.
    """
    if not ADMIN_NOTIFY_EMAILS:
        return
    
    # Use request context for IP and User Agent, falls back if called outside request
    ip = request.remote_addr if request else "N/A"
    ua = request.user_agent.string if request else "N/A"
    when = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')
    
    subject = f"[Family Finance] New User Pending Approval: {username}"
    # Link to the admin page for approval (assuming 'admin_users' is the route)
    admin_link = url_for('admin_users', _external=True)

    html = f"""
        <h2>New User Registration Pending Approval</h2>
        <p>A new user has registered for the Family Finance Tracker.</p>
        <p><strong>Username:</strong> {username}</p>
        <p><strong>Email:</strong> {email or username}</p>
        <p><strong>When (UTC):</strong> {when}</p>
        <p><strong>IP:</strong> {ip}</p>
        <p><strong>User-Agent:</strong> {ua}</p>
        <hr>
        <p>This user is pending approval. Please visit the <a href="{admin_link}">Admin User Management page</a> to review and approve the account.</p>
        <p>User ID: {user_id}</p>
    """
    
    for admin_addr in ADMIN_NOTIFY_EMAILS:
        try:
            send_email(admin_addr, subject, html)
        except Exception as e:
            print(f"Admin notification failed to {admin_addr}: {e}", file=sys.stderr)

def notify_admin_user_approved(username: str, approver: str | None, group_id: str | None):
    """
    Notifies admins when a user has been approved.
    """
    if not ADMIN_NOTIFY_EMAILS:
        return
        
    subject = f"[Family Finance] User approved: {username}"
    html = f"""
        <h2>User Approved</h2>
        <p><strong>User:</strong> {username}</p>
        <p><strong>Group:</strong> {group_id or '(none)'}</p>
        <p><strong>Approved by:</strong> {approver or 'Admin'}</p>
        <p><strong>When (UTC):</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}</p>
    """
    
    for admin_addr in ADMIN_NOTIFY_EMAILS:
        try:
            send_email(admin_addr, subject, html)
        except Exception as e:
            print(f"Admin notification failed to {admin_addr}: {e}", file=sys.stderr)

# -------------------------------------------------
# Asset and Group Permission Helpers
# -------------------------------------------------

def get_asset_by_id(asset_id: int):
    """Fetches a single asset by ID, ensuring it belongs to the user's group."""
    db = get_db()
    cur = db.cursor()
    
    if g.user['group_id'] is None:
        # A user without a group cannot see any shared assets
        return None

    try:
        cur.execute("""
            SELECT * FROM assets WHERE id = %s AND group_id = %s;
        """, (asset_id, g.user['group_id']))
        return cur.fetchone()
    except Exception as e:
        print(f"Error fetching asset {asset_id}: {e}", file=sys.stderr)
        return None
    finally:
        cur.close()


def get_group_members(group_id: str):
    """Fetches all approved users belonging to a specific group."""
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            SELECT id, username, email FROM users
            WHERE group_id = %s AND is_approved = TRUE;
        """, (group_id,))
        return cur.fetchall()
    except Exception as e:
        print(f"Error fetching group members for {group_id}: {e}", file=sys.stderr)
        return []
    finally:
        cur.close()

# -------------------------------------------------
# User Loading Hook (Runs before every request)
# -------------------------------------------------

@app.before_request
def load_logged_in_user():
    """
    Checks the session for a user ID and loads the user object into
    the global context (g.user) for easy access in views.
    Also handles decryption of sensitive fields on the user object.
    """
    user_id = request.session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                'SELECT * FROM users WHERE id = %s', (user_id,)
            )
            g.user = cur.fetchone()
        except Exception as e:
            print(f"Database error loading user {user_id}: {e}", file=sys.stderr)
            g.user = None
        finally:
            cur.close()

        # If the user exists and is not admin, but is not approved, log them out
        if g.user is not None and not g.user['is_approved'] and not g.user['is_admin']:
            if request.endpoint not in ['logout', 'pending_approval', 'static']:
                flash("Your account approval was revoked or is pending. Please log in again.", "warning")
                request.session.clear()
                g.user = None

        # Handle lockout logic
        if g.user and g.user.get('lockout_until'):
            lockout_time = g.user['lockout_until']
            if lockout_time > datetime.now():
                # User is currently locked out
                g.user = None # Treat as logged out for security
                flash("Your account is temporarily locked due to too many failed login attempts.", "danger")
                if request.endpoint not in ['login', 'static']:
                    return redirect(url_for('login'))
            else:
                # Lockout time expired, reset attempts
                cur = db.cursor()
                try:
                    cur.execute(
                        "UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = %s",
                        (user_id,)
                    )
                    db.commit()
                except Exception as e:
                    print(f"Error resetting lockout for user {user_id}: {e}", file=sys.stderr)
                finally:
                    cur.close()
