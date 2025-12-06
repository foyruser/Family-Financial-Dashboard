from flask import Flask, g, session
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

import os
import sys
import secrets
from cryptography.fernet import Fernet

# -------------------------------------------------
# App & Config
# -------------------------------------------------
# Instantiate the Flask application
app = Flask(__name__)

# --- Configuration Loading ---
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY", secrets.token_hex(24))

# PostgreSQL Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("FATAL: DATABASE_URL environment variable is not set.", file=sys.stderr)
    # Use a dummy value to prevent crash, but app will fail on DB access
    DATABASE_URL = "postgresql://user:password@localhost/dummy_db"

# Email Configuration (for admin notifications)
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
ADMIN_NOTIFY_EMAILS = [e.strip() for e in os.environ.get("ADMIN_NOTIFY_EMAILS", "").split(',') if e.strip()]
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000") # Base URL for external links

# Encryption Configuration
# The shared secret key for Fernet encryption (must be 32 URL-safe base64 bytes)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # Generate a key if missing (development only)
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("WARNING: ENCRYPTION_KEY not set. Using a temporary key. Data encrypted with this key will be lost on restart.", file=sys.stderr)

try:
    fernet = Fernet(ENCRYPTION_KEY)
except Exception as e:
    print(f"FATAL: Invalid ENCRYPTION_KEY format: {e}", file=sys.stderr)
    sys.exit(1)

# Helper functions for encryption/decryption
def enc(data):
    """Encrypts a string or returns an empty byte string if input is None/empty."""
    if not data: return b''
    try:
        return fernet.encrypt(data.encode('utf-8'))
    except Exception as e:
        print(f"Encryption error: {e}", file=sys.stderr)
        return b''

def dec(data):
    """Decrypts bytes or returns an empty string if input is None/empty/invalid."""
    if not data: return ''
    try:
        # data might be a memoryview/bytes coming from psycopg2
        return fernet.decrypt(bytes(data)).decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}", file=sys.stderr)
        return 'DECRYPTION_FAILED'

# Secure cookies in prod
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set to True only if using HTTPS in production
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
)

# Respect proxy headers for real client IP (important for rate limiting)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# --- Extensions ---
bcrypt = Bcrypt(app)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://", # Simple in-memory storage for rate limiting
)

# Custom hook to manage flash messages across redirects
# This is a common pattern when you cannot use `get_flashed_messages` directly
# due to certain Flask/environment configurations
@app.after_request
def flash_session_handler(response):
    """Stores flashed messages in the session before redirecting."""
    if response.status_code == 302:
        # Check for messages passed via `flash()`
        messages = g.get('_flashes')
        if messages:
            session['flash_messages'] = messages
    
    # Restore messages from session on non-redirect requests
    elif response.status_code == 200 and 'flash_messages' in session:
        # Re-add to g to be processed by jinja2
        g._flashes = session.pop('flash_messages')

    return response

# -------------------------------------------------
# Import and Register Blueprints/Routes
# -------------------------------------------------

# We import the routes here so they can access the 'app' instance and extensions
import family_finance.routes # Assuming the application module is 'family_finance'

# NOTE: The rest of the application setup (DB, utils, routes) is handled by
# the other files provided in this exchange: db.py, utils.py, and routes.py.

if __name__ == '__main__':
    # When running locally, use a default host/port
    app.run(debug=True, host='0.0.0.0', port=5000)
