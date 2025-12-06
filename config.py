from flask import Flask
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.fernet import Fernet

import os
import sys

# -------------------------------------------------
# App & Config Initialization
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

# Rate Limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Email configuration
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
ADMIN_NOTIFY_EMAILS = [e.strip() for e in os.environ.get("ADMIN_NOTIFY_EMAILS", "").split(',') if e.strip()]
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:5000")

# -------------------------------------------------
# Security & Encryption Configuration
# -------------------------------------------------

# Get the encryption key from environment variables
FERNET_KEY = os.environ.get("FERNET_KEY", "A_FALLBACK_KEY_MUST_BE_32_URL_SAFE_BASE64_BYTES")
try:
    if len(FERNET_KEY) < 44:
        # Generate a key if it's missing or clearly incorrect/too short
        FERNET_KEY = Fernet.generate_key().decode()
    F = Fernet(FERNET_KEY.encode())
except Exception as e:
    print(f"ERROR: Could not initialize Fernet. Encryption will fail. Check FERNET_KEY environment variable. Error: {e}", file=sys.stderr)
    # Use a dummy Fernet if initialization fails to prevent crash
    F = Fernet(Fernet.generate_key())


# Sensitive Field Definition - Centralized list for decryption
SENSITIVE_ASSET_FIELDS = [
    'account_no',
    'financial_institution',
    'beneficiary_name',
    'contact_phone',
    'document_location',
]

def enc(text):
    """Encrypts a string, handling None or empty strings."""
    if not text:
        return None
    try:
        return F.encrypt(str(text).encode()).decode()
    except Exception as e:
        print(f"Encryption error: {e}", file=sys.stderr)
        return text

def dec(token):
    """Decrypts a token, handling None or non-encrypted data."""
    if not token or not isinstance(token, str):
        return token
    try:
        # Check if the token looks like a Fernet token (starts with 'gAAAAA')
        if token.startswith('gAAAAA'):
            return F.decrypt(token.encode()).decode()
        else:
            # Assume it's unencrypted text if it doesn't match the token format
            return token
    except Exception as e:
        print(f"Decryption error on token {token[:15]}...: {e}", file=sys.stderr)
        return token
