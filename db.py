import psycopg2
from psycopg2.extras import RealDictCursor
from flask import g
from datetime import datetime
import os
import sys

# Import app, bcrypt, and encryption utils from config
from .config import app, bcrypt, enc

# -------------------------------------------------
# Database Configuration
# -------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL")

# -------------------------------------------------
# Connection Management Functions
# -------------------------------------------------

def get_db():
    """
    Establishes a PostgreSQL database connection if one is not already
    present in the Flask global context (g), and returns the connection.
    """
    if 'db' not in g:
        if not DATABASE_URL:
            print("ERROR: DATABASE_URL not set.", file=sys.stderr)
            raise ConnectionError("DATABASE_URL is not configured.")
        
        try:
            # Connect using the URL. The RealDictCursor allows results to be
            # returned as dicts (like JSON objects), which is cleaner.
            g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        except Exception as e:
            print(f"Database connection failed: {e}", file=sys.stderr)
            raise ConnectionError(f"Could not connect to database: {e}")

    return g.db

def close_db(e=None):
    """
    Closes the database connection if it exists in the Flask global context.
    This is typically registered to run after each request.
    """
    db = g.pop('db', None)

    if db is not None:
        db.close()

# Register the close_db function to run after each request
app.teardown_appcontext(close_db)

# -------------------------------------------------
# Database Initialization and Schema Setup
# -------------------------------------------------

def init_db():
    """
    Sets up the database schema and inserts initial admin/sample data.
    """
    conn = get_db()
    cur = conn.cursor()

    try:
        # 1. Create the 'users' table
        print("Creating users table...", file=sys.stderr)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                email VARCHAR(120) UNIQUE NOT NULL,
                password_hash VARCHAR(128) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                is_approved BOOLEAN DEFAULT FALSE,
                group_id VARCHAR(50), -- Used for shared asset access
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                lockout_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 2. Create the 'assets' table
        print("Creating assets table...", file=sys.stderr)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) NOT NULL,
                group_id VARCHAR(50), -- Duplicated from user for efficient query access
                type VARCHAR(50) NOT NULL,
                name VARCHAR(100) NOT NULL,
                description TEXT,
                country VARCHAR(50),
                currency VARCHAR(10),
                value NUMERIC(15, 2), -- Current book value / policy value
                account_no VARCHAR(100), -- ENCRYPTED
                financial_institution VARCHAR(100), -- ENCRYPTED
                beneficiary_name VARCHAR(100), -- ENCRYPTED
                policy_or_plan_type VARCHAR(100), -- Specific type (e.g., 401k, Term Life)
                contact_phone VARCHAR(50), -- ENCRYPTED
                document_location VARCHAR(100), -- ENCRYPTED (e.g., 'Safe Deposit Box #123')
                investment_strategy TEXT,
                current_value NUMERIC(15, 2), -- Market value (if different from 'value')
                owner VARCHAR(100),
                owner_id INTEGER, -- User ID of the primary owner if different from user_id
                notes TEXT,
                added_date DATE DEFAULT CURRENT_DATE,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 3. Create the 'groups' table (for sharing assets)
        print("Creating groups table...", file=sys.stderr)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id VARCHAR(50) PRIMARY KEY, -- Group ID (e.g., 'family-smith')
                name VARCHAR(100) NOT NULL,
                created_by_user_id INTEGER REFERENCES users(id) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 4. Insert initial data (Admin user, Group, Sample Asset)
        
        # Check if admin user already exists
        cur.execute("SELECT id FROM users WHERE username = 'admin';")
        if cur.fetchone() is None:
            print("Inserting admin user and sample data...", file=sys.stderr)
            
            # Create a password hash for 'password'
            admin_password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
            
            # Insert Admin User
            cur.execute("""
                INSERT INTO users (username, email, password_hash, is_admin, is_approved, group_id)
                VALUES (%s, %s, %s, TRUE, TRUE, %s) RETURNING id;
            """, ('admin', 'admin@example.com', admin_password_hash, 'family-demo'))
            admin_id = cur.fetchone()['id']

            # Insert Demo Group
            cur.execute("""
                INSERT INTO groups (id, name, created_by_user_id)
                VALUES (%s, %s, %s);
            """, ('family-demo', 'Demo Family Group', admin_id))
            
            # Insert a sample asset
            cur.execute("""
                INSERT INTO assets (user_id, type, name, country, currency, value, account_no, last_updated, notes, owner, owner_id,
                                    financial_institution, beneficiary_name, policy_or_plan_type, contact_phone, document_location,
                                    investment_strategy, current_value, description, added_date, group_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s);
            """, (admin_id, "Bank Account", "Checking - Demo", "USA", "USD", 5000.00, enc("****1234"),
                  "Sample notes about this asset.", "Admin User", admin_id, enc("Demo Bank of Finance"), enc("Spouse Name"),
                  "Checking", enc("+1-800-111-2222"), enc("Locker A1"),
                  "Keep $3k buffer for emergencies.", 5000.00, "Main household account for daily spending.",
                  datetime.now().date(), "family-demo"))

            print("Database initialized successfully.", file=sys.stderr)
        else:
            print("Admin user already exists. Skipping initialization.", file=sys.stderr)

        conn.commit()
        return "Database setup complete."
    except Exception as e:
        conn.rollback()
        print(f"init_db error: {e}", file=sys.stderr)
        return f"Database initialization failed: {e}"

if __name__ == '__main__':
    # When run directly, try to initialize the database
    print(init_db(), file=sys.stderr)
