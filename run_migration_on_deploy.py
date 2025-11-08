import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
from cryptography.fernet import Fernet
from tqdm import tqdm # Library for progress bars (install with pip install tqdm)

# --- CONFIGURATION ---
DATABASE_URL = os.environ.get('DATABASE_URL') 
FERNET_KEY = os.environ.get('FERNET_KEY')

# --- ENCRYPTOR IMPLEMENTATION (Copied from app.py) ---
class Encryptor:
    def __init__(self, key):
        if not key:
            raise ValueError("Encryption key cannot be empty.")
        self.f = Fernet(key)

    def encrypt(self, data):
        if data is None or data == '':
            return None
        return self.f.encrypt(str(data).encode()).decode()

    # NOTE: Decrypt function is NOT strictly needed for migration, 
    # but included for completeness. The focus is on encrypting the plain text.
    def decrypt(self, data):
        if data is None or data == '':
            return ''
        try:
            return self.f.decrypt(data.encode()).decode()
        except Exception:
            # If decryption fails, assume it was unencrypted plain text (or bad token)
            return data

# Initialize Encryptor
if not FERNET_KEY:
    print("FATAL ERROR: FERNET_KEY environment variable not found. Cannot encrypt data.", file=sys.stderr)
    sys.exit(1)
try:
    ENCRYPTOR = Encryptor(FERNET_KEY.encode())
except Exception as e:
    print(f"FATAL ERROR: Failed to initialize Encryptor: {e}", file=sys.stderr)
    sys.exit(1)

# --- DATABASE CONNECTION & HELPERS ---
def get_db_connection():
    if not DATABASE_URL:
        raise Exception("DATABASE_URL environment variable not found.")
    return psycopg2.connect(DATABASE_URL)

def run_migration(table_name, sensitive_fields):
    """
    Fetches all unencrypted rows, encrypts the sensitive fields, 
    and updates the database.
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # 1. Select all data (we assume if it's not encrypted, it's plaintext)
        cur.execute(f"SELECT id, {', '.join(sensitive_fields)} FROM {table_name};")
        records = cur.fetchall()
        
        if not records:
            print(f"✅ No records found in '{table_name}'. Skipping migration.")
            return

        print(f"\n⏳ Starting migration for {len(records)} records in '{table_name}'...")
        
        # 2. Process each record
        for record in tqdm(records, desc=f"Encrypting {table_name}"):
            record_id = record['id']
            updates = {}
            needs_update = False
            
            # Encrypt sensitive fields
            for field in sensitive_fields:
                value = record.get(field)
                if value:
                    # Check if the data is already encrypted (simple check: if it looks like Fernet data)
                    # NOTE: Fernet tokens always start with 'g' and contain two periods.
                    if isinstance(value, str) and value.startswith('g') and value.count('.') == 2:
                        updates[field] = value # Data is likely already encrypted, skip
                    else:
                        updates[field] = ENCRYPTOR.encrypt(value)
                        needs_update = True
                else:
                    updates[field] = None # Ensure None/empty strings remain None

            # 3. Update the record if needed
            if needs_update:
                set_clause = ', '.join([f"{field} = %s" for field in sensitive_fields])
                update_query = f"UPDATE {table_name} SET {set_clause} WHERE id = %s;"
                
                params = [updates[field] for field in sensitive_fields] + [record_id]
                
                with conn.cursor() as update_cur:
                    update_cur.execute(update_query, params)
        
        # 4. Commit all changes
        conn.commit()
        print(f"✅ Migration for '{table_name}' completed. All fields are now encrypted.")

    except Exception as e:
        if conn: conn.rollback()
        print(f"\n❌ FATAL ERROR during {table_name} migration: {e}", file=sys.stderr)
    finally:
        if conn: conn.close()

if __name__ == '__main__':
    # Fields to be encrypted in the ASSETS table
    ASSET_FIELDS = [
        'name', 'account_no', 'notes', 'financial_institution', 'beneficiary_name', 
        'policy_or_plan_type', 'contact_phone', 'document_location', 'investment_strategy'
    ]

    # Fields to be encrypted in the EXPENSES table
    EXPENSE_FIELDS = [
        'description', 'notes'
    ]

    print("--- Starting Database Encryption Migration ---")
    
    run_migration('assets', ASSET_FIELDS)
    run_migration('expenses', EXPENSE_FIELDS)

    print("\n--- Migration Complete. Your data is now encrypted. ---")
