import sqlite3

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # VULNERABILITY 1: SQL Injection
    # An attacker could enter "' OR '1'='1" to see all users
    # FIX: Use parameterized queries
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # VULNERABILITY 2: Hardcoded Password
    # Credentials should never be in the source code
    # FIX: Load password from a secure source (e.g., environment variable)
    # For demonstration, we'll omit it or use a placeholder for a secure load mechanism
    # admin_pass = os.environ.get('ADMIN_PASSWORD') # Example using environment variable
    
    return cursor.fetchone()