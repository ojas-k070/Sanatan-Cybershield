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
    # import os
    # admin_pass = os.environ.get("ADMIN_PASSWORD")
    # For demonstration, we'll omit it or use a placeholder if not strictly needed for this function's logic
    # admin_pass = "REPLACE_WITH_SECURE_LOADING_METHOD"
    
    return cursor.fetchone()