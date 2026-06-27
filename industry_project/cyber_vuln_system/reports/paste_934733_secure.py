import sqlite3

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # VULNERABILITY 1: SQL Injection
    # An attacker could enter "' OR '1'='1" to see all users
    # query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # VULNERABILITY 2: Hardcoded Password
    # Credentials should never be in the source code
    # admin_pass = "Admin_Login_2026_Secure!"
    # Retrieve admin_pass from a secure source like environment variables or a secrets manager
    admin_pass = os.environ.get('ADMIN_PASSWORD') # Example using environment variable
    if not admin_pass:
        # Handle the case where the password is not found
        print("Error: Admin password not configured.")
        return None

    return cursor.fetchone()