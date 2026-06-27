import sqlite3

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # VULNERABILITY 1: SQL Injection
    # An attacker could enter "' OR '1'='1" to see all users
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

    # VULNERABILITY 2: Hardcoded Password
    # Credentials should never be in the source code
    admin_pass = "Admin_Login_2026_Secure!"
    
    return cursor.fetchone()