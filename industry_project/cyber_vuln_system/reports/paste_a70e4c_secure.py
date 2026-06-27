import sqlite3

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # FIX: Use parameterized queries to prevent SQL Injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # FIX: Remove hardcoded password. Load from secure configuration or environment variable.
    # admin_pass = "Admin_Login_2026_Secure!"
    
    return cursor.fetchone()