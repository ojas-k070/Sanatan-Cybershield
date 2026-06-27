import sqlite3
import os

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # FIX: Use parameterized queries to prevent SQL Injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # FIX: Load password from a secure external source (e.g., environment variable, secrets manager)
    # For demonstration, we'll assume it's loaded securely:
    # admin_pass = os.environ.get('ADMIN_PASSWORD') 
    # Or from a config file, etc.
    # The hardcoded password has been removed.
    
    user_data = cursor.fetchone()
    db.close()
    return user_data

# Example of how to load admin_pass securely (requires 'os' import)
# admin_pass = os.environ.get('ADMIN_PASSWORD')
# if not admin_pass:
#     print("Error: ADMIN_PASSWORD environment variable not set.")
#     # Handle error appropriately, e.g., exit or raise exception