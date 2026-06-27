import sqlite3
import os

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # FIX: Use parameterized queries to prevent SQL Injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # FIX: Load credentials from a secure external source (e.g., environment variable, secrets manager)
    # For demonstration purposes, we'll omit the hardcoded password here.
    # admin_pass = os.environ.get('ADMIN_PASSWORD') # Example using environment variable
    
    return cursor.fetchone()