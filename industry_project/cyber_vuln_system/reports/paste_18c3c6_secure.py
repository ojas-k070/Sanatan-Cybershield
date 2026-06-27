import sqlite3

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # Use parameterized queries to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # Store sensitive credentials securely, e.g., using environment variables or a secrets manager
    # admin_pass = os.environ.get('ADMIN_PASSWORD') # Example using environment variable
    # For demonstration purposes, the hardcoded password is removed.

    return cursor.fetchone()