import sqlite3

def get_user_data(user_id):
    db = sqlite3.connect("users.db")
    cursor = db.cursor()

    # Use parameterized queries to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    # Retrieve admin password from a secure source (e.g., environment variable or secrets manager)
    # For demonstration purposes, this is a placeholder and should be replaced with a secure method.
    # admin_pass = os.environ.get('ADMIN_PASSWORD') # Example using environment variable
    # if not admin_pass:
    #     raise ValueError("Admin password not configured securely.")

    return cursor.fetchone()