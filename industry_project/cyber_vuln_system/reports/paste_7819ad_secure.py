import sqlite3

def safe_login(username, password):
    # Connect to an in-memory database for demonstration
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    # Secure query construction using parameterized queries
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    
    try:
        cursor.execute(query, (username, password))
        return cursor.fetchone()
    except sqlite3.OperationalError as e:
        return f"Error: {e}"