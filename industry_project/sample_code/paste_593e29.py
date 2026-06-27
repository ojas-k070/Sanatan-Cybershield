import sqlite3

def unsafe_login(username, password):
    # Connect to an in-memory database for demonstration
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    
    # Vulnerable query construction
    # An attacker entering ' OR '1'='1 for password can bypass authentication
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        return cursor.fetchone()
    except sqlite3.OperationalError as e:
        return f"Error: {e}"
