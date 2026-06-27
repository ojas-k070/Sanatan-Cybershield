import pymysql

# Database configuration
db_config = {
    "host": "localhost",
    "user": "your_username",
    "password": "your_password",
    "database": "your_database_name",
    "charset": "utf8mb4",
    # Returns rows as dictionaries instead of tuples for easier reading
    "cursorclass": pymysql.cursors.DictCursor,
}

try:
    # Establish the connection using a context manager
    with pymysql.connect(**db_config) as connection:
        print("🎉 Connection successful!")

        # Create a cursor object to execute SQL statements
        with connection.cursor() as cursor:
            # 1. Example: Creating a simple table
            create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100),
                email VARCHAR(100)
            )
            """
            cursor.execute(create_table_query)

            # 2. Example: Fetching data from the table
            select_query = "SELECT id, name, email FROM users LIMIT 5"
            cursor.execute(select_query)

            # Fetch all the rows from the executed query
            rows = cursor.fetchall()

            print("\n--- User Data ---")
            if not rows:
                print("No data found, but the connection works perfectly!")
            for row in rows:
                print(f"ID: {row['id']} | Name: {row['name']} | Email: {row['email']}")

except pymysql.MySQLError as e:
    print(f"❌ Error connecting to the database: {e}")

finally:
    print("\n🔒 Database connection closed.")