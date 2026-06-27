import sqlite3
import os

DB_PATH = "NewsStorage/storage.db"

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Build 50 caption columns dynamically
    caption_columns_list = [f"caption{i} TEXT" for i in range(1, 51)]
    caption_columns_sql = ", ".join(caption_columns_list)

    # Construct the CREATE TABLE statement safely
    create_table_sql = f"CREATE TABLE IF NOT EXISTS storage (hash TEXT PRIMARY KEY, {caption_columns_sql})"
    cursor.execute(create_table_sql)

    conn.commit()
    conn.close()
    print("Database created with storage table!")

if __name__ == "__main__":
    init_db()