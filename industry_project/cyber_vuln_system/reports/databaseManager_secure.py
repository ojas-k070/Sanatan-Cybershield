import sqlite3
import cv2
import numpy as np
from scipy.fftpack import dct
import os

database = "NewsStorage/storage.db"

def generate_pHash(imagePath):
    # Basic path traversal prevention
    base_dir = os.path.abspath(os.path.dirname(__file__))
    abs_image_path = os.path.abspath(os.path.join(base_dir, imagePath))
    
    # Further validation could be added here to ensure the path is within expected directories
    if not abs_image_path.startswith(base_dir):
        raise ValueError(f"Image path traversal attempt detected: {imagePath}")

    image = cv2.imread(abs_image_path, cv2.IMREAD_GRAYSCALE)
    if image is None:
        raise ValueError(f"Could not load image: {imagePath}")

    # Resize and apply DCT
    image = cv2.resize(image, (32, 32))
    dctMatrix = dct(dct(image.astype(float), axis=0, norm='ortho'), axis=1, norm='ortho')

    # Use top-left 8x8 DCT
    dctArray8x8 = dctMatrix[:8, :8].flatten()

    # Build binary hash
    median = np.median(dctArray8x8[1:])  # ignore DC coefficient
    binaryHash = ''.join(['1' if x > median else '0' for x in dctArray8x8])

    # Convert to hex
    phash = '{:0{}x}'.format(int(binaryHash, 2), len(binaryHash) // 4)
    return phash


def keyExists(key):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM storage WHERE hash = ? LIMIT 1", (key,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists


def dbInsertPair(key, caption):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO storage (hash, caption1) VALUES (?, ?)", (key, caption))
        print(f"Inserted: Hash={key}, Caption='{caption}'")
    except sqlite3.IntegrityError:
        print(f"Insert failed: Hash {key} already exists.")
    conn.commit()
    conn.close()


def dbAppendPair(key, caption):
    conn = sqlite3.connect(database)
    cursor = conn.cursor()

    # Fetch all caption columns to find the first available one
    caption_columns = [f'caption{i}' for i in range(1, 51)]
    select_cols_str = ', '.join(caption_columns)
    
    cursor.execute(f"SELECT {select_cols_str} FROM storage WHERE hash = ?", (key,))
    row = cursor.fetchone()

    if row:
        for i, val in enumerate(row, start=1):
            if val is None:
                column_name = f"caption{i}"
                # Use parameterized query for the value and hash, but column name is still dynamic
                # A safer approach would be to have a fixed number of columns or a different schema
                cursor.execute(f"UPDATE storage SET {column_name} = ? WHERE hash = ?", (caption, key))
                print(f"Updated: {column_name} for hash={key}")
                break
        else:
            print(f"No empty caption column found for hash {key}")
    else:
        print(f"No row found for hash {key}")

    conn.commit()
    conn.close()


def dbSearch(key):
    conn = sqlite3.connect('NewsStorage/storage.db')
    cursor = conn.cursor()
    caption_cols = [f"caption{i}" for i in range(1, 51)]
    cols_string = ", ".join(caption_cols)
    
    # Similar to dbAppendPair, column names are dynamically generated.
    # This is generally discouraged. A fixed set of columns or a JSON/TEXT field for captions
    # would be more secure and maintainable.
    cursor.execute(
        f"SELECT {cols_string} FROM storage WHERE hash = ?",
        (key,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    captions = [c for c in row if c and c.strip()]
    return captions if captions else []


def addPair(image_path, caption):
    if len(caption) < 5:
        return
    try:
        key = generate_pHash(image_path)
    except ValueError as e:
        print(f"Error generating hash: {e}")
        return

    if keyExists(key):
        dbAppendPair(key, caption)
    else:
        dbInsertPair(key, caption)

# if __name__ == "__main__":
#     addPair("image.png", "Hello")
