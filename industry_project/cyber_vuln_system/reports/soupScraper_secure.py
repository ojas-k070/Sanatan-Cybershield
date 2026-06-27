import os
import time
import hashlib
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from PIL import Image
import requests
from databaseManager import addPair

url = "https://www.brut.media/in"
storage = "NewsStorage/images"
os.makedirs(storage, exist_ok=True)

options = Options()
# options.headless = True  # Set False to see Chrome UI during development
# For production, headless is generally preferred
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

driver = webdriver.Chrome(options=options)

try:
    driver.get(url)
    # Use explicit wait for a key element to ensure page is loaded
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.TAG_NAME, "body"))
    )

    # Scroll down multiple times to load more media
    # A more robust approach might involve checking for new content or scrolling to the bottom
    for _ in range(10):
        driver.find_element(By.TAG_NAME, "body").send_keys(Keys.PAGE_DOWN)
        time.sleep(1.5) # Still using sleep here, but explicit waits for elements are better

    media_cards = driver.find_elements(By.CSS_SELECTOR, "article, div[data-testid]")

    def hash_image(path):
        try:
            with Image.open(path) as img:
                img = img.convert('RGB').resize((128,128))
                # Use SHA-256 for stronger hashing
                return hashlib.sha256(img.tobytes()).hexdigest()
        except Exception as e:
            print(f"Error hashing image {path}: {e}")
            return None

    observed_hashes = set()
    image_count = 0

    for card in media_cards:
        try:
            img_elem = card.find_element(By.TAG_NAME, "img")
            img_url = img_elem.get_attribute("src") or img_elem.get_attribute("data-src")
            if not img_url:
                continue

            # Extract caption from first p, h2, or span inside media card
            try:
                caption_element = card.find_element(By.CSS_SELECTOR, "p, h2, span")
                caption = caption_element.text.strip()
            except:
                caption = "No caption"
            if not caption:
                caption = "No caption"

            # Download image
            image_filename = f"brut_img_{image_count}.jpg"
            image_path = os.path.join(storage, image_filename)
            try:
                response = requests.get(img_url, timeout=10)
                response.raise_for_status() # Raise an exception for bad status codes
                img_data = response.content
                with open(image_path, "wb") as f:
                    f.write(img_data)
            except requests.exceptions.RequestException as e:
                print(f"Error downloading image {img_url}: {e}")
                continue

            # Hash the image for deduplication
            h = hash_image(image_path)
            if h is None:
                os.remove(image_path) # Clean up partially downloaded or unhashable image
                continue

            if h in observed_hashes:
                os.remove(image_path)
                continue
            observed_hashes.add(h)

            # Save path and caption to DB
            addPair(image_path, caption)

            print(f"Saved entry #{image_count + 1}: hash={h}")
            print(f"Caption: {caption}")
            print(f"Image path: {image_path}\n")

            image_count += 1
            time.sleep(1) # Consider removing or reducing this sleep if not strictly necessary
        except Exception as e:
            # Catching specific exceptions is better, but for broad coverage, this is a fallback
            print(f"Error processing entry #{image_count + 1}: {e}")

    print("Scraping complete.")

finally:
    driver.quit()
