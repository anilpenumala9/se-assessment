import json
import base64
import os
from Crypto.Cipher import ChaCha20

# --- CONFIGURATION ---
DATA_FILE = "harvested_dataset.json"
OUTPUT_DIR = "recovered_data"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def decrypt_record(ciphertext, etag_hex, record_index):
    """
    Uses the page's ETag as the 32-byte key and 
    constructs the nonce using the first 8 bytes of the ETag + record index.
    """
    # Use the page ETag as the KEY
    key_bytes = bytes.fromhex(etag_hex)
    
    # Construct 12-byte nonce: first 8 bytes of ETag + 4-byte record index
    nonce = key_bytes[:8] + record_index.to_bytes(4, byteorder='big')
    
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    return cipher.decrypt(ciphertext)

def main():
    if not os.path.exists(DATA_FILE):
        print(f"❌ ERROR: {DATA_FILE} not found. Please place it in this directory.")
        return

    with open(DATA_FILE, "r") as f:
        data = json.load(f)

    print(f"🚀 Starting decryption using Page ETags as keys...")

    for page_num, content in data.items():
        page_etag = content.get("etag")
        if not page_etag:
            continue
            
        print(f"Processing Page {page_num}...")
        
        for idx, b64_rec in enumerate(content["records"]):
            try:
                ciphertext = base64.b64decode(b64_rec)
                decrypted_bytes = decrypt_record(ciphertext, page_etag, idx)
                
                # Check for standard JSON structure markers (JSON typically starts with { or [)
                if decrypted_bytes.startswith(b'{') or decrypted_bytes.startswith(b'['):
                    file_path = os.path.join(OUTPUT_DIR, f"page_{page_num}_rec_{idx}.json")
                    with open(file_path, "wb") as out:
                        out.write(decrypted_bytes)
                    print(f"  ✅ Saved: {file_path}")
            
            except Exception:
                # If decryption fails (e.g., incorrect key/nonce), skip this record
                continue

    print("--- FINISHED ---")

if __name__ == "__main__":
    main()