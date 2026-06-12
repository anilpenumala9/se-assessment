import json
import base64
import os
import zlib
import gzip
from Crypto.Cipher import ChaCha20

def try_decompress(data):
    """Attempt to decompress data using common formats."""
    # Attempt 1: Zlib
    try:
        return zlib.decompress(data), "zlib"
    except:
        pass
    # Attempt 2: Gzip
    try:
        return gzip.decompress(data), "gzip"
    except:
        pass
    # If no compression found, return raw data
    return data, "none"

def decrypt_and_decompress(dataset_file):
    with open(dataset_file, "r") as f:
        data = json.load(f)

    if not os.path.exists("recovered_data"):
        os.makedirs("recovered_data")

    for page_num, content in data.items():
        etag_hex = content["etag"]
        key = bytes.fromhex(etag_hex)
        
        for idx, b64_rec in enumerate(content["records"]):
            try:
                # 1. Decrypt
                ciphertext = base64.b64decode(b64_rec)
                nonce = key[:8] + idx.to_bytes(4, byteorder='big')
                cipher = ChaCha20.new(key=key, nonce=nonce)
                decrypted_bytes = cipher.decrypt(ciphertext)
                
                # 2. Decompress
                final_data, method = try_decompress(decrypted_bytes)
                
                # 3. Save if it looks like JSON or text
                # We check for '{' or '[' (JSON start) or if it's readable text
                if final_data.startswith((b'{', b'[')):
                    file_path = f"recovered_data/page_{page_num}_rec_{idx}.json"
                    with open(file_path, "wb") as out:
                        out.write(final_data)
                    print(f"✅ Saved: {file_path} (Method: {method})")
                    
            except Exception:
                continue

decrypt_and_decompress("harvested_dataset.json")
print("--- DECRYPTION COMPLETE ---")