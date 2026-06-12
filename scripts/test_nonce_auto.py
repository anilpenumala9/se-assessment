import json
import base64
from Crypto.Cipher import ChaCha20

def test_nonce_auto(page, record_idx):
    # 1. Load the original dataset
    with open("harvested_dataset.json", "r") as f:
        data = json.load(f)

    # 2. Extract the ETag and the Base64 string automatically
    etag_hex = data[str(page)]["etag"]
    b64_string = data[str(page)]["records"][record_idx]
    
    key = bytes.fromhex(etag_hex)
    ciphertext = base64.b64decode(b64_string)
    
    print(f"--- TESTING STRATEGIES FOR PAGE {page}, REC {record_idx} ---")
    
    # Nonce strategies
    strategies = {
        "1. ETag[:12]": key[:12],
        "2. Counter(12 bytes)": record_idx.to_bytes(12, 'big'),
        "3. ETag[:8] + Counter": key[:8] + record_idx.to_bytes(4, 'big'),
        "4. Counter + ETag[8:16]": record_idx.to_bytes(4, 'big') + key[8:12],
    }
    
    for name, nonce in strategies.items():
        try:
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
            
            # Print first 50 bytes. We are looking for something that is NOT garbage.
            print(f"{name}: {decrypted[:50]}")
        except Exception:
            print(f"{name}: Failed")

# Run it for your problematic record
test_nonce_auto(page=11, record_idx=19)