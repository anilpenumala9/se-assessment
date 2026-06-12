import json
import base64
import zlib
import gzip
from Crypto.Cipher import ChaCha20

# 1. Configuration (Use the values that worked for you)
# The key and nonce found in your previous successful run
KEY = bytes.fromhex("ed082ffa611e73a171401d3e7e9b0645bde1d04d7181c6015f4b407f85bc1141") 
NONCE = bytes.fromhex("ed082ffa611e73a171401d3e")[:12] # ChaCha20 uses 12-byte nonce

def try_decompress(data):
    """Attempts to identify and decompress binary data."""
    # Test Zlib
    try:
        return zlib.decompress(data), "Zlib"
    except: pass
    
    # Test Gzip
    try:
        return gzip.decompress(data), "Gzip"
    except: pass
    
    # Test Raw (Maybe it's just raw JSON text)
    try:
        return data.decode('utf-8'), "RawText"
    except: pass
    
    return None, None

# Load the harvested data
with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

print("🚀 Starting full-scale extraction and decompression...")

for page_num, content in data.items():
    for idx, b64_rec in enumerate(content["records"]):
        ciphertext = base64.b64decode(b64_rec)
        
        # 1. Decrypt
        cipher = ChaCha20.new(key=KEY, nonce=NONCE)
        decrypted_bytes = cipher.decrypt(ciphertext)
        
        # 2. Decompress
        payload, p_type = try_decompress(decrypted_bytes)
        
        # 3. Check for readable results
        if payload and ("{" in str(payload) or "flag" in str(payload) or "CTF" in str(payload)):
            print(f"🎉 FOUND DATA! Page {page_num}, Record {idx} | Format: {p_type}")
            print(f"👉 Payload Snippet: {str(payload)[:200]}")
            
            # Save the successful file
            with open(f"recovered_p{page_num}_r{idx}.txt", "w") as out:
                out.write(str(payload))
            break