import base64
import hashlib
from Crypto.Cipher import ChaCha20

# --- CONFIGURATION ---
B64_DATA = "rPeBvh2iPmUuy7SrEeAzVFwW3HJYOCNJPESJi3Y2SIFJbccEdYMQRiJu6JzUhyi+3Z29oRsWP04hzTsKYNxjsfLKgh+or9L1WUmlyntzvQzxCW78cQ3iF2pCP94IahL8GFnLRsowLNmYyCwrW6xoxU2rvq/VLSl63KXHt4xP1K85aAj8zJO1lhcDsN5oJau74HFPxlKJhWEBPKkTVgFokfvDdErHS7uySXov24NhbFMj2LxiJsqC06uGAdqZ3zytijKrtCJp2mqWj7Gdv4TjKs/cV4lEAPSmjv+Ya7BMkswE9EkYwRKVKRRbLw4LTD64EPo4aWrI1ojzByuGt5j7Hg=="
ETAG = "bd023ce37fb05e1d7f472c81374d8c7fccbec45695b54bea0d9189405f391798"
JWT = "PASTE_YOUR_JWT_HERE" # Put your full JWT string here

def derive_and_decrypt():
    # 1. Derive the Key: Hash the combination of ETag and JWT
    # We use SHA256 to ensure the key is exactly 32 bytes
    combined = (JWT + ETAG).encode('utf-8')
    derived_key = hashlib.sha256(combined).digest()
    
    ciphertext = base64.b64decode(B64_DATA)
    
    print(f"--- ATTEMPTING DERIVED KEY DECRYPTION ---")
    
    # 2. Try common nonces (since we don't know the specific IV/Nonce)
    # Most JWE or secure flows use a zero-nonce or a prefix-nonce
    possible_nonces = [b'\x00'*12, b'\x01'*12, ciphertext[:12]]
    
    for nonce in possible_nonces:
        try:
            cipher = ChaCha20.new(key=derived_key, nonce=nonce)
            decrypted = cipher.decrypt(ciphertext)
            
            # Check for JSON start
            if decrypted.startswith(b'{') or decrypted.startswith(b'['):
                print(f"🎉 FOUND MATCH with nonce {nonce.hex()}")
                print(f"Result: {decrypted[:100]}")
                return
        except Exception as e:
            continue

    print("❌ Derived key attempt failed.")

derive_and_decrypt()