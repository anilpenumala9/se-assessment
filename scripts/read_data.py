import base64
import json
from Crypto.Cipher import ChaCha20

# Provided Data
B64_DATA = "rPeBvh2iPmUuy7SrEeAzVFwW3HJYOCNJPESJi3Y2SIFJbccEdYMQRiJu6JzUhyi+3Z29oRsWP04hzTsKYNxjsfLKgh+or9L1WUmlyntzvQzxCW78cQ3iF2pCP94IahL8GFnLRsowLNmYyCwrW6xoxU2rvq/VLSl63KXHt4xP1K85aAj8zJO1lhcDsN5oJau74HFPxlKJhWEBPKkTVgFokfvDdErHS7uySXov24NhbFMj2LxiJsqC06uGAdqZ3zytijKrtCJp2mqWj7Gdv4TjKs/cV4lEAPSmjv+Ya7BMkswE9EkYwRKVKRRbLw4LTD64EPo4aWrI1ojzByuGt5j7Hg=="
ETAG = "bd023ce37fb05e1d7f472c81374d8c7fccbec45695b54bea0d9189405f391798"

KEY = bytes.fromhex(ETAG)
CIPHERTEXT = base64.b64decode(B64_DATA)

def try_decrypt(nonce, label):
    try:
        cipher = ChaCha20.new(key=KEY, nonce=nonce)
        decrypted = cipher.decrypt(CIPHERTEXT)
        # Heuristic: Check if starts with JSON
        if decrypted.startswith(b'{') or decrypted.startswith(b'['):
            try:
                # Try to see if it decodes as UTF-8
                decoded = decrypted.decode('utf-8')
                print(f"🎉 FOUND MATCH: {label}")
                print(f"Content: {decoded[:100]}")
                return True
            except:
                pass
    except:
        pass
    return False

def run_brute_force():
    print("--- STARTING BRUTE FORCE DECRYPTION ---")
    
    # 1. Test counter ranges (0 to 100)
    for counter in range(101):
        for endian in ['big', 'little']:
            # Nonce 1: 8 bytes from ETag + 4 byte counter
            nonce_8 = KEY[:8] + counter.to_bytes(4, byteorder=endian)
            if try_decrypt(nonce_8, f"Nonce8-Counter{counter}-{endian}"): return
            
            # Nonce 2: 12 bytes from ETag
            nonce_12 = KEY[:12]
            if try_decrypt(nonce_12, "Nonce12-Fixed"): return

    print("--- SEARCH COMPLETE: NO VALID JSON FOUND ---")

run_brute_force()