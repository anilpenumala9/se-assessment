import json
import base64
from Crypto.Cipher import AES, ChaCha20
from hashlib import sha256

# YOUR API KEY GOES HERE
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b" 

def test_decryption(key, ciphertext, mode_type, nonce=None):
    try:
        if mode_type == "AES-GCM":
            # GCM expects 12-byte nonce. We use the ETag for this.
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce[:12])
            return cipher.decrypt(ciphertext)
        elif mode_type == "ChaCha20":
            # ChaCha20 expects 12-byte nonce.
            cipher = ChaCha20.new(key=key, nonce=nonce[:12])
            return cipher.decrypt(ciphertext)
    except:
        return None
    return None

with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

# Focus: Page 1, Record 2
page_data = data["1"]
ciphertext = base64.b64decode(page_data["records"][2])
etag_bytes = bytes.fromhex(page_data["etag"])
api_key_bytes = sha256(API_KEY.encode()).digest() # Standardizing API Key to 32 bytes

print("🚀 Scanning for algorithm signatures...")

# We will test combinations of Key and Nonce
key_candidates = [api_key_bytes, etag_bytes, sha256(api_key_bytes + etag_bytes).digest()]
nonce_candidates = [etag_bytes, api_key_bytes]

for k in key_candidates:
    for n in nonce_candidates:
        # 1. Test AES-GCM
        res = test_decryption(k, ciphertext, "AES-GCM", nonce=n)
        if res and any(c in res for c in [b'{', b'flag', b'CTF']):
            print(f"🎉 FOUND AES-GCM! Key: {k.hex()[:8]}...")
            print(f"Data: {res[:50]}")
            exit()
            
        # 2. Test ChaCha20
        res = test_decryption(k, ciphertext, "ChaCha20", nonce=n)
        if res and any(c in res for c in [b'{', b'flag', b'CTF']):
            print(f"🎉 FOUND ChaCha20! Key: {k.hex()[:8]}...")
            print(f"Data: {res[:50]}")
            exit()

print("❌ Still nothing. The key is likely a derivation of ETag + API_KEY.")