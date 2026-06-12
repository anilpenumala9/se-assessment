# diagnose_stream.py
import requests
import base64
import hashlib
from Crypto.Cipher import AES, ChaCha20

# =====================================================================
# CONFIGURATION
# =====================================================================
URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset?page=1"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."
# =====================================================================

headers = {"Authorization": f"Bearer {API_KEY}"}
res = requests.get(URL, headers=headers)
etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
key_bytes = bytes.fromhex(etag)
first_record_b64 = res.json().get("data", [])[0]
ct_bytes = base64.b64decode(first_record_b64)

print(f"📡 Evaluating Page 1 Data Payload ({len(ct_bytes)} bytes)...")
print("-" * 70)

# --- TEST 1: AES-GCM (Standard Layout: 12-byte Nonce + Ciphertext + 16-byte Tag) ---
try:
    if len(ct_bytes) > 28:
        nonce = ct_bytes[:12]
        tag = ct_bytes[-16:]
        cipher_text = ct_bytes[12:-16]
        
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        dec = cipher.decrypt_and_verify(cipher_text, tag)
        print(f"🎉 SUCCESS! Mode is AES-GCM (Inline Nonce/Tag):\n👉 {dec[:100]}\n")
except Exception as e:
    print(f"❌ Test 1 (AES-GCM Standard) Failed: {e}")

# --- TEST 2: AES-GCM (Alternate Layout: 12-byte Nonce + Ciphertext, No Tag validation) ---
try:
    if len(ct_bytes) > 12:
        nonce = ct_bytes[:12]
        cipher_text = ct_bytes[12:]
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        dec = cipher.decrypt(cipher_text)
        print(f"🔮 Test 2 Output (AES-GCM No-Tag Check):\n👉 {dec[:60]}...\n")
except Exception as e: pass

# --- TEST 3: ChaCha20 (Standard Layout: 12-byte Nonce + Ciphertext) ---
try:
    if len(ct_bytes) > 12:
        nonce = ct_bytes[:12]
        cipher_text = ct_bytes[12:]
        cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
        dec = cipher.decrypt(cipher_text)
        print(f"🔮 Test 3 Output (ChaCha20 Inline Nonce):\n👉 {dec[:60]}...\n")
except Exception as e: pass

# --- TEST 4: The Key-Swap Twist (API Key is the Cipher Key, ETag is the IV) ---
try:
    # Hash your API key string to force it into a clean 32-byte (256-bit) AES key
    derived_api_key = hashlib.sha256(API_KEY.encode()).digest()
    # Use the first 16 bytes of the ETag hex as a CBC Initialization Vector
    alt_iv = key_bytes[:16]
    
    cipher = AES.new(derived_api_key, AES.MODE_CBC, iv=alt_iv)
    dec = cipher.decrypt(ct_bytes)
    print(f"🔮 Test 4 Output (API Key as Cipher Key + ETag as IV):\n👉 {dec[:60]}...\n")
except Exception as e: pass