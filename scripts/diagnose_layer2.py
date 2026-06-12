# diagnose_layer2.py
import requests
import base64
from Crypto.Cipher import AES

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

print(f"🔑 Testing Page 1 ETag Key: {etag[:10]}...")
print(f"📦 Total Binary Ciphertext Size: {len(ct_bytes)} bytes\n")

# --- TEST 1: Raw ECB (No Padding check) ---
try:
    dec = AES.new(key_bytes, AES.MODE_ECB).decrypt(ct_bytes)
    print(f"🔬 Try 1 (Raw ECB - No Padding):\n👉 {dec[:60]}...\n")
except Exception as e: print(f"❌ Try 1 Failed: {e}\n")

# --- TEST 2: Raw CBC with Null IV (No Padding check) ---
try:
    dec = AES.new(key_bytes, AES.MODE_CBC, iv=b'\x00'*16).decrypt(ct_bytes)
    print(f"🔬 Try 2 (Raw CBC Zero-IV - No Padding):\n👉 {dec[:60]}...\n")
except Exception as e: print(f"❌ Try 2 Failed: {e}\n")

# --- TEST 3: Raw CBC with Inline IV (No Padding check) ---
try:
    if len(ct_bytes) > 16:
        dec = AES.new(key_bytes, AES.MODE_CBC, iv=ct_bytes[:16]).decrypt(ct_bytes[16:])
        print(f"🔬 Try 3 (Raw CBC Inline-IV - No Padding):\n👉 {dec[:60]}...\n")
except Exception as e: print(f"❌ Try 3 Failed: {e}\n")

# --- TEST 4: AES-CTR Mode (Stream Cipher - No Padding) ---
try:
    # Testing standard CTR mode with a zeroed nonce/counter prefix
    dec = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8).decrypt(ct_bytes)
    print(f"🔬 Try 4 (AES-CTR - No Padding):\n👉 {dec[:60]}...\n")
except Exception as e: print(f"❌ Try 4 Failed: {e}\n")