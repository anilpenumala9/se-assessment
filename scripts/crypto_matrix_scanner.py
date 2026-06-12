# crypto_matrix_scanner.py
import requests
import base64
import hashlib
from Crypto.Cipher import AES

# =====================================================================
# CONFIGURATION
# =====================================================================
URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset?page=1"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# =====================================================================

def is_readable_plaintext(b_stream):
    """Returns True if the bytes look like readable text (JSON/ASCII)."""
    if not b_stream:
        return False
    # Count printable ASCII chars, tabs, newlines, carriage returns
    text_chars = sum(1 for x in b_stream if 32 <= x <= 126 or x in (9, 10, 13))
    ratio = text_chars / len(b_stream)
    return ratio > 0.75

# 1. Fetch live page 1 assets
headers = {"Authorization": f"Bearer {API_KEY}"}
res = requests.get(URL, headers=headers)
if res.status_code != 200:
    print(f"❌ HTTP Error {res.status_code}")
    exit()

raw_etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
first_record_b64 = res.json().get("data", [])[0]
raw_payload = base64.b64decode(first_record_b64)

print("📡 Assets loaded. Generating key candidates...")

# 2. Build out all plausible key combinations (Must be exactly 32 bytes for AES-256)
keys = {}
if len(raw_etag) == 64:
    try: keys["ETag parsed as Hex Bytes"] = bytes.fromhex(raw_etag)
    except: pass
keys["SHA-256 Hash of ETag String"] = hashlib.sha256(raw_etag.encode()).digest()
keys["SHA-256 Hash of Raw API Key"] = hashlib.sha256(API_KEY.encode()).digest()
if len(API_KEY) >= 32:
    keys["First 32 Bytes of Raw API Key"] = API_KEY.encode()[:32]

print(f"🔑 Loaded {len(keys)} distinct 32-byte key candidates.")
print(f"📦 Payload size: {len(raw_payload)} bytes. Beginning cross-matrix sweep...\n")

success_found = False

# 3. Sweep the matrix
for key_name, key_bytes in keys.items():
    
    # --- MODE 1: AES-ECB ---
    try:
        dec = AES.new(key_bytes, AES.MODE_ECB).decrypt(raw_payload)
        if is_readable_plaintext(dec):
            print(f"🎉 FOUND SUCCESS CONTEXT!\n🔑 Key: {key_name}\n🛠️ Mode: AES-256-ECB\n📝 Plaintext sample: {dec[:80]}")
            success_found = True; break
    except: pass

    # --- MODE 2: AES-CBC (Zero IV) ---
    try:
        dec = AES.new(key_bytes, AES.MODE_CBC, iv=b'\x00'*16).decrypt(raw_payload)
        if is_readable_plaintext(dec):
            print(f"🎉 FOUND SUCCESS CONTEXT!\n🔑 Key: {key_name}\n🛠️ Mode: AES-256-CBC with Zero-IV\n📝 Plaintext sample: {dec[:80]}")
            success_found = True; break
    except: pass

    # --- MODE 3: AES-CBC (Inline IV - First 16 bytes) ---
    try:
        if len(raw_payload) > 16:
            dec = AES.new(key_bytes, AES.MODE_CBC, iv=raw_payload[:16]).decrypt(raw_payload[16:])
            if is_readable_plaintext(dec):
                print(f"🎉 FOUND SUCCESS CONTEXT!\n🔑 Key: {key_name}\n🛠️ Mode: AES-256-CBC with Inline-IV\n📝 Plaintext sample: {dec[:80]}")
                success_found = True; break
    except: pass

    # --- MODE 4: AES-CTR (Zero Nonce) ---
    try:
        dec = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8).decrypt(raw_payload)
        if is_readable_plaintext(dec):
            print(f"🎉 FOUND SUCCESS CONTEXT!\n🔑 Key: {key_name}\n🛠️ Mode: AES-256-CTR (Zero Nonce)\n📝 Plaintext sample: {dec[:80]}")
            success_found = True; break
    except: pass

    # --- MODE 5: AES-GCM (Inline Nonce, No Tag validation check) ---
    # Testing if first 12 bytes is Nonce, or last 12 bytes is Nonce
    try:
        if len(raw_payload) > 12:
            dec = AES.new(key_bytes, AES.MODE_GCM, nonce=raw_payload[:12]).decrypt(raw_payload[12:])
            if is_readable_plaintext(dec):
                print(f"🎉 FOUND SUCCESS CONTEXT!\n🔑 Key: {key_name}\n🛠️ Mode: AES-256-GCM (First 12B Nonce, No Tag Check)\n📝 Plaintext sample: {dec[:80]}")
                success_found = True; break
                
            dec = AES.new(key_bytes, AES.MODE_GCM, nonce=raw_payload[:12]).decrypt(raw_payload[12:-16])
            if is_readable_plaintext(dec):
                print(f"🎉 FOUND SUCCESS CONTEXT!\n🔑 Key: {key_name}\n🛠️ Mode: AES-256-GCM (First 12B Nonce + Last 16B Tag)\n📝 Plaintext sample: {dec[:80]}")
                success_found = True; break
    except: pass

if not success_found:
    print("❌ Matrix sweep complete. No straightforward text alignment found.")
    print("👉 Double-check: Did the page data contain any sub-arrays, or is the text completely unpadded?")