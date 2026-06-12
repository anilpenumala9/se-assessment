# diagnose_splits.py
import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# =====================================================================
# CONFIGURATION
# =====================================================================
URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset?page=1"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# =====================================================================

def check_text(b_stream, label):
    """Helper to catch and print cleanly if cleartext is recovered."""
    try:
        # Check if bytes are mostly readable printable ASCII characters
        printable = sum(1 for x in b_stream if 32 <= x <= 126 or x in (9, 10, 13))
        if printable / len(b_stream) > 0.8:
            print(f"🎉 SUCCESS match found via: {label}")
            print(f"👉 Plaintext: {b_stream.decode('utf-8', errors='ignore')[:120]}\n")
            return True
    except:
        pass
    return False

# Load assets
headers = {"Authorization": f"Bearer {API_KEY}"}
res = requests.get(URL, headers=headers)
etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
key_bytes = bytes.fromhex(etag)
first_record_b64 = res.json().get("data", [])[0]
ct_bytes = base64.b64decode(first_record_b64)

print(f"📡 Page 1 ETag Hex Loaded ({len(key_bytes)} bytes)")
print(f"📦 Encrypted Payload Size: {len(ct_bytes)} bytes\n")

# -----------------------------------------------------------------
# SWEEP 1: The 16/16 Combo Splits (AES-128-CBC)
# -----------------------------------------------------------------
part_A = key_bytes[:16]
part_B = key_bytes[16:]

# Strategy 1A: First half Key, Second half IV
try:
    dec = AES.new(part_A, AES.MODE_CBC, iv=part_B).decrypt(ct_bytes)
    if check_text(dec, "AES-128-CBC [Key=First 16B, IV=Last 16B] (Raw)"): exit()
    if check_text(unpad(dec, 16), "AES-128-CBC [Key=First 16B, IV=Last 16B] (Unpadded)"): exit()
except: pass

# Strategy 1B: Second half Key, First half IV
try:
    dec = AES.new(part_B, AES.MODE_CBC, iv=part_A).decrypt(ct_bytes)
    if check_text(dec, "AES-128-CBC [Key=Last 16B, IV=First 16B] (Raw)"): exit()
    if check_text(unpad(dec, 16), "AES-128-CBC [Key=Last 16B, IV=First 16B] (Unpadded)"): exit()
except: pass

# -----------------------------------------------------------------
# SWEEP 2: Page-Deterministic Nonces / IVs
# -----------------------------------------------------------------
# Padded integer nonces (big vs little endian)
nonce_big = (1).to_bytes(12, byteorder='big')
nonce_little = (1).to_bytes(12, byteorder='little')
# String-based padded nonces (e.g., b"000000000001")
nonce_str = str(1).encode().zfill(12)

gcm_nonces = [
    ("Integer Big-Endian Nonce", nonce_big),
    ("Integer Little-Endian Nonce", nonce_little),
    ("String Zfilled Nonce", nonce_str)
]

# Standard GCM layout assumption: 240 bytes ciphertext + 16 bytes tag
gcm_cipher = ct_bytes[:-16]
gcm_tag = ct_bytes[-16:]

for label, nonce in gcm_nonces:
    try:
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        dec = cipher.decrypt_and_verify(gcm_cipher, gcm_tag)
        if check_text(dec, f"AES-256-GCM [Deterministic Nonce: {label}]"): exit()
    except: pass

print("❌ Split patterns sweep complete. No direct match found.")