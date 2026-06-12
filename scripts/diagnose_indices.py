# diagnose_indices.py
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

def check_for_plaintext(b_stream, context_label):
    if not b_stream: return False
    # Check if the decrypted stream contains highly printable ASCII text
    printable = sum(1 for x in b_stream if 32 <= x <= 126 or x in (9, 10, 13))
    ratio = printable / len(b_stream)
    if ratio > 0.75:
        print(f"🎉 SUCCESS! Found matching pattern!")
        print(f"🛠️  Configuration: {context_label}")
        print(f"👉 Plaintext: {b_stream.decode('utf-8', errors='ignore')[:150]}\n")
        return True
    return False

# 1. Fetch live page 1 data
headers = {"Authorization": f"Bearer {API_KEY}"}
res = requests.get(URL, headers=headers)
etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
master_key_bytes = bytes.fromhex(etag)
records = res.json().get("data", [])

print(f"📡 Master Page Key: {etag[:10]}...")
print(f"📦 Processing index-diversification sweep across first 2 records...\n")

# Sweep through the first couple of records to find the structural pattern
for idx in range(min(2, len(records))):
    ct_bytes = base64.b64decode(records[idx])
    
    # Generate variations of the index as bytes
    idx_bytes_4_big = idx.to_bytes(4, byteorder='big')
    idx_bytes_16_big = idx.to_bytes(16, byteorder='big')
    idx_str_bytes = str(idx).encode()
    
    # Generate an MD5 hash of the index (exactly 16 bytes - very common for IVs)
    idx_md5 = hashlib.md5(idx_str_bytes).digest()
    idx_sha256_12 = hashlib.sha256(idx_str_bytes).digest()[:12]

    # -----------------------------------------------------------------
    # HYPOTHESIS 1: ETag is Key, IV/Nonce is derived from the Record Index
    # -----------------------------------------------------------------
    
    # Test CBC Mode with Index-based IVs
    for iv_name, iv_bytes in [("MD5 of Index String", idx_md5), ("Padded 16B Integer", idx_bytes_16_big)]:
        try:
            dec = AES.new(master_key_bytes, AES.MODE_CBC, iv=iv_bytes).decrypt(ct_bytes)
            if check_for_plaintext(dec, f"Record [{idx}] -> AES-CBC | IV: {iv_name}"): exit()
        except: pass

    # Test CTR Mode with Index-based Nonces
    for nonce_name, nonce_bytes in [("4B Big Endian", idx_bytes_4_big), ("String Bytes", idx_str_bytes.zfill(8))]:
        try:
            # PyCryptodome CTR mode expects an 8-byte nonce or explicit counter
            dec = AES.new(master_key_bytes, AES.MODE_CTR, nonce=nonce_bytes[:8].zfill(8)).decrypt(ct_bytes)
            if check_for_plaintext(dec, f"Record [{idx}] -> AES-CTR | Nonce: {nonce_name}"): exit()
        except: pass

    # Test GCM Mode with Index-based Nonces
    for nonce_name, nonce_bytes in [("SHA256-truncated 12B", idx_sha256_12), ("String Bytes 12B", idx_str_bytes.zfill(12))]:
        try:
            # Separate ciphertext and standard trailing 16B authentication tag
            dec = AES.new(master_key_bytes, AES.MODE_GCM, nonce=nonce_bytes).decrypt(ct_bytes[:-16])
            if check_for_plaintext(dec, f"Record [{idx}] -> AES-GCM (No Tag Check) | Nonce: {nonce_name}"): exit()
        except: pass

    # Test CFB Mode (Stream-like block mode variant)
    try:
        dec = AES.new(master_key_bytes, AES.MODE_CFB, iv=idx_md5, segment_size=128).decrypt(ct_bytes)
        if check_for_plaintext(dec, f"Record [{idx}] -> AES-CFB-128 | IV: MD5(Index)"): exit()
    except: pass


    # -----------------------------------------------------------------
    # HYPOTHESIS 2: Key itself is derived from ETag + Record Index
    # -----------------------------------------------------------------
    
    # Common Key Derivation: SHA256(Master Key Bytes + Index Bytes)
    derived_key_1 = hashlib.sha256(master_key_bytes + idx_bytes_4_big).digest()
    derived_key_2 = hashlib.sha256(master_key_bytes + idx_str_bytes).digest()
    
    for k_name, derived_key in [("SHA256(Key + Int-Idx)", derived_key_1), ("SHA256(Key + Str-Idx)", derived_key_2)]:
        # Test standard Zero-IV CBC with the newly derived unique key
        try:
            dec = AES.new(derived_key, AES.MODE_CBC, iv=b'\x00'*16).decrypt(ct_bytes)
            if check_for_plaintext(dec, f"Record [{idx}] -> AES-CBC (Zero-IV) | Derived Key: {k_name}"): exit()
        except: pass
        
        # Test standard ECB with the newly derived unique key
        try:
            dec = AES.new(derived_key, AES.MODE_ECB).decrypt(ct_bytes)
            if check_for_plaintext(dec, f"Record [{idx}] -> AES-ECB | Derived Key: {k_name}"): exit()
        except: pass

print("❌ Index rotation sweep finished. No direct textual alignment matched.")