# solve_advanced_structures.py
import json
import base64
import hmac
import hashlib
from Crypto.Cipher import AES

CACHE_FILE = "harvested_dataset.json"

def check_text(b_stream, page, record_idx, mode_label):
    if not b_stream: return False
    printable = sum(1 for x in b_stream if 32 <= x <= 126 or x in (9, 10, 13))
    ratio = printable / len(b_stream)
    if ratio > 0.80:
        print(f"\n🎉 CRACKED! Match found on Page {page}, Record {record_idx}!")
        print(f"🛠️  Strategy: {mode_label}")
        print(f"👉 Plaintext: {b_stream.decode('utf-8', errors='ignore')[:200]}\n")
        return True
    return False

with open(CACHE_FILE, "r") as f:
    data_matrix = json.load(f)

print(f"📂 Loaded cache. Scanning 500 records for advanced structures...")
found = False

for page_str, content in data_matrix.items():
    if found: break
    etag_hex = content["etag"]
    master_key = bytes.fromhex(etag_hex)
    
    for idx, record_b64 in enumerate(content["records"]):
        ct_bytes = base64.b64decode(record_b64)
        
        # -----------------------------------------------------------------
        # TWIST 1: Inline IV Per Record (First 16B = IV, next 240B = Ciphertext)
        # -----------------------------------------------------------------
        if len(ct_bytes) == 256:
            inline_iv = ct_bytes[:16]
            actual_ciphertext = ct_bytes[16:]
            
            try:
                dec = AES.new(master_key, AES.MODE_CBC, iv=inline_iv).decrypt(actual_ciphertext)
                if check_text(dec, page_str, idx, "Inline IV (First 16 Bytes of Record) + AES-CBC"):
                    found = True; break
            except: pass

        # -----------------------------------------------------------------
        # TWIST 2: HMAC-SHA256 Key Derivation
        # -----------------------------------------------------------------
        # The engineer uses the ETag as an HMAC key to derive a unique key per page/record
        page_le = int(page_str).to_bytes(4, byteorder='little')
        record_le = idx.to_bytes(4, byteorder='little')
        
        # Candidate Key A: HMAC of the page number
        hk_page = hmac.new(master_key, page_le, hashlib.sha256).digest()
        # Candidate Key B: HMAC of the record index
        hk_record = hmac.new(master_key, record_le, hashlib.sha256).digest()
        # Candidate Key C: HMAC of the combined coordinates
        hk_combined = hmac.new(master_key, page_le + record_le, hashlib.sha256).digest()

        derived_keys = [
            ("HMAC-SHA256(ETag, Page)", hk_page),
            ("HMAC-SHA256(ETag, RecordIdx)", hk_record),
            ("HMAC-SHA256(ETag, Page+RecordIdx)", hk_combined)
        ]

        for key_label, d_key in derived_keys:
            # Test ECB
            try:
                dec = AES.new(d_key, AES.MODE_ECB).decrypt(ct_bytes)
                if check_text(dec, page_str, idx, f"AES-ECB via Derived Key: {key_label}"):
                    found = True; break
            except: pass
            
            # Test CBC with Zero IV
            try:
                dec = AES.new(d_key, AES.MODE_CBC, iv=b'\x00'*16).decrypt(ct_bytes)
                if check_text(dec, page_str, idx, f"AES-CBC (Zero IV) via Derived Key: {key_label}"):
                    found = True; break
            except: pass

if not found:
    print("❌ Advanced structural sweep completed. No hits.")