# break_layer2.py
import requests
import json
import base64
import os
from Crypto.Cipher import AES

# =====================================================================
# CONFIGURATION
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."
CACHE_FILE = "harvested_dataset.json"
# =====================================================================

def harvest_all_pages():
    """Scrapes all 20 pages and maps ETags directly to their data payload."""
    if os.path.exists(CACHE_FILE):
        print(f"📦 Loading harvested data from local cache: {CACHE_FILE}")
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
            
    print("📡 Local cache not found. Starting live network harvest across 20 pages...")
    dataset = {}
    headers = {"Authorization": f"Bearer {API_KEY}"}
    
    for page in range(1, 21):
        url = f"{BASE_URL}?page={page}"
        try:
            res = requests.get(url, headers=headers)
            if res.status_code != 200:
                print(f"⚠️ Failed to fetch page {page}: HTTP {res.status_code}")
                continue
                
            etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
            records = res.json().get("data", [])
            
            if etag and records:
                dataset[str(page)] = {
                    "etag": etag,
                    "records": records
                }
                print(f"   ✅ Harvested Page {page}/20 (ETag: {etag[:8]}... | Chunks: {len(records)})")
        except Exception as e:
            print(f"❌ Error harvesting page {page}: {e}")
            
    with open(CACHE_FILE, "w") as f:
        json.dump(dataset, f, indent=4)
    print(f"💾 All pages successfully cached to {CACHE_FILE}\n")
    return dataset

def is_plaintext(b_stream):
    """Returns True if the bytes look like meaningful text."""
    if not b_stream: return False
    # Filter for printable ASCII, tabs, and line breaks
    printable = sum(1 for x in b_stream if 32 <= x <= 126 or x in (9, 10, 13))
    ratio = printable / len(b_stream)
    return ratio > 0.80

# 1. Execute Harvesting Phase
data_matrix = harvest_all_pages()

print("🎯 Starting global brute-force sweep across all 500 records...")
found_flag = False

# 2. Sweep every single record across all pages
for page_num, content in data_matrix.items():
    etag_str = content["etag"]
    
    try:
        key_bytes = bytes.fromhex(etag_str)
    except Exception:
        continue # Skip if ETag isn't clean hex
        
    for idx, record_b64 in enumerate(content["records"]):
        ct_bytes = base64.b64decode(record_b64)
        
        # --- STRATEGY A: AES-ECB (Block Independent) ---
        try:
            dec = AES.new(key_bytes, AES.MODE_ECB).decrypt(ct_bytes)
            if is_plaintext(dec):
                print(f"\n🎉 CRACKED! Found valid data in Page {page_num}, Record Index {idx}!")
                print(f"🛠️  Cipher: AES-256-ECB")
                print(f"👉 Decrypted: {dec.decode('utf-8', errors='ignore')}\n")
                found_flag = True; break
        except: pass

        # --- STRATEGY B: AES-CBC (Zero IV Variant) ---
        try:
            dec = AES.new(key_bytes, AES.MODE_CBC, iv=b'\x00'*16).decrypt(ct_bytes)
            if is_plaintext(dec):
                print(f"\n🎉 CRACKED! Found valid data in Page {page_num}, Record Index {idx}!")
                print(f"🛠️  Cipher: AES-256-CBC (Zero IV)")
                print(f"👉 Decrypted: {dec.decode('utf-8', errors='ignore')}\n")
                found_flag = True; break
        except: pass

        # --- STRATEGY C: AES-CTR (Zero Nonce Variant) ---
        try:
            dec = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8).decrypt(ct_bytes)
            if is_plaintext(dec):
                print(f"\n🎉 CRACKED! Found valid data in Page {page_num}, Record Index {idx}!")
                print(f"🛠️  Cipher: AES-256-CTR (Zero Nonce)")
                print(f"👉 Decrypted: {dec.decode('utf-8', errors='ignore')}\n")
                found_flag = True; break
        except: pass

        # --- STRATEGY D: AES-GCM Inline (Strip out common 16B trailing tag structures) ---
        try:
            # Slicing out the trailing 16 bytes assuming it's a standard authentication tag
            dec = AES.new(key_bytes, AES.MODE_GCM, nonce=b'\x00'*12).decrypt(ct_bytes[:-16])
            if is_plaintext(dec):
                print(f"\n🎉 CRACKED! Found valid data in Page {page_num}, Record Index {idx}!")
                print(f"🛠️  Cipher: AES-256-GCM (No-Tag Validation)")
                print(f"👉 Decrypted: {dec.decode('utf-8', errors='ignore')}\n")
                found_flag = True; break
        except: pass

    if found_flag:
        break

if not found_flag:
    print("\n❌ Sweep finished. No hidden needle found in the 500-record haystack.")
    print("💡 If this fails, our cache file allows us to easily test stream-reassembly or alternative KDFs across all pages next!")