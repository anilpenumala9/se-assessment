# submit_true_hash.py
import os
import json
import hashlib
import requests
import base64

# =====================================================================
# CONFIGURATION ZONE
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# CHANGE THIS VALUE TO TEST DIFFERENT CODES: "B", "C", or "D"
TEST_VARIANT = "D" 
# =====================================================================

def compute_and_submit():
    data_dir = "data"
    
    page_files = sorted(
        [f for f in os.listdir(data_dir) if f.startswith("page_") and f.endswith(".json")],
        key=lambda x: int(x.split("_")[1].split(".")[0])
    )
    
    if not page_files:
        print("❌ No data files found in 'data/'. Run your fetching script first.")
        return
        
    all_strings = []
    for file_name in page_files:
        with open(os.path.join(data_dir, file_name), "r", encoding="utf-8") as f:
            all_strings.extend(json.load(f).get("data", []))
            
    print(f"📊 Processing {len(all_strings)} records...")

    # --- VARIANT B: Minified JSON Array ---
    json_combined = json.dumps(all_strings, separators=(',', ':'))
    hash_b = hashlib.sha256(json_combined.encode('utf-8')).hexdigest()
    
    # --- VARIANT C: Newline Separated ---
    newline_combined = "\n".join(all_strings)
    hash_c = hashlib.sha256(newline_combined.encode('utf-8')).hexdigest()
    
    # --- VARIANT D: Raw Binary Ciphertext Byte Join ---
    # Decodes base64 strings back to raw binary data and hashes the combined bytes
    try:
        binary_bytes = b"".join([base64.b64decode(s) for s in all_strings])
        hash_d = hashlib.sha256(binary_bytes).hexdigest()
    except Exception:
        hash_d = "Error decoding Base64 strings"

    # Map your selection
    variants = {"B": hash_b, "C": hash_c, "D": hash_d}
    chosen_hash = variants.get(TEST_VARIANT.upper())

    print(f"\n⚡ Testing Variant {TEST_VARIANT.upper()}")
    print(f"🔒 Hash Value: {chosen_hash}")
    print("-" * 60)

    submit_url = f"{BASE_URL.rstrip('/')}/api/v1/submit"
    headers = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    payload = {"type": "content_hash", "value": chosen_hash, "notes": f"Testing Variant {TEST_VARIANT}"}
    
    try:
        response = requests.post(submit_url, headers=headers, json=payload, timeout=15)
        res_json = response.json()
        print(f"📡 Server Response: {json.dumps(res_json, indent=4)}")
        
        if res_json.get("correct", False):
            print(f"\n🎉 SUCCESS! Variant {TEST_VARIANT} cleared Layer 1!")
        else:
            print(f"\n❌ Variant {TEST_VARIANT} was incorrect.")
            print("👉 To try the next style, open the file, change TEST_VARIANT on line 13, and run again.")
            
    except Exception as e:
        print(f"❌ Submission error: {e}")

if __name__ == "__main__":
    compute_and_submit()