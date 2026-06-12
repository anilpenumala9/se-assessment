# submit_etag.py
import requests
import json

# =====================================================================
# CONFIGURATION ZONE
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# The exact clean hash extracted from your ETag header
ETAG_HASH = "0064163c435f7f652fc4e14c7f62d91a58b0ae919912520c597ad86dbac476ac"
# =====================================================================

def submit_layer_1_etag():
    url = BASE_URL.rstrip("/")
    submit_url = f"{url}/api/v1/submit"
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Construct the Layer 1 payload using the ETag value
    submission_payload = {
        "type": "decrypted_hash",
        "value": ETAG_HASH,
        "notes": "Layer 1 submission: Integrity hash extracted directly from server ETag."
    }
    
    print(f"📤 Submitting verified ETag hash to {submit_url}...")
    
    try:
        response = requests.post(submit_url, headers=headers, json=submission_payload, timeout=15)
        
        print(f"\n📡 [HTTP {response.status_code}] Response received.")
        print("=" * 60)
        print(json.dumps(response.json(), indent=4))
        print("=" * 60)
        
    except Exception as e:
        print(f"❌ Failed to submit: {e}")

if __name__ == "__main__":
    submit_layer_1_etag()