# check_phase2_key.py
import requests
import json

# =====================================================================
# CONFIGURATION ZONE
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# The exact winning submission ID from your previous run
SUBMISSION_ID = "9125856a-2b5a-46df-858b-097b19a29833"
# =====================================================================

def fetch_unlocked_layer():
    clean_base = BASE_URL.rstrip("/")
    
    # We will try the two most common RESTful paths for checking a submission status
    target_urls = [
        f"{clean_base}/api/v1/submit/{SUBMISSION_ID}",
        f"{clean_base}/api/v1/submit?id={SUBMISSION_ID}"
    ]
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    print(f"🕵️‍♂️ Querying verification system for Submission ID: {SUBMISSION_ID}...")
    print("-" * 60)
    
    for url in target_urls:
        print(f"📡 Sending GET to: {url}")
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                print(f"🎯 HIT! Server responded with HTTP 200")
                print("=" * 60)
                print(json.dumps(response.json(), indent=4))
                print("=" * 60)
                return
            else:
                print(f"❌ Returned HTTP {response.status_code}")
                
        except Exception as e:
            print(f"💥 Connection error: {e}")
            
    print("\n⚠️ Neither submission path returned data.")
    print("💡 Alternative option: Run a simple GET request on your root BASE_URL to see if the main page dataset has transformed into Phase 2 instructions now that you cleared Phase 1!")

if __name__ == "__main__":
    fetch_unlocked_layer()