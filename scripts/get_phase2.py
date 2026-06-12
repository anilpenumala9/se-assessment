# get_phase2.py
import requests
import json

# =====================================================================
# CONFIGURATION ZONE
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."
# =====================================================================

def fetch_phase_2():
    url = BASE_URL.rstrip("/")
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    print("📡 Querying root URL for updated Phase 2 instructions...")
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        print("\n" + "="*60)
        print("🔓 PHASE 2 ROADMAP UNLOCKED")
        print("="*60)
        print(json.dumps(response.json(), indent=4))
        print("="*60)
        
    except Exception as e:
        print(f"❌ Failed to fetch updated instructions: {e}")

if __name__ == "__main__":
    fetch_phase_2()