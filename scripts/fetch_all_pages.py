# fetch_all_pages.py
import os
import json
import requests

# =====================================================================
# CONFIGURATION ZONE
# Paste your actual assessment details here!
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."
DATA_ENDPOINT = ""                    # Leave blank if you hit the root URL directly
# =====================================================================

def fetch_all_data():
    # 1. Clean and build the URL exactly like Postman does
    url = BASE_URL.rstrip("/")
    if DATA_ENDPOINT:
        url = f"{url}/{DATA_ENDPOINT.lstrip('/')}"
        
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    # Create the data directory to store the results locally
    os.makedirs("data", exist_ok=True)
    
    current_page = 20
    has_more = True
    
    print("🚀 Starting bulk dataset ingestion...")
    print(f"📡 Target URL: {url}")
    print("-" * 50)

    while has_more:
        # Add page parameter to the query string (?page=1, ?page=2, etc.)
        query_params = {"page": current_page}
        
        try:
            print(f"⏳ Fetching Page {current_page}...", end="", flush=True)
            
            response = requests.get(
                url=url, 
                headers=headers, 
                params=query_params, 
                timeout=15
            )
            
            # Catch bad status codes instantly
            response.raise_for_status()
            
            page_json = response.json()
            print(f" Success! (Found {len(page_json.get('data', []))} records)")
            
            # 2. Save this specific page data to its own JSON file
            filename = os.path.join("data", f"page_{current_page}.json")
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(page_json, f, indent=4)
            
            # 3. Check if there are more pages left to pull
            has_more = page_json.get("has_more", False)
            
            if has_more:
                current_page += 1
            else:
                print("-" * 50)
                print(f"🎉 Complete! All pages successfully written to the 'data/' folder.")
                
        except requests.exceptions.HTTPError as http_err:
            print(f"\n❌ HTTP Error on page {current_page}: {http_err}")
            print(f"Server message: {response.text}")
            break
        except Exception as e:
            print(f"\n❌ Critical unexpected error: {e}")
            break

if __name__ == "__main__":
    fetch_all_data()