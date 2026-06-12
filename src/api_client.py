# src/api_client.py
import os
import time
import requests
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

BASE_URL = os.getenv("BASE_URL")
API_KEY = os.getenv("API_KEY")

def api_call(endpoint: str, method: str = "GET", data: dict = None, params: dict = None, max_retries: int = 5) -> dict:
    """
    An enhanced API client wrapper that automatically catches 429 Rate Limits,
    inspects the 'Retry-After' header, sleeps, and retries seamlessly.
    """
    if not BASE_URL or not API_KEY:
        raise ValueError("CRITICAL: BASE_URL or API_KEY is missing from your .env file!")

    cleaned_base = BASE_URL.rstrip("/")
    cleaned_endpoint = endpoint.lstrip("/")
    url = f"{cleaned_base}/{cleaned_endpoint}"
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    attempt = 0
    while attempt <= max_retries:
        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=data,
                params=params,
                timeout=10
            )
            
            # CASE 1: Hit a Rate Limit (429)
            if response.status_code == 429:
                attempt += 1
                if attempt > max_retries:
                    print("❌ Max retries exceeded due to rate limiting.")
                    response.raise_for_status()
                
                # Extract wait time; default to 2 seconds if header is missing or malformed
                retry_after = response.headers.get("Retry-After")
                try:
                    wait_time = int(retry_after) if retry_after else 2
                except ValueError:
                    wait_time = 2  # Fallback if Retry-After is given as an HTTP date string
                
                print(f"⚠️ [429] Rate limited! Backing off for {wait_time}s... (Attempt {attempt}/{max_retries})")
                time.sleep(wait_time)
                continue  # Jump back to the start of the loop and try again
            
            # CASE 2: Other HTTP Errors (4xx, 5xx)
            response.raise_for_status()
            
            # CASE 3: Success!
            return response.json() if response.content else {}
            
        except requests.exceptions.HTTPError as http_err:
            # Captures the error envelope payload specified in your guide
            print(f"❌ HTTP Error: {http_err} | Response Envelope: {response.text}")
            raise http_err
            
        except requests.exceptions.RequestException as req_err:
            print(f"❌ Network/Timeout Error: {req_err}")
            raise req_err

    raise Exception(f"❌ Failed to get a response after {max_retries} attempts.")