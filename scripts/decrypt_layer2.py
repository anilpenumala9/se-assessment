import requests
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# =====================================================================
# CONFIGURATION ZONE
# =====================================================================
BASE_URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."
TOTAL_PAGES = 20
# =====================================================================

def decrypt_record(aes_key_bytes, base64_ciphertext):
    """
    Decrypts a single base64 string, auto-detecting AES-256-ECB 
    vs AES-256-CBC (with prepended/inline IV) cryptographic modes.
    """
    ciphertext_bytes = base64.b64decode(base64_ciphertext)
    
    # STRATEGY 1: AES-256-ECB (Electronic Codebook - No IV used)
    try:
        cipher_ecb = AES.new(aes_key_bytes, AES.MODE_ECB)
        decrypted_bytes = cipher_ecb.decrypt(ciphertext_bytes)
        return unpad(decrypted_bytes, AES.block_size)
    except ValueError:
        pass

    # STRATEGY 2: AES-256-CBC with an Inline/Prepended IV
    # (First 16 bytes = IV, remaining bytes = actual ciphertext)
    try:
        if len(ciphertext_bytes) > 16:
            iv_bytes = ciphertext_bytes[:16]
            actual_ciphertext = ciphertext_bytes[16:]
            
            cipher_cbc = AES.new(aes_key_bytes, AES.MODE_CBC, iv=iv_bytes)
            decrypted_bytes = cipher_cbc.decrypt(actual_ciphertext)
            return unpad(decrypted_bytes, AES.block_size)
    except ValueError:
        pass

    # STRATEGY 3: Fallback to AES-256-CBC with a Null IV (16 bytes of zeroes)
    iv_bytes = b'\x00' * 16 
    cipher_fallback = AES.new(aes_key_bytes, AES.MODE_CBC, iv=iv_bytes)
    return unpad(cipher_fallback.decrypt(ciphertext_bytes), AES.block_size)


def run_pipeline():
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    master_plaintext_stream = b""
    print("🚀 Starting Phase 2 Streaming Decryption Pipeline...")
    print("-" * 70)
    
    for page in range(1, TOTAL_PAGES + 1):
        url = f"{BASE_URL}?page={page}"
        print(f"📡 Fetching Page {page}/{TOTAL_PAGES}...")
        
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            print(f"❌ Failed to fetch Page {page}. Status code: {response.status_code}")
            return
            
        # Extract the Key from the ETag header
        etag_value = response.headers.get("ETag") or response.headers.get("etag")
        if not etag_value:
            print(f"❌ Critical Error: No ETag header found on page {page}!")
            return
            
        # Clean up quotes and common weak ETag prefixes (W/)
        key_hex = etag_value.replace('"', '').replace('W/', '').strip()
        
        print(f"   ⚙️ Raw ETag: {etag_value} -> Cleaned Hex: {key_hex[:10]}...")
        print(f"   🔑 Key Found: {key_hex[:10]}...{key_hex[-10:]}")
        
        try:
            key_bytes = bytes.fromhex(key_hex)
        except ValueError as e:
            print(f"\n❌ CRITICAL HEX ERROR on Page {page}!")
            print(f"   The server returned an unexpected ETag format: {repr(etag_value)}")
            raise e
        
        # Parse the encrypted items from the body
        try:
            body_json = response.json()
            records = body_json.get("data", []) 
        except Exception:
            print(f"❌ Failed to parse JSON body on page {page}")
            return

        print(f"   🔓 Processing {len(records)} records...")
        
        # Decrypt each item on this page and append to our master binary stream
        for record in records:
            try:
                decrypted_item = decrypt_record(key_bytes, record)
                master_plaintext_stream += decrypted_item
            except Exception as e:
                print(f"   💥 Decryption failed completely on a record in page {page}!")
                print(f"   Error details: {e}")
                return

    print("-" * 70)
    print("✅ All pages successfully streamed and decrypted!")
    
    # Generate the final SHA-256 hash of the complete decrypted stream
    final_hash = hashlib.sha256(master_plaintext_stream).hexdigest()
    
    print("\n" + "="*70)
    print("🎯 TARGET LAYER 2 DECRYPTED HASH GENERATED:")
    print(f"👉 {final_hash}")
    print("="*70)
    
    print("\n📝 Next Step: Paste this hash into your Postman payload:")
    print(json.dumps({
        "type": "decrypted_hash",
        "value": final_hash,
        "notes": "Submitting generated Phase 2 decrypted data hash"
    }, indent=4))


if __name__ == "__main__":
    run_pipeline()