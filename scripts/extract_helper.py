import json
import base64
from Crypto.Cipher import ChaCha20
from hashlib import sha256

# YOUR API KEY (Must be the same one used previously)
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b" 

with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

# Use the same test sample: Page 1, Record 2
page_data = data["1"]
ciphertext = base64.b64decode(page_data["records"][2])
etag_bytes = bytes.fromhex(page_data["etag"])
api_key_bytes = sha256(API_KEY.encode()).digest()

# Candidates tested in the previous successful run
key_candidates = [api_key_bytes, etag_bytes, sha256(api_key_bytes + etag_bytes).digest()]
nonce_candidates = [etag_bytes, api_key_bytes]

print("--- COPY THESE VALUES FOR THE NEXT SCRIPT ---")
for k in key_candidates:
    for n in nonce_candidates:
        try:
            cipher = ChaCha20.new(key=k, nonce=n[:12])
            res = cipher.decrypt(ciphertext)
            
            # Check if this combination yields readable data
            if any(c in res for c in [b'{', b'flag', b'CTF']):
                print(f"KEY:   {k.hex()}")
                print(f"NONCE: {n[:12].hex()}")
                print("---------------------------------------------")
                exit()
        except:
            continue