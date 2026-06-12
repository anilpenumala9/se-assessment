import json
import base64
import hashlib
from Crypto.Cipher import AES

def test_key(key, ciphertext):
    """Attempts decryption and checks for JSON start byte."""
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(ciphertext)
        if dec.startswith(b'{"') or dec.startswith(b'['):
            return True, dec
    except:
        pass
    return False, None

with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

# We only test the first record of the first page to save time
# Once we find the KDF pattern, we can apply it to the whole set
sample_page = data["1"]
ciphertext = base64.b64decode(sample_page["records"][0])
raw_etag = bytes.fromhex(sample_page["etag"])

print(f"Brute-forcing key derivation for Page 1...")

# Strategies to derive the key from the ETag
strategies = {
    "SHA256(ETag)": hashlib.sha256(raw_etag).digest(),
    "MD5(ETag)": hashlib.md5(raw_etag).digest() * 2, # Pad to 32 bytes
    "SHA1(ETag)": hashlib.sha1(raw_etag).digest() + b'\x00'*12,
    "ETag[:16]": raw_etag[:16] + raw_etag[:16], # Repeated ETag
    "SHA256(ETag + 'salt')": hashlib.sha256(raw_etag + b'salt').digest(),
}

for name, key in strategies.items():
    success, result = test_key(key, ciphertext)
    if success:
        print(f"🎉 MATCH FOUND! KDF Strategy: {name}")
        print(f"👉 Decrypted: {result[:50]}")
        break
    else:
        print(f"❌ Failed: {name}")