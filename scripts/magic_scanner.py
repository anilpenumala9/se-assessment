import json
import base64
from Crypto.Cipher import AES

def get_file_type(data):
    """Checks the first few bytes for common file signatures."""
    if data.startswith(b'{"'): return "JSON"
    if data.startswith(b'\x1f\x8b'): return "Gzip"
    if data.startswith(b'\x78\x9c') or data.startswith(b'\x78\x01') or data.startswith(b'\x78\xda'): return "Zlib"
    if data.startswith(b'%PDF'): return "PDF"
    return "UNKNOWN"

with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

# Focus: Page 1, Record 2
etag = bytes.fromhex(data["1"]["etag"])
ciphertext = base64.b64decode(data["1"]["records"][2])

print(f"Testing Page 1, Rec 2. ETag key: {etag.hex()[:8]}...")

# 1. Test ECB Mode (Does not use an IV)
try:
    cipher_ecb = AES.new(etag, AES.MODE_ECB)
    dec_ecb = cipher_ecb.decrypt(ciphertext)
    print(f"ECB Mode Result: {get_file_type(dec_ecb)} | First 16 bytes: {dec_ecb[:16]}")
except Exception as e: print(f"ECB failed: {e}")

# 2. Test CBC Mode (Assuming first 16 bytes of data is the IV)
try:
    iv = ciphertext[:16]
    actual_ct = ciphertext[16:]
    cipher_cbc = AES.new(etag, AES.MODE_CBC, iv=iv)
    dec_cbc = cipher_cbc.decrypt(actual_ct)
    print(f"CBC Mode (Inline IV) Result: {get_file_type(dec_cbc)} | First 16 bytes: {dec_cbc[:16]}")
except Exception as e: print(f"CBC failed: {e}")

# 3. Test CBC Mode (Assuming Zero-IV)
try:
    cipher_cbc_z = AES.new(etag, AES.MODE_CBC, iv=b'\x00'*16)
    dec_cbc_z = cipher_cbc_z.decrypt(ciphertext)
    print(f"CBC Mode (Zero IV) Result: {get_file_type(dec_cbc_z)} | First 16 bytes: {dec_cbc_z[:16]}")
except Exception as e: print(f"CBC failed: {e}")