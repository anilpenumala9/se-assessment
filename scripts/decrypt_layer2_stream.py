# decrypt_layer2_stream.py
import requests
import base64
import zlib
from Crypto.Cipher import AES

# =====================================================================
# CONFIGURATION
# =====================================================================
URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset?page=1"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# =====================================================================

def test_payload_delivery(raw_bytes, architecture_label):
    """Checks if bytes are raw text or a hidden compressed payload."""
    # 1. Test for direct plaintext
    try:
        text = raw_bytes.decode('utf-8')
        # Look for common data markers (JSON, CSV headers, alphanumeric clusters)
        printable = sum(1 for x in raw_bytes if 32 <= x <= 126 or x in (9, 10, 13))
        if printable / len(raw_bytes) > 0.8:
            print(f"🎉 CRACKED! Raw text recovered via {architecture_label}!")
            print(f"👉 Data Snippet: {text[:200]}\n")
            return True
    except:
        pass

    # 2. Test for Zlib Compression (Common headers: 0x7801, 0x789C, 0x78DA)
    try:
        decompressed = zlib.decompress(raw_bytes)
        print(f"🎉 CRACKED! Decrypted stream matches Zlib compressed payload via {architecture_label}!")
        print(f"👉 Decompressed Snippet: {decompressed.decode('utf-8', errors='ignore')[:200]}\n")
        return True
    except:
        pass

    # 3. Test for Gzip/Deflate raw blocks
    try:
        decompressed = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
        print(f"🎉 CRACKED! Decrypted stream matches Raw Deflate payload via {architecture_label}!")
        print(f"👉 Decompressed Snippet: {decompressed.decode('utf-8', errors='ignore')[:200]}\n")
        return True
    except:
        pass

    return False

# 1. Fetch and assemble the continuous stream
headers = {"Authorization": f"Bearer {API_KEY}"}
res = requests.get(URL, headers=headers)
etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
key_bytes = bytes.fromhex(etag)

records = res.json().get("data", [])
# Concatenate all 25 chunks back into the single historical binary block
full_stream = b"".join(base64.b64decode(record) for record in records)

print(f"📡 Reassembled Page 1 Continuous Stream: {len(full_stream)} total bytes.")
print(f"🔑 Using Master Page Key: {etag[:15]}...\n")

# -----------------------------------------------------------------
# SWEEP 1: AES-256-CTR (Continuous Counter Stream)
# -----------------------------------------------------------------
try:
    # CTR treats the entire payload as one sequence, starting counter at 0
    dec_ctr = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8).decrypt(full_stream)
    if test_payload_delivery(dec_ctr, "AES-256-CTR (Zero Nonces)"): exit()
except Exception as e: pass

# -----------------------------------------------------------------
# SWEEP 2: AES-256-CBC (Continuous Block Chaining)
# -----------------------------------------------------------------
try:
    dec_cbc = AES.new(key_bytes, AES.MODE_CBC, iv=b'\x00'*16).decrypt(full_stream)
    if test_payload_delivery(dec_cbc, "AES-256-CBC (Zero IV)"): exit()
except Exception as e: pass

# -----------------------------------------------------------------
# SWEEP 3: AES-256-GCM (Whole-Stream Authenticated Envelope)
# -----------------------------------------------------------------
try:
    # If GCM, the first 12 bytes of the whole stream is the Nonce, 
    # and the last 16 bytes of the whole stream is the Authentication Tag.
    inline_nonce = full_stream[:12]
    inline_tag = full_stream[-16:]
    inline_ciphertext = full_stream[12:-16]
    
    dec_gcm = AES.new(key_bytes, AES.MODE_GCM, nonce=inline_nonce).decrypt(inline_ciphertext)
    if test_payload_delivery(dec_gcm, "AES-256-GCM (Continuous Stream Layout)"): exit()
except Exception as e: pass

# -----------------------------------------------------------------
# SWEEP 4: AES-256-ECB (Block Independent Stream)
# -----------------------------------------------------------------
try:
    dec_ecb = AES.new(key_bytes, AES.MODE_ECB).decrypt(full_stream)
    if test_payload_delivery(dec_ecb, "AES-256-ECB"): exit()
except Exception as e: pass

print("❌ Reassembled stream sweep complete. No cryptographic match hit.")