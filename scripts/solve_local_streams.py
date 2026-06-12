# solve_local_streams.py
import json
import base64
import zlib
from Crypto.Cipher import AES

CACHE_FILE = "harvested_dataset.json"

def test_cleartext(raw_bytes, page_num, cipher_label):
    """Checks if a decrypted stream contains readable text or compressed data."""
    if not raw_bytes:
        return False
        
    # Test 1: Direct UTF-8 Plaintext
    try:
        # Check printable ASCII density
        printable = sum(1 for x in raw_bytes if 32 <= x <= 126 or x in (9, 10, 13))
        ratio = printable / len(raw_bytes)
        if ratio > 0.80:
            print(f"\n🎉 SUCCESS on Page {page_num}!")
            print(f"🛠️  Cipher: {cipher_label}")
            print(f"👉 Plaintext Snippet:\n{raw_bytes.decode('utf-8', errors='ignore')[:300]}\n")
            return True
    except:
        pass

    # Test 2: Zlib Decompression (If the plaintext was compressed before encryption)
    try:
        decompressed = zlib.decompress(raw_bytes)
        print(f"\n🎉 SUCCESS on Page {page_num} (Zlib Compressed Payload)!")
        print(f"🛠️  Cipher: {cipher_label}")
        print(f"👉 Decompressed Snippet:\n{decompressed.decode('utf-8', errors='ignore')[:300]}\n")
        return True
    except:
        pass

    # Test 3: Raw Deflate Decompression
    try:
        decompressed = zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
        print(f"\n🎉 SUCCESS on Page {page_num} (Raw Deflate Compressed Payload)!")
        print(f"🛠️  Cipher: {cipher_label}")
        print(f"👉 Decompressed Snippet:\n{decompressed.decode('utf-8', errors='ignore')[:300]}\n")
        return True
    except:
        pass

    return False

# Load local cache
with open(CACHE_FILE, "r") as f:
    data_matrix = json.load(f)

print(f"📂 Loaded {len(data_matrix)} pages from local cache.")
print("🚀 Beginning continuous stream analysis across all pages...\n")

for page_str, content in data_matrix.items():
    etag = content["etag"]
    records = content["records"]
    
    try:
        key_bytes = bytes.fromhex(etag)
    except:
        continue
        
    # REASSEMBLY: Stitch the 25 fragments back into the true 6,400-byte stream
    full_stream = b"".join(base64.b64decode(r) for r in records)
    
    # --- MODE 1: Continuous AES-256-CTR ---
    try:
        dec_ctr = AES.new(key_bytes, AES.MODE_CTR, nonce=b'\x00'*8).decrypt(full_stream)
        if test_cleartext(dec_ctr, page_str, "AES-256-CTR (Continuous Counter, Zero Nonce)"): 
            break
    except: pass

    # --- MODE 2: Continuous AES-256-CBC ---
    try:
        dec_cbc = AES.new(key_bytes, AES.MODE_CBC, iv=b'\x00'*16).decrypt(full_stream)
        if test_cleartext(dec_cbc, page_str, "AES-256-CBC (Continuous Block Chaining, Zero IV)"): 
            break
    except: pass

    # --- MODE 3: Continuous AES-256-GCM Envelope ---
    # In a full-stream GCM deployment, the first 12 bytes of the whole stream is the nonce,
    # and the trailing 16 bytes is the authentication tag.
    try:
        if len(full_stream) > 28:
            inline_nonce = full_stream[:12]
            inline_tag = full_stream[-16:]
            inline_ciphertext = full_stream[12:-16]
            
            dec_gcm = AES.new(key_bytes, AES.MODE_GCM, nonce=inline_nonce).decrypt(inline_ciphertext)
            if test_cleartext(dec_gcm, page_str, "AES-256-GCM (Stitched Stream Envelope)"): 
                break
    except: pass

    # --- MODE 4: Continuous AES-256-CFB ---
    try:
        dec_cfb = AES.new(key_bytes, AES.MODE_CFB, iv=b'\x00'*16, segment_size=128).decrypt(full_stream)
        if test_cleartext(dec_cfb, page_str, "AES-256-CFB (Continuous Stream Variant)"): 
            break
    except: pass

print("🧹 Local continuous sweep finished.")