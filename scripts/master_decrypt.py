import json
import base64
import zlib
import itertools
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def try_decrypt(ciphertext, key, mode, iv=None):
    """Attempts to decrypt with standard modes and returns the raw bytes."""
    try:
        if mode == 'ECB':
            cipher = AES.new(key, AES.MODE_ECB)
        elif mode == 'CBC':
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        elif mode == 'CTR':
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
        else:
            return None
        return cipher.decrypt(ciphertext)
    except:
        return None

def analyze(data):
    for page_num, content in data.items():
        key = bytes.fromhex(content["etag"])
        
        for record_idx, b64_rec in enumerate(content["records"]):
            raw_ct = base64.b64decode(b64_rec)
            
            # TEST PIPELINE
            # We try combinations of: 
            # 1. Decrypt -> Unpad -> Decompress
            # 2. Decompress -> Decrypt (Unlikely but possible)
            # 3. Just XOR
            
            # Setup common IVs
            ivs = [b'\x00'*16, raw_ct[:16], bytes([0]*16)]
            
            for mode in ['ECB', 'CBC', 'CTR']:
                for iv in ivs:
                    decrypted = try_decrypt(raw_ct, key, mode, iv)
                    if not decrypted: continue
                    
                    # Check for plaintext markers (JSON, XML, or readable ASCII)
                    # We check for '{' or '[' or common file headers
                    if decrypted.startswith(b'{"') or decrypted.startswith(b'['):
                        print(f"MATCH: Page {page_num}, Rec {record_idx} | Mode: {mode} | Data: {decrypted[:50]}")
                        return
                    
                    # Check if it was Zlib compressed
                    try:
                        decomp = zlib.decompress(decrypted)
                        if b'flag' in decomp or b'{' in decomp:
                            print(f"ZLIB MATCH: Page {page_num}, Rec {record_idx} | Data: {decomp[:50]}")
                            return
                    except:
                        pass
                        
            # TEST XOR (Simple brute force for a 1-byte or 4-byte repeating key)
            # If it's a simple XOR, the ETag might be the key.
            xor_key = key[:4] # Try first 4 bytes of ETag
            xor_res = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(raw_ct)])
            if b'flag' in xor_res or b'{' in xor_res:
                print(f"XOR MATCH: Page {page_num}, Rec {record_idx} | Data: {xor_res[:50]}")
                return

# Run the analyzer
with open("harvested_dataset.json", "r") as f:
    data = json.load(f)
    analyze(data)