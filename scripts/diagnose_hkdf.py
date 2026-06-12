# diagnose_hkdf.py
import requests
import base64
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# =====================================================================
# CONFIGURATION
# =====================================================================
URL = "https://ca-seassessment-api-dev.happywater-190f264d.northcentralus.azurecontainerapps.io/api/v1/dataset?page=1"  # e.g., "https://api.assessment.com"
API_KEY = "sa_e615fed19ebcf175e94b1350ca84fd64c01992fbf350daffb8635f5c9ae4ce1b"   # e.g., "sa_auth_12345..."

# =====================================================================

headers = {"Authorization": f"Bearer {API_KEY}"}
res = requests.get(URL, headers=headers)
etag = res.headers.get("ETag", "").replace('"', '').replace('W/', '').strip()
ikm_bytes = bytes.fromhex(etag)

first_record_b64 = res.json().get("data", [])[0]
payload_bytes = base64.b64decode(first_record_b64)

# Standard AES-GCM payload split: 240 bytes ciphertext + 16 bytes Auth Tag
ciphertext = payload_bytes[:-16]
tag = payload_bytes[-16:]

print(f"📡 Page 1 ETag loaded as HKDF IKM: {etag[:10]}...")
print(f"📦 Ciphertext: {len(ciphertext)} bytes | Tag: {len(tag)} bytes\n")

# --- PATTERN A: Single 44-byte stream split into Key (32) and Nonce (12) ---
scenarios_single = [
    {"name": "Single Run - No Context", "info": b""},
    {"name": "Single Run - Context: 'encryption'", "info": b"encryption"},
    {"name": "Single Run - Context: 'aes-gcm'", "info": b"aes-gcm"},
    {"name": "Single Run - Context: 'layer2'", "info": b"layer2"},
]

print("🚀 Running Pattern A (Single Derived Stream)...")
for sc in scenarios_single:
    try:
        # Fixed signature: using positional arguments for master secret
        okm = HKDF(ikm_bytes, 44, b"", SHA256, context=sc["info"])
        derived_key = okm[:32]
        derived_nonce = okm[32:]
        
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=derived_nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"   🎉 SUCCESS [{sc['name']}]:\n   👉 {plaintext.decode('utf-8', errors='ignore')[:100]}\n")
    except ValueError:
        pass  # Auth tag verification failed
    except Exception as e:
        print(f"   ❌ Error on {sc['name']}: {e}")

# --- PATTERN B: Separate context labels for Key and Nonce ---
scenarios_dual = [
    {"name": "Dual Run - Labels: 'key' / 'nonce'", "k_info": b"key", "n_info": b"nonce"},
    {"name": "Dual Run - Labels: 'aes_key' / 'gcm_nonce'", "k_info": b"aes_key", "n_info": b"gcm_nonce"},
    {"name": "Dual Run - Labels: 'encryption_key' / 'encryption_nonce'", "k_info": b"encryption_key", "n_info": b"encryption_nonce"},
]

print("\n🚀 Running Pattern B (Dual Derived Streams)...")
for sc in scenarios_dual:
    try:
        derived_key = HKDF(ikm_bytes, 32, b"", SHA256, context=sc["k_info"])
        derived_nonce = HKDF(ikm_bytes, 12, b"", SHA256, context=sc["n_info"])
        
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=derived_nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"   🎉 SUCCESS [{sc['name']}]:\n   👉 {plaintext.decode('utf-8', errors='ignore')[:100]}\n")
    except ValueError:
        pass  # Auth tag verification failed
    except Exception as e:
        print(f"   ❌ Error on {sc['name']}: {e}")

print("Sweep finished.")