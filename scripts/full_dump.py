import json
import base64

# Load your file
with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

# Page 1, Record 2
etag = bytes.fromhex(data["1"]["etag"])
record_b64 = data["1"]["records"][2] # Python indices are 0-based
ciphertext = base64.b64decode(record_b64)

# Use the same 4-byte key that triggered the match
xor_key = etag[:4]

# Decrypt the WHOLE thing
full_decrypted = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(ciphertext)])

# Print the full result
print("--- FULL DECRYPTED CONTENT ---")
print(full_decrypted)
print("------------------------------")
print("--- AS STRING ---")
print(full_decrypted.decode('utf-8', errors='ignore'))