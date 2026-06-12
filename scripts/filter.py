import json
import base64
from Crypto.Cipher import ChaCha20

# REPLACE WITH THE VALUES FOUND IN THE PREVIOUS STEP
KEY = bytes.fromhex("22a81bd6be032a7a495086163e2efbaf35320dedc170b7b6224aaf7c6ff6f63e") 
NONCE = bytes.fromhex("ed082ffa611e73a171401d3e") 

with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

print(f"--- DIAGNOSTIC DUMP (Page 1, First 5 Records) ---")

for idx in range(5):
    ciphertext = base64.b64decode(data["1"]["records"][idx])
    cipher = ChaCha20.new(key=KEY, nonce=NONCE)
    decrypted = cipher.decrypt(ciphertext)
    
    # Print the first 64 bytes in Hex
    print(f"Record {idx} (Hex): {decrypted[:64].hex()}")
    # Print the first 64 bytes as ASCII (if possible)
    print(f"Record {idx} (ASCII): {repr(decrypted[:64])}")
    print("-" * 40)