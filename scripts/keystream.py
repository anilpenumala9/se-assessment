import json
import base64

# This is the exact header from your file metadata
# '{\r\n    "1": {' -> 14 bytes
known_plaintext = b'{\r\n    "1": {'

with open("harvested_dataset.json", "r") as f:
    data = json.load(f)

# Focus on the very first record of the first page
ciphertext = base64.b64decode(data["1"]["records"][0])

# Extract the true keystream: Plaintext XOR Ciphertext = Keystream
# We only need the first 14 bytes
keystream = bytes([ciphertext[i] ^ known_plaintext[i] for i in range(len(known_plaintext))])

print(f"--- TRUE KEYSTREAM (First 14 bytes) ---")
print(f"Hex: {keystream.hex()}")
print(f"ASCII: {keystream}")

# TEST: Does this keystream appear at the start of other records?
# If the keystream is the same for the first 14 bytes of every record,
# you are dealing with a static XOR key, not a stream cipher!
print("\n--- CHECKING RECORD 2 ---")
ciphertext_r2 = base64.b64decode(data["1"]["records"][1])
# XOR the first 14 bytes of Record 2 with the keystream we just found
# If this results in '{\r\n    "1": {', we cracked it!
recovered_r2 = bytes([ciphertext_r2[i] ^ keystream[i] for i in range(len(keystream))])
print(f"Decoded Header of Record 2: {recovered_r2}")