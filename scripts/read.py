import os

output_dir = "recovered_data"
# Loop through the files in the directory
for filename in os.listdir(output_dir):
    if filename.endswith(".json"):
        file_path = os.path.join(output_dir, filename)
        
        print(f"\n--- HEX DUMP OF {filename} (First 64 Bytes) ---")
        with open(file_path, "rb") as f:
            raw_data = f.read(64)
            print(f"Hex: {raw_data.hex()}")
            print(f"ASCII Preview: {raw_data}")