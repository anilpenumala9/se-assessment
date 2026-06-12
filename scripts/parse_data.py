import json
import msgpack
import bson
import os

def attempt_parsing(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    print(f"--- ATTEMPTING TO PARSE {file_path} ---")

    # 1. Try MessagePack
    try:
        unpacked = msgpack.unpackb(data)
        print("✅ Success: Detected MessagePack!")
        return unpacked
    except:
        print("❌ Not MessagePack")

    # 2. Try BSON
    try:
        unpacked = bson.decode(data)
        print("✅ Success: Detected BSON!")
        return unpacked
    except:
        print("❌ Not BSON")

    # 3. Try standard JSON (just in case the 'b' was a fluke)
    try:
        decoded = data.decode('utf-8')
        print("✅ Success: It is plain JSON!")
        return json.loads(decoded)
    except:
        print("❌ Not UTF-8 JSON")
    
    return None

# Run the test
file_to_test = "recovered_data/page_20_rec_22.json"
result = attempt_parsing(file_to_test)

if result:
    print(f"\n--- DATA PREVIEW ---")
    print(result)