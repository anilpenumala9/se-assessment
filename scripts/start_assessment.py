# scripts/start_assessment.py
import sys
import os
import json

# Ensure the root directory is on the path so Python can find 'src'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api_client import api_call

def start_puzzle():
    print("🚀 Preparing one-shot call to the root BASE_URL...")
    print("⚠️ WARNING: Typing 'yes' will officially START your 3-hour assessment window.")
    
    confirm = input("Are you ready to trigger the clock and fetch instructions? (yes/no): ")
    if confirm.lower() != 'yes':
        print("Aborted. The clock has NOT been started.")
        return

    try:
        # 1. Fire a single authenticated request to the root URL
        response_data = api_call("", method="GET")
        
        # 2. Save the output cleanly to a local file
        os.makedirs("data", exist_ok=True)
        output_file = os.path.join("data", "instructions.json")
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(response_data, f, indent=4)
            
        print("\n" + "="*50)
        print("🎉 CLOCK STARTED SUCCESSFULLY!")
        print(f"💾 Server instructions written to: {output_file}")
        print("="*50)
        
        # Show the JSON output on the screen for instant review
        print(json.dumps(response_data, indent=4))
        
    except Exception as e:
        print(f"\n❌ Process stopped. Look closely at the error responses printed above.")

if __name__ == "__main__":
    start_puzzle()