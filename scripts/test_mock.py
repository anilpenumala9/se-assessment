# scripts/test_mock.py
from unittest.mock import patch, MagicMock
import os

# Set dummy env vars so the client doesn't complain
os.environ["BASE_URL"] = "https://fakeapi.com"
os.environ["API_KEY"] = "sa_fake_key_for_testing"

from src.api_client import api_call

# 1. Create a fake 429 response
mock_429 = MagicMock()
mock_429.status_code = 429
mock_429.headers = {"Retry-After": "2"}

# 2. Create a fake 200 response
mock_200 = MagicMock()
mock_200.status_code = 200
mock_200.content = b'{"message": "Success after waiting!"}'
mock_200.json.return_value = {"message": "Success after waiting!"}

@patch("requests.request")
def run_mock_test(mock_req):
    # Tell requests.request to return a 429 on the first try, then a 200 on the second try
    mock_req.side_effect = [mock_429, mock_200]
    
    print("🚀 Triggering mock API call...")
    result = api_call("/test-endpoint")
    print(f"🎉 Final Output from wrapper: {result}")

if __name__ == "__main__":
    run_mock_test()