import os
import requests
import pandas as pd
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

print("✅ Windows environment & stack loaded successfully!")
print(f"Base URL configured: {os.getenv('BASE_URL')}")