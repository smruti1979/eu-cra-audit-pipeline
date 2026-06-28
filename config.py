import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

NVD_BASE_URL = os.getenv("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
REQUEST_TIMEOUT = 60

# Vulnerability keyword flags used to evaluate 'exploitable' status under CRA
CRA_EXPLOITABLE_KEYWORDS = [
    "rce", 
    "remote code execution", 
    "exploit available", 
    "overflow"
]
