"""
Convenience server launcher for Cloud Incident & Forensic Response Platform.
"""

import os
import sys
import uvicorn
from dotenv import load_dotenv

# Ensure backend root is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Load environment variables from backend/.env or root .env
load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(os.path.dirname(BASE_DIR), ".env"))

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    print(f"🚀 Launching Cloud Forensic Platform Backend on http://localhost:{port}")
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
