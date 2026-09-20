import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.main import app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", os.getenv("WEBSITES_PORT", 8000)))
    uvicorn.run(app, host="0.0.0.0", port=port)
