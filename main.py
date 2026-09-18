import os
import sys

# Prepend site-packages and backend directories to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
azure_packages = os.path.join(BASE_DIR, ".python_packages", "lib", "site-packages")
backend_path = os.path.join(BASE_DIR, "backend")

for p in [azure_packages, backend_path, BASE_DIR]:
    if p and os.path.exists(p) and p not in sys.path:
        sys.path.insert(0, p)
    elif p and p not in sys.path:
        sys.path.insert(0, p)

from app.main import app

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", os.getenv("WEBSITES_PORT", 8000)))
    uvicorn.run(app, host="0.0.0.0", port=port)

