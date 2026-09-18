"""
Gunicorn Configuration for Azure App Service Linux.
Automatically loaded by Gunicorn on startup.
"""

import os
import sys
import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. Add all potential site-packages paths on Azure Linux App Service
candidate_paths = [
    os.path.join(BASE_DIR, ".python_packages", "lib", "site-packages"),
    os.path.join(BASE_DIR, "backend"),
    BASE_DIR,
]
# Add antenv python site-packages if present
antenv_site_packages = glob.glob(os.path.join(BASE_DIR, "antenv", "lib", "python*", "site-packages"))
candidate_paths.extend(antenv_site_packages)

for p in candidate_paths:
    if p and p not in sys.path:
        sys.path.insert(0, p)

port = os.getenv("PORT", os.getenv("WEBSITES_PORT", "8000"))
bind = f"0.0.0.0:{port}"
workers = 2
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 600
keepalive = 10
wsgi_app = "main:app"

