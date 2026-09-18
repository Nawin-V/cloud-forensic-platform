"""
Gunicorn Configuration for Azure App Service Linux.
Automatically loaded by Gunicorn on startup.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
backend_path = os.path.join(BASE_DIR, "backend")
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

port = os.getenv("PORT", os.getenv("WEBSITES_PORT", "8000"))
bind = f"0.0.0.0:{port}"
workers = 2
worker_class = "uvicorn.workers.UvicornWorker"
timeout = 600
keepalive = 10
wsgi_app = "main:app"
