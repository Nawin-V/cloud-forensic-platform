#!/bin/bash
echo "🚀 Starting Cloud Forensic Platform API on Azure..."
if [ -d "/home/site/wwwroot/antenv" ]; then
    echo "Found /home/site/wwwroot/antenv, activating..."
    source /home/site/wwwroot/antenv/bin/activate
fi

export PYTHONPATH="/home/site/wwwroot/.python_packages/lib/site-packages:/home/site/wwwroot/backend:/home/site/wwwroot:${PYTHONPATH}"

echo "Starting Uvicorn ASGI server on port 8000..."
exec python -m uvicorn main:app --host 0.0.0.0 --port 8000
