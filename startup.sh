#!/bin/bash
cd /home/site/wwwroot || true
echo "🚀 Starting Cloud Forensic Platform API on Azure..."
export PYTHONPATH="/home/site/wwwroot/.python_packages/lib/site-packages:/home/site/wwwroot/backend:/home/site/wwwroot:${PYTHONPATH}"
if [ -d "/home/site/wwwroot/antenv" ]; then
    echo "Found /home/site/wwwroot/antenv, activating..."
    source /home/site/wwwroot/antenv/bin/activate
fi

echo "Starting server via main.py..."
exec python /home/site/wwwroot/main.py
