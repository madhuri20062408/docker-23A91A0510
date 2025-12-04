#!/bin/bash
# Start Uvicorn with the FastAPI app

cd /srv/app
python3 -m uvicorn app.server:app --host 0.0.0.0 --port 8080
