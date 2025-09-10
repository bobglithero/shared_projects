#!/usr/bin/env python3
import asyncio
import json
from datetime import datetime
from pathlib import Path
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os

app = FastAPI(title="Demo Data Capture Server")

@app.get("/health")
async def health():
    return {"status": "running", "purpose": "educational_demo"}

@app.post("/capture")  
async def capture_data(request: Request):
    try:
        data = await request.json()
        timestamp = datetime.now().isoformat()
        
        print(f"\n[DEMO CAPTURE {timestamp}]")
        print("=" * 60)
        print("SIMULATED DATA EXFILTRATION:")
        print(json.dumps(data, indent=2))
        print("=" * 60)
        
        # Log to file for analysis
        log_file = Path("/demo/logs/captured_exfiltration.log")
        log_file.parent.mkdir(exist_ok=True)
        with open(log_file, "a") as f:
            f.write(f"\n[{timestamp}] CAPTURED DATA:\n")
            f.write(json.dumps(data, indent=2))
            f.write("\n" + "=" * 60 + "\n")
        
        return {"status": "captured", "timestamp": timestamp}
    
    except Exception as e:
        print(f"Capture error: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    capture_port = int(os.getenv("CAPTURE_PORT", "9080"))
    print(f"Starting demo capture server on port {capture_port}")
    uvicorn.run(app, host="0.0.0.0", port=capture_port, log_level="info")
