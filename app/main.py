from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import httpx
import os
import re
import json
from datetime import datetime
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List, Dict, Tuple, Optional

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Production-ready with SOC Dashboard",
    version="0.7.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"
LOG_FILE = "audit_logs.jsonl"

# Simple RBAC
ALLOWED_API_KEYS = {
    os.getenv("INTERNAL_API_KEY", "dev-key-12345"): {"role": "admin", "name": "Admin User"},
    "viewer-key-67890": {"role": "viewer", "name": "SOC Viewer"}
}

def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    if not x_api_key or x_api_key not in ALLOWED_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    return ALLOWED_API_KEYS[x_api_key]

# Presidio Setup (kept light)
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

registry = RecognizerRegistry()
registry.load_predefined_recognizers()
analyzer = AnalyzerEngine(registry=registry)
anonymizer = AnonymizerEngine()

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str
    messages: List[Message]
    temperature: float = 0.7
    max_tokens: int = 500

@app.get("/")
async def root():
    return {"message": "Enterprise LLM Security Gateway is running! 🚀"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# ==================== BEAUTIFUL SOC DASHBOARD ====================
@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard(user: dict = Depends(verify_api_key)):
    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in list(f)[-200:]:
                if line.strip():
                    logs.append(json.loads(line))
    except:
        pass

    html = f"""
    <html>
    <head><title>SOC Dashboard - LLM Security Gateway</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
        h1 {{ color: #1e3a8a; }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #1e3a8a; color: white; }}
        .blocked {{ background-color: #fee2e2; }}
        .success {{ background-color: #ecfdf5; }}
    </style>
    </head>
    <body>
        <h1>🔐 Enterprise LLM Security Gateway - SOC Dashboard</h1>
        <p><strong>Welcome, {user['name']} ({user['role']})</strong></p>
        <p>Total Logs: {len(logs)}</p>
        <table>
            <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
    """
    for log in reversed(logs):
        status_class = "blocked" if log.get("status") in ["blocked", "error"] else "success"
        html += f"""
            <tr class="{status_class}">
                <td>{log.get('timestamp', '')[:19]}</td>
                <td>{log.get('event_type', log.get('type', 'request'))}</td>
                <td>{log.get('status', 'success')}</td>
                <td>{log.get('reason', log.get('pii_detected', ''))}</td>
            </tr>
        """
    html += "</table></body></html>"
    return HTMLResponse(html)

# ... (rest of the code remains same as previous version)

print("✅ SOC Dashboard ready at /dashboard")