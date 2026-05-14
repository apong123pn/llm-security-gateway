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
    description="Production SOC Dashboard",
    version="0.7.1"
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

ALLOWED_API_KEYS = {
    os.getenv("INTERNAL_API_KEY", "dev-key-12345"): {"role": "admin", "name": "Admin User"}
}

def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    if not x_api_key or x_api_key not in ALLOWED_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    return ALLOWED_API_KEYS[x_api_key]

# Presidio Setup
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

# ==================== PROFESSIONAL SOC DASHBOARD ====================
@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard(user: dict = Depends(verify_api_key)):
    logs = []
    blocked = 0
    pii_count = 0

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in list(f)[-300:]:
                if line.strip():
                    log = json.loads(line)
                    logs.append(log)
                    if log.get("status") == "blocked":
                        blocked += 1
                    if log.get("pii_detected"):
                        pii_count += len(log.get("pii_detected", []))
    except:
        pass

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Dashboard - LLM Security</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f8fafc; }}
            .header {{ background: linear-gradient(135deg, #1e3a8a, #3b82f6); color: white; padding: 25px; }}
            .container {{ padding: 20px; max-width: 1400px; margin: auto; }}
            .cards {{ display: flex; gap: 20px; margin-bottom: 30px; }}
            .card {{ background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); flex: 1; }}
            table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
            th {{ background: #1e3a8a; color: white; }}
            .blocked {{ background-color: #fee2e2; }}
            .success {{ background-color: #ecfdf5; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 Enterprise LLM Security Gateway</h1>
            <p>Welcome, <strong>{user['name']}</strong> • Role: <strong>{user['role'].upper()}</strong></p>
        </div>
        <div class="container">
            <h2>Security Overview</h2>
            <div class="cards">
                <div class="card">
                    <h3>Total Requests</h3>
                    <h2>{len(logs)}</h2>
                </div>
                <div class="card">
                    <h3>Blocked Requests</h3>
                    <h2 style="color:#ef4444;">{blocked}</h2>
                </div>
                <div class="card">
                    <h3>PII Detected</h3>
                    <h2 style="color:#f59e0b;">{pii_count}</h2>
                </div>
            </div>

            <h2>Recent Activity</h2>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Event Type</th>
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
                    <td>{log.get('status', 'success').upper()}</td>
                    <td>{log.get('reason', '') or ', '.join(log.get('pii_detected', []))}</td>
                </tr>
        """
    html += """
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

# (The rest of the code - endpoints, PII, injection, etc. - remains the same as previous version)

print("✅ Enhanced SOC Dashboard is ready at /dashboard")