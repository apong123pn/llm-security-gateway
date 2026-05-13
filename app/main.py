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

ALLOWED_API_KEYS = {
    os.getenv("INTERNAL_API_KEY", "dev-key-12345"): {"role": "admin", "name": "Admin User"}
}

def verify_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")):
    if not x_api_key or x_api_key not in ALLOWED_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    return ALLOWED_API_KEYS[x_api_key]

# Presidio Setup (kept minimal)
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
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in list(f)[-150:]:
                if line.strip():
                    logs.append(json.loads(line))
    except:
        pass

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SOC Dashboard - LLM Security Gateway</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f8fafc; }}
            .header {{ background: linear-gradient(135deg, #1e40af, #3b82f6); color: white; padding: 20px; }}
            .container {{ padding: 20px; max-width: 1400px; margin: auto; }}
            table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
            th {{ background: #1e40af; color: white; }}
            .blocked {{ background-color: #fee2e2; }}
            .success {{ background-color: #ecfdf5; }}
            .status {{ padding: 5px 12px; border-radius: 20px; font-size: 0.85em; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 Enterprise LLM Security Gateway</h1>
            <p>Welcome, <strong>{user['name']}</strong> | Role: <strong>{user['role'].upper()}</strong></p>
        </div>
        <div class="container">
            <h2>Recent Activity & Security Events</h2>
            <p><strong>Total Events:</strong> {len(logs)}</p>
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
    """
    for log in reversed(logs):
        status_class = "blocked" if log.get("status") in ["blocked", "error"] else "success"
        status_text = log.get("status", "success").upper()
        html += f"""
                <tr class="{status_class}">
                    <td>{log.get('timestamp', '')[:19]}</td>
                    <td>{log.get('event_type', log.get('type', 'request'))}</td>
                    <td><span class="status">{status_text}</span></td>
                    <td>{log.get('reason', '') or log.get('pii_detected', '')}</td>
                </tr>
        """
    html += """
            </table>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html)

# Rest of the code (endpoints, PII, etc.) remains the same as previous version

print("✅ Professional SOC Dashboard is ready at /dashboard")