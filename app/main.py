from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import os
import json
from datetime import datetime

load_dotenv = lambda: None   # dummy

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="SOC Dashboard",
    version="0.7.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE = "audit_logs.jsonl"

@app.get("/")
async def root():
    return {"message": "Dashboard is ready at /dashboard"}

@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard():
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
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }}
            h1 {{ color: #1e40af; }}
            table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background: #1e40af; color: white; }}
            .blocked {{ background-color: #fee2e2; }}
            .success {{ background-color: #ecfdf5; }}
        </style>
    </head>
    <body>
        <h1>🔐 Enterprise LLM Security Gateway - SOC Dashboard</h1>
        <p><strong>Total Logs:</strong> {len(logs)}</p>
        <table>
            <tr>
                <th>Time</th>
                <th>Event Type</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
    """
    for log in reversed(logs):
        row_class = "blocked" if log.get("status") in ["blocked", "error"] else "success"
        html += f"""
            <tr class="{row_class}">
                <td>{log.get('timestamp', '')[:19]}</td>
                <td>{log.get('event_type', log.get('type', 'request'))}</td>
                <td>{log.get('status', 'success').upper()}</td>
                <td>{log.get('reason', '') or ', '.join(log.get('pii_detected', []))}</td>
            </tr>
        """
    html += """
        </table>
    </body>
    </html>
    """
    return HTMLResponse(html)

print("✅ Simple Dashboard ready at /dashboard")