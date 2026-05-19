# gateway.py - Full Version with PII Redaction + Prompt Injection Detection + SOC Dashboard
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import time
import uuid
import os
import json

load_dotenv()

from app.database import DatabaseService
from app.pii_redaction import PIIRedactionService
from app.threat_detection import ThreatDetectionService
from app.dashboard import generate_dashboard_html

# ============================================================
# PYDANTIC MODELS
# ============================================================

class Message(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[Message]
    temperature: float = 0.7
    max_tokens: int = 500

# ============================================================
# SERVICES
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./audit_logs.db")
db_service = DatabaseService(DATABASE_URL)
pii_service = PIIRedactionService()
threat_service = ThreatDetectionService()

# ============================================================
# API KEYS (RBAC Ready)
# ============================================================

# User database with roles and departments
USERS = {
    "admin-key-12345": {
        "name": "Admin User",
        "role": "admin",
        "department": "it",
        "permissions": ["full_access", "view_dashboard", "view_logs", "view_stats"]
    },
    "eng-key-67890": {
        "name": "Engineer User",
        "role": "engineer",
        "department": "engineering",
        "permissions": ["use_gpt4", "use_gpt35", "view_stats"]
    },
    "mktg-key-11111": {
        "name": "Marketing User",
        "role": "marketing",
        "department": "marketing",
        "permissions": ["use_gpt35", "view_stats"]
    },
    "security-key-22222": {
        "name": "Security Analyst",
        "role": "security",
        "department": "security",
        "permissions": ["view_dashboard", "view_logs", "view_stats", "view_alerts"]
    }
}

def verify_api_key(api_key: str):
    """Verify API key and return user info"""
    if api_key not in USERS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return USERS[api_key]

def check_model_access(user_info: dict, requested_model: str) -> bool:
    """Check if user has access to requested model (RBAC)"""
    permissions = user_info.get("permissions", [])
    
    # Admin has full access
    if "full_access" in permissions:
        return True
    
    # Check specific model permissions
    if requested_model == "gpt-4" and "use_gpt4" not in permissions:
        return False
    if requested_model == "gpt-3.5-turbo" and "use_gpt35" not in permissions:
        return False
    
    return True

# ============================================================
# APP SETUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "="*60)
    print("🔐 LLM SECURITY GATEWAY - WEEK 4")
    print("="*60)
    print("\n✅ Microsoft Presidio PII Redaction: ACTIVE")
    print("✅ Rebuff Prompt Injection Detection: ACTIVE")
    print("✅ SOC Dashboard: ACTIVE (http://localhost:8000/dashboard)")
    print("\n📋 API Keys:")
    for key, info in USERS.items():
        print(f"   {info['name']} ({info['department']}): {key}")
    print("\n📍 Endpoints:")
    print("   POST /v1/chat/completions/{api_key} - Send LLM request")
    print("   GET  /dashboard - SOC Dashboard")
    print("   GET  /stats - Gateway statistics")
    print("   GET  /logs/{api_key} - View audit logs")
    print("   GET  /docs - Swagger documentation")
    print("="*60 + "\n")
    
    await db_service.init_db()
    print("✅ Database ready")
    yield
    await db_service.close_db()

app = FastAPI(
    title="LLM Security Gateway",
    description="Enterprise LLM Security Gateway with PII Redaction, Prompt Injection Detection, and SOC Dashboard",
    version="4.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# BASIC ENDPOINTS
# ============================================================

@app.get("/")
async def root():
    return {
        "service": "LLM Security Gateway",
        "status": "operational",
        "version": "4.0.0",
        "features": [
            "PII Redaction (Microsoft Presidio)",
            "Prompt Injection Detection (Rebuff + Heuristics)",
            "SOC Dashboard",
            "Audit Logging (SQLite)",
            "RBAC (Role-Based Access Control)"
        ],
        "endpoints": {
            "dashboard": "/dashboard",
            "docs": "/docs",
            "stats": "/stats",
            "chat": "/v1/chat/completions/{api_key}"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "pii_redaction": "active",
        "threat_detection": "active",
        "database": "connected",
        "timestamp": time.time()
    }

# ============================================================
# SOC DASHBOARD ENDPOINT
# ============================================================

@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard():
    """Professional SOC Dashboard with real-time security metrics"""
    
    # Get stats from database
    stats = await db_service.get_stats()
    
    # Get recent threat alerts
    threat_report = await db_service.get_threat_report(limit=20)
    recent_alerts = threat_report.get("recent_threats", [])
    
    # Format alerts for dashboard
    formatted_alerts = []
    for alert in recent_alerts:
        formatted_alerts.append({
            "timestamp": alert.get("timestamp", ""),
            "user_id": alert.get("user_id", "Unknown"),
            "attack_types": alert.get("attack_types", ["Unknown"]),
            "confidence": int(alert.get("confidence", 0) * 100),
            "blocked": alert.get("blocked", False)
        })
    
    # Generate HTML dashboard
    html = generate_dashboard_html(stats, formatted_alerts)
    return HTMLResponse(content=html)

# ============================================================
# STATISTICS ENDPOINT
# ============================================================

@app.get("/stats")
async def get_stats():
    """Get gateway statistics including PII and threat metrics"""
    return await db_service.get_stats()

# ============================================================
# LOGS ENDPOINT (Requires API Key)
# ============================================================

@app.get("/logs/{api_key}")
async def get_logs(api_key: str, limit: int = 20):
    """View audit logs - requires valid API key"""
    user_info = verify_api_key(api_key)
    
    # Check if user has permission to view logs
    if "view_logs" not in user_info.get("permissions", []) and "full_access" not in user_info.get("permissions", []):
        raise HTTPException(status_code=403, detail="Access denied: insufficient permissions")
    
    logs = await db_service.get_logs(limit=limit)
    return {
        "user": user_info["name"],
        "role": user_info["role"],
        "department": user_info["department"],
        "total_logs": len(logs),
        "logs": logs
    }

# ============================================================
# THREAT REPORT ENDPOINT (Security Team Only)
# ============================================================

@app.get("/threats/{api_key}")
async def get_threat_report(api_key: str, limit: int = 50):
    """Get detailed threat report - security team only"""
    user_info = verify_api_key(api_key)
    
    # Only security role or admin can view threat reports
    if user_info["role"] not in ["security", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied: security team only")
    
    report = await db_service.get_threat_report(limit=limit)
    return report

# ============================================================
# PII REPORT ENDPOINT (Compliance Team Only)
# ============================================================

@app.get("/pii-report/{api_key}")
async def get_pii_report(api_key: str, limit: int = 50):
    """Get detailed PII detection report - compliance team only"""
    user_info = verify_api_key(api_key)
    
    # Only admin can view PII reports (sensitive data)
    if user_info["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied: admin only")
    
    report = await db_service.get_pii_report(limit=limit)
    return report

# ============================================================
# MAIN CHAT ENDPOINT WITH PII REDACTION + THREAT DETECTION + RBAC
# ============================================================

@app.post("/v1/chat/completions/{api_key}")
async def chat_completion(
    api_key: str,
    request: ChatRequest,
    background_tasks: BackgroundTasks,
    raw_request: Request
):
    """
    Send a chat completion request with:
    - Automatic PII redaction (Presidio)
    - Prompt injection detection (Rebuff + heuristics)
    - RBAC model access control
    """
    
    start_time = time.time()
    
    # Verify API key and get user info
    user_info = verify_api_key(api_key)
    user_name = user_info["name"]
    user_role = user_info["role"]
    user_dept = user_info["department"]
    
    # RBAC: Check model access
    if not check_model_access(user_info, request.model):
        raise HTTPException(
            status_code=403, 
            detail=f"Access denied: {user_role} role does not have access to model '{request.model}'. Contact your administrator."
        )
    
    # Get the user's message
    original_prompt = request.messages[-1].content if request.messages else ""
    
    # === PROMPT INJECTION DETECTION ===
    is_injection, threat_details = await threat_service.detect_prompt_injection(original_prompt)
    
    # Block if injection detected with high confidence
    if is_injection and threat_details["confidence"] > 0.7:
        response_text = f"[BLOCKED] Security Alert: Prompt injection detected. Attack type: {', '.join(threat_details['attack_types'])}"
        
        response_data = {
            "id": str(uuid.uuid4()),
            "object": "chat.completion",
            "created": int(time.time()),
            "model": request.model,
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": response_text},
                "finish_reason": "stop"
            }],
            "security": {
                "blocked": True,
                "block_reason": "prompt_injection",
                "attack_types": threat_details["attack_types"],
                "confidence": threat_details["confidence"]
            },
            "user": {
                "name": user_name,
                "role": user_role,
                "department": user_dept
            }
        }
        
        # Log blocked request
        duration_ms = int((time.time() - start_time) * 1000)
        background_tasks.add_task(
            db_service.log_request,
            {
                "user_id": user_name,
                "department": user_dept,
                "provider": "echo",
                "model": request.model,
                "temperature": request.temperature,
                "max_tokens": request.max_tokens,
                "original_prompt": original_prompt,
                "original_response": response_text,
                "blocked": True,
                "block_reason": f"prompt_injection: {', '.join(threat_details['attack_types'])}",
                "prompt_injection_detected": True,
                "injection_confidence": threat_details["confidence"],
                "injection_attack_type": ", ".join(threat_details["attack_types"]),
                "client_ip": raw_request.client.host if raw_request.client else None,
                "user_agent": raw_request.headers.get("user-agent"),
                "response_time_ms": duration_ms
            }
        )
        
        return response_data
    
    # === PII DETECTION & REDACTION (only if not blocked) ===
    detected_pii = await pii_service.detect_pii(original_prompt)
    redacted_prompt, pii_mapping = await pii_service.redact_pii(original_prompt)
    
    pii_types = list(set([p["entity_type"] for p in detected_pii]))
    
    if detected_pii:
        print(f"🔐 PII Detected for {user_name}: {pii_types}")
    
    if is_injection:
        print(f"⚠️ Prompt Injection Detected (low confidence) for {user_name}: {threat_details['attack_types']}")
    
    # Generate response using redacted prompt
    response_text = f"[Echo] {user_name} ({user_dept}) said: {redacted_prompt}"
    
    # === DEANONYMIZE RESPONSE (Restore original PII) ===
    final_response = await pii_service.deanonymize(response_text, pii_mapping)
    
    response_data = {
        "id": str(uuid.uuid4()),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": final_response},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": len(original_prompt) // 4,
            "completion_tokens": len(final_response) // 4,
            "total_tokens": (len(original_prompt) + len(final_response)) // 4
        },
        "security": {
            "pii_detected": len(detected_pii) > 0,
            "pii_types": pii_types,
            "pii_count": len(detected_pii),
            "prompt_injection_detected": is_injection,
            "injection_confidence": threat_details.get("confidence", 0),
            "injection_types": threat_details.get("attack_types", [])
        },
        "user": {
            "name": user_name,
            "role": user_role,
            "department": user_dept
        }
    }
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log to database
    background_tasks.add_task(
        db_service.log_request,
        {
            "user_id": user_name,
            "department": user_dept,
            "provider": "echo",
            "model": request.model,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "original_prompt": original_prompt,
            "redacted_prompt": redacted_prompt,
            "original_response": final_response,
            "redacted_response": response_text,
            "pii_detected": len(detected_pii) > 0,
            "pii_types": pii_types,
            "pii_count": len(detected_pii),
            "prompt_injection_detected": is_injection,
            "injection_confidence": threat_details.get("confidence", 0),
            "injection_attack_type": ", ".join(threat_details.get("attack_types", [])),
            "blocked": False,
            "client_ip": raw_request.client.host if raw_request.client else None,
            "user_agent": raw_request.headers.get("user-agent"),
            "response_time_ms": duration_ms
        }
    )
    
    return response_data

# ============================================================
# RUN THE APPLICATION
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway:app", host="0.0.0.0", port=8000, reload=True)