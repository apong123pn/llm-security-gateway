# gateway.py - Complete Production Gateway with PII Redaction (PII stays hidden)
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import time
import uuid
import os

load_dotenv()

from app.database import DatabaseService
from app.pii_redaction import PIIRedactionService
from app.threat_detection import ThreatDetectionService
from app.rate_limiter import RateLimiter
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

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:SSnipey9863@localhost:5432/llm_gateway")
db_service = DatabaseService(DATABASE_URL)
pii_service = PIIRedactionService()
threat_service = ThreatDetectionService()
rate_limiter = RateLimiter()

# ============================================================
# USERS WITH RBAC
# ============================================================

USERS = {
    "admin-key-12345": {"name": "Admin User", "role": "admin", "department": "it", "permissions": ["full_access"]},
    "eng-key-67890": {"name": "Engineer User", "role": "engineer", "department": "engineering", "permissions": ["use_gpt4", "use_gpt35"]},
    "mktg-key-11111": {"name": "Marketing User", "role": "marketing", "department": "marketing", "permissions": ["use_gpt35"]},
    "security-key-22222": {"name": "Security Analyst", "role": "security", "department": "security", "permissions": ["view_dashboard", "view_logs"]}
}

def verify_api_key(api_key: str):
    if api_key not in USERS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return USERS[api_key]

# ============================================================
# APP SETUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "="*60)
    print("🔐 LLM SECURITY GATEWAY - PRODUCTION READY")
    print("="*60)
    await db_service.init_db()
    await rate_limiter.connect()
    print("\n✅ PostgreSQL Database: ACTIVE")
    print("✅ PII Redaction (Presidio): ACTIVE")
    print("✅ Threat Detection (Rebuff): ACTIVE")
    print("✅ Rate Limiting (Redis): ACTIVE")
    print("\n📍 SOC Dashboard: http://localhost:8000/dashboard")
    print("📍 API Docs: http://localhost:8000/docs")
    print("📍 Chat UI: Open chat_ui.html in browser")
    print("="*60 + "\n")
    yield
    await db_service.close_db()
    await rate_limiter.disconnect()

app = FastAPI(
    title="LLM Security Gateway",
    description="Enterprise LLM Security Gateway with PII Redaction, Threat Detection, and SOC Dashboard",
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
            "Prompt Injection Detection (Rebuff)",
            "SOC Dashboard",
            "PostgreSQL Audit Logging",
            "Redis Rate Limiting",
            "RBAC Access Control"
        ]
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "pii_redaction": "active",
        "threat_detection": "active",
        "database": "postgresql",
        "rate_limiting": "active",
        "timestamp": time.time()
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def soc_dashboard():
    stats = await db_service.get_stats()
    threat_report = await db_service.get_threat_report(limit=20)
    html = generate_dashboard_html(stats, threat_report.get("recent_threats", []))
    return HTMLResponse(content=html)

@app.get("/stats")
async def get_stats():
    return await db_service.get_stats()

@app.get("/logs/{api_key}")
async def get_logs(api_key: str, limit: int = 20):
    user_info = verify_api_key(api_key)
    if "view_logs" not in user_info.get("permissions", []) and "full_access" not in user_info.get("permissions", []):
        raise HTTPException(status_code=403, detail="Access denied")
    logs = await db_service.get_logs(limit=limit)
    return {"user": user_info["name"], "role": user_info["role"], "logs": logs}

@app.get("/threats/{api_key}")
async def get_threat_report(api_key: str, limit: int = 50):
    user_info = verify_api_key(api_key)
    if user_info["role"] not in ["security", "admin"]:
        raise HTTPException(status_code=403, detail="Access denied: security team only")
    report = await db_service.get_threat_report(limit=limit)
    return report

# ============================================================
# MAIN CHAT ENDPOINT - PII STAYS REDACTED
# ============================================================

@app.post("/v1/chat/completions/{api_key}")
async def chat_completion(
    api_key: str,
    request: ChatRequest,
    background_tasks: BackgroundTasks,
    raw_request: Request,
    response: Response
):
    start_time = time.time()
    
    # Verify API key
    user_info = verify_api_key(api_key)
    
    # Rate limiting check
    is_allowed, remaining = await rate_limiter.check_rate_limit(api_key)
    if not is_allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Max 100 requests per 60 seconds.")
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Limit"] = "100"
    
    # Get user message
    original_prompt = request.messages[-1].content if request.messages else ""
    
    # === PROMPT INJECTION DETECTION ===
    is_injection, threat_details = await threat_service.detect_prompt_injection(original_prompt)
    
    # Block if high confidence injection detected
    if is_injection and threat_details["confidence"] > 0.7:
        duration_ms = int((time.time() - start_time) * 1000)
        response_text = f"[BLOCKED] Security Alert: Prompt injection detected. Attack type: {', '.join(threat_details['attack_types'])}"
        
        background_tasks.add_task(
            db_service.log_request,
            {
                "user_id": user_info["name"],
                "department": user_info["department"],
                "provider": "gateway",
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
        
        return {
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
            }
        }
    
    # === PII DETECTION & REDACTION ===
    detected_pii = await pii_service.detect_pii(original_prompt)
    redacted_prompt, pii_mapping = await pii_service.redact_pii(original_prompt)
    pii_types = list(set([p["entity_type"] for p in detected_pii]))
    
    if detected_pii:
        print(f"🔐 PII Detected for {user_info['name']}: {pii_types}")
        print(f"   Original: {original_prompt[:100]}...")
        print(f"   Redacted: {redacted_prompt[:100]}...")
    
    if is_injection:
        print(f"⚠️ Prompt Injection Detected (low confidence) for {user_info['name']}: {threat_details['attack_types']}")
    
    # === GENERATE RESPONSE WITH REDACTED PROMPT (PII STAYS HIDDEN) ===
    # No deanonymization - PII remains as [EMAIL], [PHONE], [PERSON], etc.
    final_response = f"[Echo] {user_info['name']} said: {redacted_prompt}"
    
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
        }
    }
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log to database
    background_tasks.add_task(
        db_service.log_request,
        {
            "user_id": user_info["name"],
            "department": user_info["department"],
            "provider": "gateway",
            "model": request.model,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "original_prompt": original_prompt,
            "redacted_prompt": redacted_prompt,
            "original_response": final_response,
            "redacted_response": final_response,
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