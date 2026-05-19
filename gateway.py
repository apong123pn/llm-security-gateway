# gateway.py - With PII Redaction + Prompt Injection Detection (Week 3)
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
# API KEYS
# ============================================================

API_KEYS = {
    "admin-key-12345": "Admin User",
    "test-key-67890": "Test User",
}

# ============================================================
# APP SETUP
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n" + "="*60)
    print("🔐 LLM SECURITY GATEWAY - WEEK 3")
    print("="*60)
    print("\n✅ Microsoft Presidio PII Redaction: ACTIVE")
    print("✅ Rebuff Prompt Injection Detection: ACTIVE")
    print("\n📋 API Keys:")
    print("   Admin: admin-key-12345")
    print("   Test: test-key-67890")
    print("\n📍 Swagger Docs: http://localhost:8000/docs")
    print("="*60 + "\n")
    
    await db_service.init_db()
    print("✅ Database ready")
    yield
    await db_service.close_db()

app = FastAPI(
    title="LLM Security Gateway",
    description="Enterprise LLM Security Gateway with PII Redaction & Prompt Injection Detection",
    version="3.0.0",
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
# ENDPOINTS
# ============================================================

@app.get("/")
async def root():
    return {
        "service": "LLM Security Gateway",
        "status": "operational",
        "version": "3.0.0",
        "features": [
            "PII Redaction (Microsoft Presidio)",
            "Prompt Injection Detection (Rebuff + Heuristics)",
            "Audit Logging (SQLite)",
            "API Key Authentication"
        ]
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "pii_redaction": "active", "threat_detection": "active"}

@app.get("/stats")
async def get_stats():
    return await db_service.get_stats()

@app.get("/logs/{api_key}")
async def get_logs(api_key: str, limit: int = 20):
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    logs = await db_service.get_logs(limit=limit)
    return {"logs": logs}

# ============================================================
# MAIN CHAT ENDPOINT WITH PII REDACTION + THREAT DETECTION
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
    """
    
    start_time = time.time()
    
    # Verify API key
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    user_name = API_KEYS[api_key]
    
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
            }
        }
        
        # Log blocked request
        duration_ms = int((time.time() - start_time) * 1000)
        background_tasks.add_task(
            db_service.log_request,
            {
                "user_id": user_name,
                "department": "unknown",
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
        print(f"🔐 PII Detected: {pii_types}")
    
    if is_injection:
        print(f"⚠️ Prompt Injection Detected (low confidence): {threat_details['attack_types']}")
    
    # Generate response using redacted prompt
    response_text = f"[Echo with Security] {user_name} said: {redacted_prompt}"
    
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
        }
    }
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log to database
    background_tasks.add_task(
        db_service.log_request,
        {
            "user_id": user_name,
            "department": "unknown",
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
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway:app", host="0.0.0.0", port=8000, reload=True)