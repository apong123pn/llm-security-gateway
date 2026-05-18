from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import time
import uuid

# Create FastAPI app
app = FastAPI(
    title="LLM Security Gateway",
    description="Enterprise LLM Security Gateway",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory log storage (temporary, until PostgreSQL is ready)
audit_logs = []

# API Keys for testing
USERS = {
    "admin-key-12345": {"role": "admin", "name": "Admin User", "department": "it"},
    "test-key-67890": {"role": "user", "name": "Test User", "department": "engineering"},
}

def verify_api_key(x_api_key: str):
    """Simple API key verification"""
    return USERS.get(x_api_key)

@app.get("/")
async def root():
    return {
        "message": "LLM Security Gateway is running!",
        "status": "healthy",
        "version": "1.0.0"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/stats")
async def get_stats():
    """Get gateway statistics"""
    total = len(audit_logs)
    blocked = len([l for l in audit_logs if l.get("blocked")])
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "uptime": "running"
    }

@app.post("/v1/chat/completions")
async def proxy_to_openai(request: Request, x_api_key: str = None):
    """Main proxy endpoint with audit logging"""
    
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Verify API key
    user_info = verify_api_key(x_api_key)
    if not user_info:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Parse request body
    body = await request.json()
    original_prompt = body.get("messages", [{}])[-1].get("content", "")
    model = body.get("model", "unknown")
    
    # For now, echo back (we'll add OpenAI later)
    response_data = {
        "id": request_id,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": f"Echo from security gateway: {original_prompt[:200]}"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": len(original_prompt) // 4,
            "completion_tokens": 50,
            "total_tokens": (len(original_prompt) // 4) + 50
        }
    }
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log to in-memory storage
    log_entry = {
        "request_id": request_id,
        "timestamp": time.time(),
        "user_id": user_info["name"],
        "department": user_info["department"],
        "model": model,
        "original_prompt": original_prompt[:500],
        "response_preview": response_data["choices"][0]["message"]["content"][:200],
        "duration_ms": duration_ms,
        "blocked": False,
        "client_ip": request.client.host if request.client else None
    }
    audit_logs.append(log_entry)
    
    # Keep only last 1000 logs
    while len(audit_logs) > 1000:
        audit_logs.pop(0)
    
    return response_data

@app.get("/logs")
async def get_logs(limit: int = 20, x_api_key: str = None):
    """View audit logs"""
    user_info = verify_api_key(x_api_key)
    if not user_info:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Return last N logs
    return {
        "total": len(audit_logs),
        "logs": audit_logs[-limit:]
    }

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("🔐 LLM SECURITY GATEWAY - SIMPLIFIED VERSION")
    print("="*60)
    print("\n✅ This simplified version uses in-memory storage")
    print("✅ PostgreSQL will be added later")
    print("\n📋 API Keys for Testing:")
    for key, info in USERS.items():
        print(f"   {info['name']} ({info['department']}): {key}")
    print("\n📍 Endpoints:")
    print("   POST /v1/chat/completions - Send LLM request")
    print("   GET  /stats - View statistics")
    print("   GET  /logs - View audit logs (requires API key)")
    print("   GET  /docs - Interactive API documentation")
    print("\n" + "="*60)
    uvicorn.run(app, host="0.0.0.0", port=8000)