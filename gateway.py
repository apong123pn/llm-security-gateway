# gateway.py - WORKING VERSION WITH REQUEST BODY
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from contextlib import asynccontextmanager
from dotenv import load_dotenv
import time
import uuid
import os

load_dotenv()
from app.database import DatabaseService

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
# DATABASE
# ============================================================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./audit_logs.db")
db_service = DatabaseService(DATABASE_URL)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("\n🚀 Starting LLM Security Gateway...")
    await db_service.init_db()
    print("✅ Database ready")
    yield
    await db_service.close_db()

# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="LLM Security Gateway",
    description="Enterprise LLM Security Gateway",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple API key storage
API_KEYS = {
    "admin-key-12345": "Admin User",
    "test-key-67890": "Test User",
}

# ============================================================
# SIMPLE ENDPOINTS (No complex auth)
# ============================================================

@app.get("/")
async def root():
    return {"message": "LLM Security Gateway Running", "docs": "/docs"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/stats")
async def get_stats():
    return await db_service.get_stats()

# ============================================================
# CHAT ENDPOINT - Using path parameter for API key (temporary)
# This WILL show the request body in Swagger
# ============================================================

@app.post("/v1/chat/completions/{api_key}")
async def chat_completion(
    api_key: str,
    request: ChatRequest,
    background_tasks: BackgroundTasks,
    raw_request: Request
):
    """
    Send a chat completion request.
    
    Replace {api_key} with your API key:
    - admin-key-12345
    - test-key-67890
    
    The request body should contain messages.
    """
    
    # Verify API key
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    user_name = API_KEYS[api_key]
    start_time = time.time()
    
    # Get the user's message
    user_message = request.messages[-1].content if request.messages else ""
    
    # Echo response
    response_text = f"[Echo] {user_name} said: {user_message}"
    
    response = {
        "id": str(uuid.uuid4()),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": response_text},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": len(user_message) // 4,
            "completion_tokens": len(response_text) // 4,
            "total_tokens": (len(user_message) + len(response_text)) // 4
        }
    }
    
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
            "original_prompt": user_message,
            "original_response": response_text,
            "blocked": False,
            "client_ip": raw_request.client.host if raw_request.client else None,
            "user_agent": raw_request.headers.get("user-agent"),
            "response_time_ms": int((time.time() - start_time) * 1000)
        }
    )
    
    return response

# ============================================================
# LOGS ENDPOINT
# ============================================================

@app.get("/logs/{api_key}")
async def get_logs(api_key: str, limit: int = 20):
    if api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    logs = await db_service.get_logs(limit=limit)
    return {"logs": logs}

# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*60)
    print("🔐 LLM SECURITY GATEWAY")
    print("="*60)
    print("\n📋 API Keys (put in URL path):")
    print("   http://localhost:8000/v1/chat/completions/admin-key-12345")
    print("   http://localhost:8000/v1/chat/completions/test-key-67890")
    print("\n📍 Swagger Docs: http://localhost:8000/docs")
    print("="*60)
    
    uvicorn.run("gateway:app", host="0.0.0.0", port=8000, reload=True)