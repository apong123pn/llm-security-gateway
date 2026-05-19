from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import time
import uuid
import logging

from config.settings import settings
from app.services.database import DatabaseService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database service
db_service = DatabaseService()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    await db_service.init_db()
    logger.info("✅ Database connected")
    yield
    # Shutdown
    await db_service.close_db()
    logger.info("👋 Shutdown complete")

app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise LLM Security Gateway with PII Redaction",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temporary users for RBAC (Week 4)
USERS = {
    "admin-key-12345": {"role": "admin", "name": "Admin User", "department": "it"},
    "test-key-67890": {"role": "user", "name": "Test User", "department": "engineering"},
}

def verify_api_key(x_api_key: str):
    """Simple API key verification"""
    if x_api_key not in USERS:
        return None
    return USERS[x_api_key]

@app.get("/")
async def root():
    return {
        "message": "LLM Security Gateway is running!", 
        "status": "healthy",
        "features": ["Database Logging", "API Gateway", "RBAC Ready"]
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/stats")
async def get_stats():
    """Get gateway statistics"""
    stats = await db_service.get_stats()
    return stats

@app.post("/v1/chat/completions")
async def proxy_to_openai(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str = None
):
    """Main proxy endpoint with audit logging"""
    
    start_time = time.time()
    
    # Verify API key
    user_info = verify_api_key(x_api_key)
    if not user_info:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Parse request body
    body = await request.json()
    original_prompt = body.get("messages", [{}])[-1].get("content", "")
    
    # For now, just echo back (we'll add real OpenAI integration in next step)
    # This is a placeholder response
    response_data = {
        "choices": [{
            "message": {
                "content": f"Echo: {original_prompt[:100]}"
            }
        }]
    }
    
    # Calculate duration
    duration_ms = int((time.time() - start_time) * 1000)
    
    # Log to database
    background_tasks.add_task(
        db_service.log_request,
        {
            "user_id": user_info["name"],
            "department": user_info["department"],
            "model": body.get("model", "unknown"),
            "original_prompt": original_prompt,
            "original_response": response_data["choices"][0]["message"]["content"],
            "blocked": False,
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "response_time_ms": duration_ms
        }
    )
    
    return response_data

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*50)
    print("🔐 LLM SECURITY GATEWAY")
    print("="*50)
    print("\n📋 API Keys for Testing:")
    for key, info in USERS.items():
        print(f"   {info['name']}: {key}")
    print("\n📍 API Docs: http://localhost:8000/docs")
    print("📍 Stats: http://localhost:8000/stats")
    print("\n" + "="*50)
    uvicorn.run(app, host="0.0.0.0", port=8000)