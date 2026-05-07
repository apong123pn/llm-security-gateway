from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy for LLM APIs",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Target LLM (we'll make this configurable later)
TARGET_LLM_URL = "https://api.openai.com/v1/chat/completions"

@app.get("/")
async def root():
    return {"message": "Enterprise LLM Security Gateway is running! 🚀"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# === BASIC PROXY ENDPOINT ===
@app.post("/v1/chat/completions")
async def proxy_llm(request: Request):
    try:
        body = await request.json()
        
        headers = {
            "Authorization": f"Bearer {os.getenv('LLM_API_KEY')}",
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                TARGET_LLM_URL,
                json=body,
                headers=headers,
                timeout=60.0
            )
            
        return response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))