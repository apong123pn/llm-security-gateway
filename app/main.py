from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import re
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy with Basic PII Redaction",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"

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

def redact_pii(text: str) -> str:
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', text)
    text = re.sub(r'\b(?:\+?91|0)?[789]\d{9}\b', '[REDACTED_PHONE]', text)
    text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CARD]', text)
    text = re.sub(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', '[REDACTED_NAME]', text)
    return text

@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content
        redacted_text = redact_pii(original_text)
        request.messages[0].content = redacted_text

        print(f"Original : {original_text[:150]}...")
        print(f"Redacted : {redacted_text[:150]}...")

        # Check API Key
        api_key = os.getenv('LLM_API_KEY')
        if not api_key or api_key.startswith("sk-your"):
            return {
                "warning": "No valid LLM_API_KEY found in .env file",
                "redacted_prompt": redacted_text,
                "message": "Add your Groq/OpenAI key in .env to get real response"
            }

        # Call LLM
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                TARGET_LLM_URL, 
                json=request.dict(), 
                headers=headers, 
                timeout=30.0
            )
        
        return response.json()

    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"LLM API connection error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))