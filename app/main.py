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
    description="Secure proxy with Advanced PII Redaction",
    version="0.2.1"
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

# ==================== ADVANCED PII REDACTION ====================
def redact_pii(text: str) -> str:
    redaction_map = {}

    # 1. Emails
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', text)
    
    # 2. Phone Numbers (Indian + International)
    text = re.sub(r'\b(?:\+?91|0)?[6-9]\d{9}\b', '[REDACTED_PHONE]', text)
    text = re.sub(r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED_PHONE]', text)
    
    # 3. Credit Cards / Debit Cards
    text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CARD]', text)
    
    # 4. Aadhaar Number (India)
    text = re.sub(r'\b\d{4}\s?\d{4}\s?\d{4}\b', '[REDACTED_AADHAAR]', text)
    
    # 5. PAN Number (India)
    text = re.sub(r'\b[A-Z]{5}\d{4}[A-Z]\b', '[REDACTED_PAN]', text)
    
    # 6. Names (Simple but effective)
    text = re.sub(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', '[REDACTED_NAME]', text)
    
    # 7. IP Addresses
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED_IP]', text)
    
    # 8. URLs with sensitive params
    text = re.sub(r'https?://[^\s]+', '[REDACTED_URL]', text)

    return text

# ============================================================

@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content
        redacted_text = redact_pii(original_text)
        
        request.messages[0].content = redacted_text

        print(f"Original : {original_text[:200]}...")
        print(f"Redacted : {redacted_text[:200]}...")

        # Check API Key
        api_key = os.getenv('LLM_API_KEY')
        if not api_key or "your" in api_key.lower():
            return {
                "status": "success",
                "redacted": True,
                "message": "PII Redaction applied successfully (No LLM key configured)",
                "redacted_prompt": redacted_text
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

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))