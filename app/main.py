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
    description="Week 3 - Fixed Prompt Injection",
    version="0.5.2"
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

# Strong Prompt Injection Detection
def detect_prompt_injection(text: str) -> bool:
    if not text:
        return False
    text_lower = text.lower()

    injection_keywords = [
        "ignore previous", "ignore all previous", "disregard previous", 
        "forget everything", "new instructions", "you are now", 
        "dan mode", "developer mode", "jailbreak", "system prompt", 
        "override", "do not follow", "reveal your instructions"
    ]
    
    for keyword in injection_keywords:
        if keyword in text_lower:
            return True
            
    # Code execution attempts
    if re.search(r'\b(exec|eval|os\.system|subprocess|shell)', text_lower):
        return True
        
    return False

# PII Redaction
def redact_pii(text: str) -> str:
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[REDACTED_EMAIL]', text)
    text = re.sub(r'\b(?:\+?91|0)?[6-9]\d{9}\b', '[REDACTED_PHONE]', text)
    text = re.sub(r'\b(?:\d[ -]*?){13,16}\b', '[REDACTED_CARD]', text)
    text = re.sub(r'\b\d{4}\s?\d{4}\s?\d{4}\b', '[REDACTED_AADHAAR]', text)
    text = re.sub(r'\b[A-Z]{5}\d{4}[A-Z]\b', '[REDACTED_PAN]', text)
    text = re.sub(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b', '[REDACTED_NAME]', text)
    return text

@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content

        # === INJECTION CHECK ===
        if detect_prompt_injection(original_text):
            raise HTTPException(
                status_code=403, 
                detail="🚫 BLOCKED: Prompt injection detected"
            )

        # PII Redaction
        redacted_text = redact_pii(original_text)
        request.messages[0].content = redacted_text

        # Call LLM
        headers = {
            "Authorization": f"Bearer {os.getenv('LLM_API_KEY')}",
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
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))