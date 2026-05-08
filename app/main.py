from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import re
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List, Dict

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy with PII Redaction + Deanonymization",
    version="0.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# ==================== REDACTION + DEANONYMIZATION ====================
def redact_pii_with_mapping(text: str) -> tuple[str, Dict[str, str]]:
    mapping = {}
    redacted_text = text

    patterns = {
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[REDACTED_EMAIL]',
        r'\b(?:\+?91|0)?[6-9]\d{9}\b': '[REDACTED_PHONE]',
        r'\b(?:\d[ -]*?){13,16}\b': '[REDACTED_CARD]',
        r'\b\d{4}\s?\d{4}\s?\d{4}\b': '[REDACTED_AADHAAR]',
        r'\b[A-Z]{5}\d{4}[A-Z]\b': '[REDACTED_PAN]',
        r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b': '[REDACTED_NAME]',
    }

    for pattern, placeholder in patterns.items():
        matches = re.findall(pattern, redacted_text)
        for match in matches:
            if match and placeholder not in mapping:
                mapping[placeholder] = match
                redacted_text = redacted_text.replace(match, placeholder, 1)

    return redacted_text, mapping

def deanonymize_response(text: str, mapping: Dict[str, str]) -> str:
    for placeholder, original in mapping.items():
        text = text.replace(placeholder, original)
    return text

# ============================================================

@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content
        redacted_text, mapping = redact_pii_with_mapping(original_text)
        
        request.messages[0].content = redacted_text

        print(f"🔴 Original : {original_text[:250]}...")
        print(f"🟠 Redacted: {redacted_text[:250]}...")

        # Simulate LLM Response
        llm_reply = "I have reviewed your information. Your name is [REDACTED_NAME], Aadhaar number is [REDACTED_AADHAAR], PAN is [REDACTED_PAN], phone is [REDACTED_PHONE], and email is [REDACTED_EMAIL]. Everything looks good."

        # Deanonymize before sending back to user
        final_response = deanonymize_response(llm_reply, mapping)

        print(f"🟢 Final Response (Deanonymized): {final_response[:300]}...")

        return {
            "status": "success",
            "redacted_prompt_used": redacted_text,
            "llm_response": final_response,
            "note": "Deanonymization applied successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))