from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import re
import json
from datetime import datetime
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List, Dict

# Import logs router
from app.logs import router as logs_router

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy with PII Redaction + Deanonymization + Audit Logging",
    version="0.4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include logs router
app.include_router(logs_router)

TARGET_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"

# Log file
LOG_FILE = "audit_logs.jsonl"

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

# ==================== PII REDACTION + MAPPING ====================
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
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b': '[REDACTED_IP]',
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

def log_request_response(log_data: dict):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            json.dump(log_data, f, ensure_ascii=False)
            f.write("\n")
    except:
        pass

# ============================================================

@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    start_time = datetime.now()
    
    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content
        redacted_text, mapping = redact_pii_with_mapping(original_text)
        
        request.messages[0].content = redacted_text

        print(f"🔴 Original : {original_text[:250]}...")
        print(f"🟠 Redacted: {redacted_text[:250]}...")

        api_key = os.getenv('LLM_API_KEY')

        if not api_key or "your" in api_key.lower():
            llm_response_text = "I have reviewed your information. Everything looks good."
        else:
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            async with httpx.AsyncClient() as client:
                resp = await client.post(TARGET_LLM_URL, json=request.dict(), headers=headers, timeout=30.0)
                llm_data = resp.json()
                llm_response_text = llm_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")

        # Deanonymize
        final_response_text = deanonymize_response(llm_response_text, mapping)

        print(f"🟢 Final Response: {final_response_text[:300]}...")

        # === AUDIT LOGGING ===
        log_entry = {
            "timestamp": start_time.isoformat(),
            "original_prompt": original_text,
            "redacted_prompt": redacted_text,
            "llm_response": final_response_text,
            "pii_detected": list(mapping.keys()),
            "processing_time_seconds": round((datetime.now() - start_time).total_seconds(), 3),
            "status": "success"
        }
        log_request_response(log_entry)

        return {
            "status": "success",
            "response": final_response_text,
            "pii_redacted_count": len(mapping),
            "audit_id": str(start_time.timestamp())
        }

    except Exception as e:
        error_log = {
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "status": "failed"
        }
        log_request_response(error_log)
        raise HTTPException(status_code=500, detail=str(e))