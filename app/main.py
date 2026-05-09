from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import re
from datetime import datetime
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List, Dict

# Presidio
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy with Hybrid PII Redaction (Presidio + Regex)",
    version="0.4.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"

# Initialize Presidio
registry = RecognizerRegistry()
registry.load_predefined_recognizers()
analyzer = AnalyzerEngine(registry=registry)
anonymizer = AnonymizerEngine()

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

# ==================== HYBRID PII REDACTION ====================
def redact_pii_with_mapping(text: str) -> tuple[str, Dict]:
    mapping = {}
    redacted_text = text

    # 1. Presidio Detection
    results = analyzer.analyze(text=text, language="en", score_threshold=0.4)
    anonymized = anonymizer.anonymize(
        text=text,
        analyzer_results=results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"})}
    )
    redacted_text = anonymized.text

    for result in results:
        placeholder = f"[REDACTED_{result.entity_type.upper()}]"
        original = text[result.start:result.end]
        if original:
            mapping[placeholder] = original

    # 2. Strong Regex Fallback (for better coverage)
    regex_patterns = {
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[REDACTED_EMAIL]',
        r'\b(?:\+?91|0)?[6-9]\d{9}\b': '[REDACTED_PHONE]',
        r'\b(?:\d[ -]*?){13,16}\b': '[REDACTED_CARD]',
        r'\b\d{4}\s?\d{4}\s?\d{4}\b': '[REDACTED_AADHAAR]',
        r'\b[A-Z]{5}\d{4}[A-Z]\b': '[REDACTED_PAN]',
        r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b': '[REDACTED_NAME]',
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b': '[REDACTED_IP]',
    }

    for pattern, placeholder in regex_patterns.items():
        matches = re.findall(pattern, redacted_text)
        for match in matches:
            if match and placeholder not in mapping:
                mapping[placeholder] = match
                redacted_text = redacted_text.replace(match, placeholder, 1)

    return redacted_text, mapping


def deanonymize_response(text: str, mapping: Dict) -> str:
    for placeholder, original in mapping.items():
        text = text.replace(placeholder, original)
    return text


# ====================== MAIN ENDPOINT ======================
@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content
        redacted_text, mapping = redact_pii_with_mapping(original_text)
        
        request.messages[0].content = redacted_text

        print(f"🔴 Original : {original_text[:250]}...")
        print(f"🟠 Redacted : {redacted_text[:250]}...")

        # Call LLM
        api_key = os.getenv("LLM_API_KEY")
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

        llm_response = response.json()

        # Deanonymize response
        if "choices" in llm_response and len(llm_response["choices"]) > 0:
            content = llm_response["choices"][0]["message"].get("content", "")
            deanonymized_content = deanonymize_response(content, mapping)
            llm_response["choices"][0]["message"]["content"] = deanonymized_content

        return llm_response

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))