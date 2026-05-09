from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import re
from datetime import datetime
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import List, Dict, Tuple

# Presidio
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

load_dotenv()

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy with Advanced Prompt Injection Defense",
    version="0.5.1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"

# Presidio Setup
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

# ==================== ADVANCED PROMPT INJECTION DETECTION ====================
def detect_prompt_injection(text: str) -> Tuple[bool, str, float]:
    text_lower = text.lower().strip()
    risk_score = 0.0
    reasons = []

    # High Risk Keywords (Weight: 40)
    high_risk = [
        "ignore previous instructions", "ignore all previous", "disregard previous",
        "forget everything", "new instructions", "you are now", "dan mode",
        "developer mode", "jailbreak", "system prompt", "override your rules",
        "do not follow", "bypass your security", "reveal your instructions"
    ]
    for keyword in high_risk:
        if keyword in text_lower:
            risk_score += 40
            reasons.append(f"High-risk keyword: '{keyword}'")

    # Medium Risk (Weight: 25)
    medium_risk = ["repeat your instructions", "output your system prompt", "act as if"]
    for keyword in medium_risk:
        if keyword in text_lower:
            risk_score += 25
            reasons.append(f"Medium-risk pattern: '{keyword}'")

    # Code Execution Attempts
    if re.search(r'\b(exec|eval|os\.|subprocess|system|shell|__import__)\b', text_lower):
        risk_score += 50
        reasons.append("Potential code execution attempt")

    # Too many commands / role-playing
    if len(re.findall(r"you are|act as|pretend|role play", text_lower)) > 2:
        risk_score += 30
        reasons.append("Multiple role-playing attempts")

    # Final Decision
    is_malicious = risk_score >= 40
    reason_str = " | ".join(reasons) if reasons else "Unknown risk"

    return is_malicious, reason_str, risk_score


# ==================== PII REDACTION (Hybrid) ====================
def redact_pii_with_mapping(text: str) -> tuple[str, Dict]:
    mapping = {}
    redacted_text = text

    # Presidio
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

    # Regex fallback
    regex_patterns = {
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '[REDACTED_EMAIL]',
        r'\b(?:\+?91|0)?[6-9]\d{9}\b': '[REDACTED_PHONE]',
        r'\b(?:\d[ -]*?){13,16}\b': '[REDACTED_CARD]',
        r'\b\d{4}\s?\d{4}\s?\d{4}\b': '[REDACTED_AADHAAR]',
        r'\b[A-Z]{5}\d{4}[A-Z]\b': '[REDACTED_PAN]',
        r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b': '[REDACTED_NAME]',
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

        # === Advanced Prompt Injection Check ===
        is_injection, reason, risk_score = detect_prompt_injection(original_text)
        if is_injection:
            print(f"🚫 BLOCKED | Risk Score: {risk_score:.1f} | Reason: {reason}")
            raise HTTPException(
                status_code=403,
                detail=f"Security Alert: Prompt injection detected (Risk: {risk_score:.1f}). Request blocked."
            )

        # === PII Redaction ===
        redacted_text, mapping = redact_pii_with_mapping(original_text)
        request.messages[0].content = redacted_text

        print(f"🔴 Original : {original_text[:200]}...")
        print(f"🟠 Redacted : {redacted_text[:200]}...")

        # Call LLM
        api_key = os.getenv("LLM_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                TARGET_LLM_URL, json=request.dict(), headers=headers, timeout=30.0
            )

        llm_response = response.json()

        # Deanonymize
        if "choices" in llm_response and len(llm_response["choices"]) > 0:
            content = llm_response["choices"][0]["message"].get("content", "")
            deanonymized_content = deanonymize_response(content, mapping)
            llm_response["choices"][0]["message"]["content"] = deanonymized_content

        return llm_response

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))