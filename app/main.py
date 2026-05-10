from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import re
import json
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
    description="Secure proxy with Strong Content Safety",
    version="0.5.6"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TARGET_LLM_URL = "https://api.groq.com/openai/v1/chat/completions"
LOG_FILE = "audit_logs.jsonl"

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

@app.get("/logs")
async def get_logs(limit: int = 100):
    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in list(f)[-limit:]:
                if line.strip():
                    logs.append(json.loads(line))
    except FileNotFoundError:
        pass
    return {"total_logs": len(logs), "logs": logs}

# ==================== PROMPT INJECTION ====================
def detect_prompt_injection(text: str) -> Tuple[bool, str, float]:
    text_lower = text.lower().strip()
    risk_score = 0.0
    reasons = []

    high_risk = ["ignore previous instructions", "ignore all previous", "disregard previous", 
                 "forget everything", "you are now", "dan mode", "developer mode", 
                 "jailbreak", "system prompt", "override your rules"]
    
    for keyword in high_risk:
        if keyword in text_lower:
            risk_score += 40
            reasons.append(keyword)

    if re.search(r'\b(exec|eval|os\.|subprocess|shell)\b', text_lower):
        risk_score += 50
        reasons.append("code execution")

    return risk_score >= 40, " | ".join(reasons), risk_score


# ==================== STRONGER CONTENT SAFETY FILTER ====================
def is_response_harmful(text: str) -> Tuple[bool, str]:
    text_lower = text.lower()
    
    # Very aggressive dangerous patterns
    dangerous_patterns = [
        r'how to make.*bomb',
        r'how to build.*(bomb|explosive|weapon)',
        r'step by step.*(bomb|explosive|poison|weapon|drug)',
        r'make.*(bomb|poison|weapon|drug)',
        r'hack into|steal credit|child porn|terrorist attack|suicide method'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, text_lower):
            return True, f"Dangerous instructional content detected"

    # Broad harmful keywords
    harmful_keywords = [
        "bomb", "explosive", "molotov", "suicide", "kill yourself", "self harm",
        "child porn", "rape", "nigger", "terrorist", "how to make a bomb",
        "how to kill", "how to hack"
    ]
    
    for word in harmful_keywords:
        if word in text_lower:
            return True, f"Harmful content: {word}"

    return False, ""


# ==================== PII REDACTION ====================
def redact_pii_with_mapping(text: str) -> tuple[str, Dict]:
    mapping = {}
    redacted_text = text

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


def log_event(log_data: dict):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            json.dump(log_data, f, ensure_ascii=False)
            f.write("\n")
    except:
        pass


# ====================== MAIN ENDPOINT ======================
@app.post("/v1/chat/completions")
async def proxy_llm(request: ChatRequest):
    start_time = datetime.now()

    try:
        if not request.messages:
            raise HTTPException(status_code=400, detail="No messages provided")

        original_text = request.messages[0].content

        # 1. Prompt Injection Check
        is_injection, reason, risk_score = detect_prompt_injection(original_text)
        if is_injection:
            print(f"🚫 BLOCKED Injection | Risk: {risk_score:.1f} | {reason}")
            log_event({
                "timestamp": start_time.isoformat(),
                "type": "prompt_injection_blocked",
                "original_prompt": original_text,
                "risk_score": risk_score,
                "reason": reason,
                "status": "blocked"
            })
            raise HTTPException(status_code=403, detail=f"Security Alert: {reason}")

        # 2. PII Redaction
        redacted_text, mapping = redact_pii_with_mapping(original_text)
        request.messages[0].content = redacted_text

        print(f"🔴 Original : {original_text[:200]}...")
        print(f"🟠 Redacted : {redacted_text[:200]}...")

        # Call LLM
        api_key = os.getenv("LLM_API_KEY")
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient() as client:
            response = await client.post(TARGET_LLM_URL, json=request.dict(), headers=headers, timeout=30.0)

        llm_response = response.json()

        # 3. Deanonymize + Content Safety
        if "choices" in llm_response and len(llm_response["choices"]) > 0:
            content = llm_response["choices"][0]["message"].get("content", "")
            deanonymized_content = deanonymize_response(content, mapping)

            is_harmful, harm_reason = is_response_harmful(deanonymized_content)
            if is_harmful:
                print(f"🚫 BLOCKED Harmful Response: {harm_reason}")
                log_event({
                    "timestamp": datetime.now().isoformat(),
                    "type": "harmful_response_blocked",
                    "original_prompt": original_text,
                    "reason": harm_reason,
                    "status": "blocked"
                })
                raise HTTPException(status_code=403, detail="Response blocked: Harmful content detected.")

            llm_response["choices"][0]["message"]["content"] = deanonymized_content

        # Success Log
        log_event({
            "timestamp": start_time.isoformat(),
            "type": "request_processed",
            "pii_detected": list(mapping.keys()),
            "status": "success"
        })

        return llm_response

    except HTTPException as e:
        raise e
    except Exception as e:
        log_event({"timestamp": datetime.now().isoformat(), "error": str(e), "status": "error"})
        raise HTTPException(status_code=500, detail=str(e))