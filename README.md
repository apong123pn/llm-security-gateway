# Enterprise LLM & GenAI Security Gateway

**Production-grade security proxy for Large Language Models (LLMs)**

A robust API gateway that protects enterprise applications from PII leakage, prompt injections, and harmful content when interacting with LLMs like Groq, OpenAI, etc.

---

## ✅ Project Progress

| Week | Status          | Key Deliverables |
|------|-----------------|------------------|
| 1    | ✅ Completed    | FastAPI Proxy, Rate Limiting, Basic Architecture |
| 2    | ✅ Completed    | Microsoft Presidio + Regex PII Redaction, Deanonymization, Audit Logging |
| 3    | ✅ Completed    | Prompt Injection Detection, Content Safety Filter, Risk-based Blocking |
| 4    | In Progress    | SOC Compliance Dashboard, RBAC, Docker |

---

## Features Implemented

- **PII/PHI Redaction** (Name, Email, Phone, Aadhaar, PAN, Credit Card, etc.)
- **Deanonymization** (Restores original data in final response)
- **Prompt Injection Defense** (Blocks DAN, "ignore previous instructions", etc.)
- **Content Safety Filter** (Blocks harmful/toxic responses)
- **Professional SOC Dashboard** (`/dashboard`)
- **Comprehensive Audit Logging**
- **API Key Authentication**

---

## Tech Stack

- **Framework**: FastAPI + Uvicorn
- **LLM Backend**: Groq (llama-3.1-8b-instant)
- **PII Detection**: Presidio + Regex
- **Security**: Custom Prompt Injection + Content Safety Engine
- **Logging**: Structured JSONL with Dashboard

---

## How to Run

```powershell
# 1. Activate environment
venv\Scripts\activate

# 2. Start server
uvicorn app.main:app --reload --port 8000