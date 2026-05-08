# Enterprise LLM & GenAI Security Gateway

**Production-grade security proxy for Large Language Models**

A secure gateway that sits between corporate users and external LLM APIs (like Groq, OpenAI, etc.) to prevent data leakage and ensure compliance.

## Features Implemented

### ✅ Completed (Week 1 & Week 2)

- **Basic Secure Proxy** – Routes requests to LLM APIs
- **Rate Limiting** – 10 requests per minute per IP
- **Advanced PII Redaction** – Automatically detects and redacts:
  - Names, Emails, Phone Numbers
  - Credit/Debit Cards
  - Aadhaar Numbers
  - PAN Numbers
  - IP Addresses, URLs, etc.
- **Deanonymization** – Restores original sensitive data in the final response to the user
- **Comprehensive Audit Logging** – Full request/response logging with PII detection details (`audit_logs.jsonl`)
- **Logs Viewer** – View recent audit logs at `/logs` endpoint

### Planned (Week 3 & 4)
- Prompt Injection Detection (Rebuff)
- Content Safety Filtering
- Authentication & RBAC
- Dashboard for SOC team
- Docker + Kubernetes deployment

## Tech Stack

- **Backend**: Python + FastAPI
- **PII Detection**: Regex + Presidio Analyzer/Anonymizer
- **Rate Limiting**: SlowAPI
- **Logging**: JSON Lines format
- **Deployment**: Ready for Docker

## Project Status

- **Week 1**: Completed (Proxy + Rate Limiting)
- **Week 2**: Completed (PII Redaction + Deanonymization + Logging)
- **Week 3**: In Progress

## How to Run Locally

```bash
# 1. Activate virtual environment
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Add LLM API key
# Put your Groq key in .env file:
# LLM_API_KEY=gsk_xxxxxxxxxxxxxxxx

# 4. Start server
uvicorn app.main:app --reload --port 8000