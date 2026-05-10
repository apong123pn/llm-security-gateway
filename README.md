# Enterprise LLM & GenAI Security Gateway

**Production-grade secure proxy for Large Language Models**

A robust security gateway that sits between internal users and external LLM providers (Groq, OpenAI, etc.) to prevent data leakage, prompt injections, and harmful content.

## Features Implemented

### ✅ Week 1 & Week 2
- FastAPI-based secure proxy
- Rate Limiting
- **Advanced PII Redaction** (Hybrid: Microsoft Presidio + Regex)
- Deanonymization (Restores original data in final response)
- Comprehensive Audit Logging (`audit_logs.jsonl`)
- Logs Viewer (`/logs`)

### ✅ Week 3 (In Progress / Mostly Done)
- **Prompt Injection Detection** with risk scoring
- Content Safety Filter (blocks harmful/toxic responses)
- Basic API Key Authentication

### Planned for Week 4
- Admin Dashboard
- Role-Based Access Control (RBAC)
- Docker + Kubernetes deployment
- PostgreSQL integration

## Tech Stack

- **Backend**: Python + FastAPI
- **PII Detection**: Presidio Analyzer + Regex
- **Security**: Prompt Injection Detection + Content Safety
- **Logging**: Structured JSONL logs

## How to Run

```bash
# 1. Activate environment
venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure API Keys
# Add these in .env file: INTERNAL_API_KEY=dev-key-12345
# LLM_API_KEY=your_groq_key
# INTERNAL_API_KEY=dev-key-12345

# 4. Start server
uvicorn app.main:app --reload --port 8000