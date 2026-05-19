# 🔐 Enterprise LLM & GenAI Security Gateway

**Production-grade security proxy for Large Language Models (LLMs)**

A robust API gateway that protects enterprise applications from PII leakage, prompt injections, and harmful content when interacting with LLMs like OpenAI, Anthropic, and others.

---

## 📊 Project Progress

| Week | Status | Key Deliverables |
|------|--------|------------------|
| Week 1 | ✅ Completed | FastAPI Gateway, API Key Authentication, SQLite Database, Audit Logging, Stats Endpoint |
| Week 2 | 🔄 In Progress | Microsoft Presidio PII Redaction |
| Week 3 | 📋 Planned | Prompt Injection Detection with Rebuff |
| Week 4 | 📋 Planned | SOC Dashboard, RBAC, Kubernetes Deployment |

---

## ✨ Features

- **FastAPI Gateway** - High-performance async API gateway
- **API Key Authentication** - Multiple keys with role-based access
- **Audit Logging** - Persistent SQLite database storage
- **Request/Response Tracking** - Full logging with timestamps
- **Stats Endpoint** - Real-time gateway statistics
- **Logs Endpoint** - Searchable audit trail
- **Swagger/OpenAPI Docs** - Interactive API documentation at `/docs`

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI + Uvicorn |
| Database | SQLite |
| ORM | SQLAlchemy |
| Authentication | API Keys |
| Language | Python 3.11+ |

---

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/YOUR_USERNAME/llm-security-gateway.git
cd llm-security-gateway
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python gateway.py