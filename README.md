@"
# 🔐 Enterprise LLM & GenAI Security Gateway

**Production-grade security proxy for Large Language Models (LLMs)**

A robust API gateway that protects enterprise applications from PII leakage, prompt injections, and harmful content when interacting with LLMs.

## 📊 Project Status

| Week | Status | Key Deliverables |
|------|--------|------------------|
| Week 1 | ✅ Complete | FastAPI Gateway, PostgreSQL Audit Logging |
| Week 2 | ✅ Complete | Microsoft Presidio PII Redaction |
| Week 3 | ✅ Complete | Rebuff Prompt Injection Detection |
| Week 4 | ✅ Complete | SOC Dashboard, RBAC, Docker, Kubernetes |

## ✨ Features

- **PII Detection & Redaction** - Microsoft Presidio (Emails, Phone, Credit Card, SSN, Person, Location, IP, URL)
- **Prompt Injection Detection** - Rebuff + 15+ heuristic patterns
- **Automatic Blocking** - Malicious requests blocked instantly
- **Deanonymization** - Restores original data after redaction
- **PostgreSQL Database** - Persistent audit logging for GDPR/HIPAA/SOC2
- **SOC Dashboard** - Professional real-time security dashboard
- **RBAC** - 4 roles with department-based model access
- **Rate Limiting** - Redis-based (100 requests / 60 seconds)
- **Docker & Kubernetes** - Production-ready deployment

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI + Uvicorn |
| Database | PostgreSQL |
| Cache | Redis |
| PII Detection | Microsoft Presidio |
| Threat Detection | Rebuff + Heuristics |
| Container | Docker |
| Orchestration | Kubernetes |

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/llm-security-gateway.git
cd llm-security-gateway

# Virtual environment
python -m venv venv
venv\Scripts\activate

# Install
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Start services
docker run --name llm-postgres -e POSTGRES_PASSWORD=SSnipey9863 -e POSTGRES_DB=llm_gateway -p 5432:5432 -d postgres:15
docker run --name llm-redis -p 6379:6379 -d redis:7-alpine

# Run gateway
python gateway.py

# Docker Deployment
docker build -t llm-security-gateway .
docker-compose up -d

# Kubernetes Deployment
kubectl apply -f k8s/

# Project Structure
llm-security-gateway/
├── gateway.py
├── app/
│   ├── database.py
│   ├── pii_redaction.py
│   ├── threat_detection.py
│   ├── rate_limiter.py
│   └── dashboard.py
└── k8s/
    ├── deployment.yaml
    ├── service.yaml
    └── hpa.yaml

    # PII Types Detected
    Email Address, Phone Number, Credit Card, SSN, Person Name, Location, IP Address, URL

# Attack Patterns Detected
Instruction Override, DAN Jailbreak, Prompt Leak, Role Play, Encoding Attack, Bypass Attempt

## 📄 License

**Internal Enterprise Use Only**

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited.

All rights reserved. This project is for internal enterprise use only and may not be reproduced, distributed, or transmitted in any form or by any means, including photocopying, recording, or other electronic or mechanical methods, without the prior written permission of the author.

For licensing inquiries, please contact: [2tenshipong2@gmail.com]

---

**Built with FastAPI, PostgreSQL, Redis, Docker, and Kubernetes** 🔐

**Version 4.0.0 | Production Ready**
