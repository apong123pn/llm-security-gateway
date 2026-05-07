from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Secure proxy for LLM APIs with PII redaction and prompt injection protection",
    version="0.1.0"
)

# CORS middleware (for future frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {
        "message": "Enterprise LLM Security Gateway is running! 🚀",
        "status": "healthy"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}