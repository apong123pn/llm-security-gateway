from fastapi import APIRouter
import json
from datetime import datetime

router = APIRouter(prefix="/logs", tags=["Logging"])

@router.get("/")
async def get_logs(limit: int = 20):
    logs = []
    try:
        with open("audit_logs.jsonl", "r", encoding="utf-8") as f:
            for line in list(f)[-limit:]:   # Get last N logs
                if line.strip():
                    logs.append(json.loads(line))
    except FileNotFoundError:
        return {"message": "No logs yet", "logs": []}
    
    return {
        "total_logs": len(logs),
        "logs": logs
    }