from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select, func, desc
from app.models.logs import Base, LLMRequestLog, SecurityAlert
from config.settings import settings
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import json

class DatabaseService:
    """PostgreSQL service for audit logging (GDPR/HIPAA compliant)"""
    
    def __init__(self):
        self.engine = create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DEBUG
        )
        self.async_session = async_sessionmaker(self.engine, expire_on_commit=False)
    
    async def init_db(self):
        """Create all tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("✅ Database tables created")
    
    async def close_db(self):
        """Close database connection"""
        await self.engine.dispose()
    
    async def log_request(self, data: Dict[str, Any]) -> str:
        """Log LLM request to PostgreSQL"""
        async with self.async_session() as session:
            log_entry = LLMRequestLog(
                request_id=str(uuid.uuid4()),
                user_id=data.get("user_id", "unknown"),
                department=data.get("department"),
                provider=data.get("provider", "openai"),
                model=data.get("model"),
                temperature=data.get("temperature"),
                max_tokens=data.get("max_tokens"),
                original_prompt=data.get("original_prompt"),
                redacted_prompt=data.get("redacted_prompt"),
                original_response=data.get("original_response"),
                redacted_response=data.get("redacted_response"),
                pii_detected=data.get("pii_detected", False),
                pii_types=json.dumps(data.get("pii_types", [])),
                pii_count=data.get("pii_count", 0),
                prompt_injection_detected=data.get("prompt_injection_detected", False),
                injection_confidence=data.get("injection_confidence", 0.0),
                injection_attack_type=data.get("injection_attack_type"),
                blocked=data.get("blocked", False),
                block_reason=data.get("block_reason"),
                client_ip=data.get("client_ip"),
                user_agent=data.get("user_agent"),
                response_time_ms=data.get("response_time_ms")
            )
            session.add(log_entry)
            await session.commit()
            return log_entry.request_id
    
    async def get_stats(self) -> Dict:
        """Get basic statistics"""
        async with self.async_session() as session:
            total = await session.scalar(select(func.count()).select_from(LLMRequestLog))
            blocked = await session.scalar(
                select(func.count()).where(LLMRequestLog.blocked == True)
            )
            pii = await session.scalar(
                select(func.count()).where(LLMRequestLog.pii_detected == True)
            )
            
            return {
                "total_requests": total or 0,
                "blocked_requests": blocked or 0,
                "pii_detections": pii or 0
            }