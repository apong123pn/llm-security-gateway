# app/database.py - SQLite Compatible Version
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Float, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select, func
from datetime import datetime
import uuid
from typing import Dict, Any, Optional
import json
import os

Base = declarative_base()

class LLMRequestLog(Base):
    __tablename__ = "llm_requests"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    department = Column(String(100), index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    response_time_ms = Column(Integer)
    provider = Column(String(50), default="openai", index=True)
    model = Column(String(100))
    temperature = Column(Float)
    max_tokens = Column(Integer)
    original_prompt = Column(Text)
    redacted_prompt = Column(Text)
    original_response = Column(Text)
    redacted_response = Column(Text)
    pii_detected = Column(Boolean, default=False, index=True)
    pii_types = Column(JSON)
    prompt_injection_detected = Column(Boolean, default=False, index=True)
    blocked = Column(Boolean, default=False, index=True)
    block_reason = Column(String(500))
    client_ip = Column(String(45))
    user_agent = Column(String(500))
    
    __table_args__ = (
        Index('ix_timestamp_user', 'timestamp', 'user_id'),
        Index('ix_blocked_timestamp', 'blocked', 'timestamp'),
    )

class DatabaseService:
    def __init__(self, database_url: str = None):
        if database_url is None:
            database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./audit_logs.db")
        
        self.database_url = database_url
        self.engine = None
        self.async_session = None
        self._using_sqlite = "sqlite" in database_url
    
    async def init_db(self):
        if self._using_sqlite:
            connect_args = {"check_same_thread": False}
            self.engine = create_async_engine(self.database_url, echo=False, connect_args=connect_args)
        else:
            self.engine = create_async_engine(self.database_url, echo=False, pool_size=5, max_overflow=10)
        
        self.async_session = async_sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
        
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print(f"✅ Database connected: {self.database_url}")
        return self
    
    async def close_db(self):
        if self.engine:
            await self.engine.dispose()
    
    async def log_request(self, data: Dict[str, Any]) -> str:
        request_id = str(uuid.uuid4())
        async with self.async_session() as session:
            log_entry = LLMRequestLog(
                request_id=request_id,
                user_id=data.get("user_id", "unknown"),
                department=data.get("department"),
                provider=data.get("provider", "openai"),
                model=data.get("model"),
                temperature=data.get("temperature"),
                max_tokens=data.get("max_tokens"),
                original_prompt=data.get("original_prompt", "")[:5000],
                redacted_prompt=data.get("redacted_prompt", "")[:5000],
                original_response=data.get("original_response", "")[:5000],
                redacted_response=data.get("redacted_response", "")[:5000],
                pii_detected=data.get("pii_detected", False),
                pii_types=json.dumps(data.get("pii_types", [])),
                prompt_injection_detected=data.get("prompt_injection_detected", False),
                blocked=data.get("blocked", False),
                block_reason=data.get("block_reason"),
                client_ip=data.get("client_ip"),
                user_agent=data.get("user_agent"),
                response_time_ms=data.get("response_time_ms")
            )
            session.add(log_entry)
            await session.commit()
            return request_id
    
    async def get_stats(self) -> Dict:
        async with self.async_session() as session:
            total = await session.scalar(select(func.count()).select_from(LLMRequestLog))
            blocked = await session.scalar(select(func.count()).where(LLMRequestLog.blocked == True))
            pii_count = await session.scalar(select(func.count()).where(LLMRequestLog.pii_detected == True))
            injection_count = await session.scalar(select(func.count()).where(LLMRequestLog.prompt_injection_detected == True))
            
            return {
                "total_requests": total or 0,
                "blocked_requests": blocked or 0,
                "pii_detections": pii_count or 0,
                "prompt_injections": injection_count or 0,
                "block_rate_percent": round((blocked or 0) / (total or 1) * 100, 2),
                "database_type": "SQLite"
            }
    
    async def get_logs(self, limit: int = 20, user_id: Optional[str] = None) -> list:
        async with self.async_session() as session:
            query = select(LLMRequestLog).order_by(LLMRequestLog.timestamp.desc())
            if user_id:
                query = query.where(LLMRequestLog.user_id == user_id)
            query = query.limit(limit)
            result = await session.execute(query)
            logs = result.scalars().all()
            
            return [
                {
                    "request_id": log.request_id,
                    "timestamp": log.timestamp.isoformat(),
                    "user_id": log.user_id,
                    "department": log.department,
                    "model": log.model,
                    "blocked": log.blocked,
                    "pii_detected": log.pii_detected,
                    "response_time_ms": log.response_time_ms
                }
                for log in logs
            ]