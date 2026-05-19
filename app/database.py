# app/database.py - Full Updated Version with PII Support
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
    """Audit log table for compliance (GDPR/HIPAA/SOC2) with PII tracking"""
    __tablename__ = "llm_requests"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    department = Column(String(100), index=True)
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    response_time_ms = Column(Integer)
    
    # Request details
    provider = Column(String(50), default="openai", index=True)
    model = Column(String(100))
    temperature = Column(Float)
    max_tokens = Column(Integer)
    
    # Content (original and redacted)
    original_prompt = Column(Text)
    redacted_prompt = Column(Text)
    original_response = Column(Text)
    redacted_response = Column(Text)
    
    # PII Detection (Microsoft Presidio)
    pii_detected = Column(Boolean, default=False, index=True)
    pii_types = Column(JSON)  # Stores list of PII types found (e.g., ["EMAIL", "PHONE"])
    pii_count = Column(Integer, default=0)  # Number of PII instances found
    
    # Threat Detection (for Week 3)
    prompt_injection_detected = Column(Boolean, default=False, index=True)
    injection_confidence = Column(Float, default=0.0)
    injection_attack_type = Column(String(100))
    
    # Actions
    blocked = Column(Boolean, default=False, index=True)
    block_reason = Column(String(500))
    
    # Metadata for audit
    client_ip = Column(String(45))
    user_agent = Column(String(500))
    
    # Indexes for fast queries
    __table_args__ = (
        Index('ix_timestamp_user', 'timestamp', 'user_id'),
        Index('ix_blocked_timestamp', 'blocked', 'timestamp'),
        Index('ix_pii_detected', 'pii_detected', 'timestamp'),
    )


class DatabaseService:
    """Database service for persistent audit logging with PII tracking"""
    
    def __init__(self, database_url: str = None):
        if database_url is None:
            database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./audit_logs.db")
        
        self.database_url = database_url
        self.engine = None
        self.async_session = None
        self._using_sqlite = "sqlite" in database_url
    
    async def init_db(self):
        """Create all tables and initialize connections"""
        if self._using_sqlite:
            connect_args = {"check_same_thread": False}
            self.engine = create_async_engine(
                self.database_url, 
                echo=False, 
                connect_args=connect_args
            )
        else:
            self.engine = create_async_engine(
                self.database_url, 
                echo=False, 
                pool_size=5, 
                max_overflow=10
            )
        
        self.async_session = async_sessionmaker(
            self.engine, 
            class_=AsyncSession, 
            expire_on_commit=False
        )
        
        # Create tables
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        db_type = "SQLite" if self._using_sqlite else "PostgreSQL"
        print(f"✅ Database connected: {self.database_url}")
        return self
    
    async def close_db(self):
        """Close database connection"""
        if self.engine:
            await self.engine.dispose()
            print("✅ Database connection closed")
    
    async def log_request(self, data: Dict[str, Any]) -> str:
        """
        Log LLM request to database with PII information.
        
        Expected data fields:
        - user_id: str
        - department: str (optional)
        - provider: str
        - model: str
        - temperature: float (optional)
        - max_tokens: int (optional)
        - original_prompt: str
        - redacted_prompt: str (optional)
        - original_response: str
        - redacted_response: str (optional)
        - pii_detected: bool
        - pii_types: list (e.g., ["EMAIL", "PHONE"])
        - pii_count: int
        - prompt_injection_detected: bool (optional)
        - injection_confidence: float (optional)
        - injection_attack_type: str (optional)
        - blocked: bool
        - block_reason: str (optional)
        - client_ip: str (optional)
        - user_agent: str (optional)
        - response_time_ms: int
        """
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
                pii_count=data.get("pii_count", 0),
                prompt_injection_detected=data.get("prompt_injection_detected", False),
                injection_confidence=data.get("injection_confidence", 0.0),
                injection_attack_type=data.get("injection_attack_type"),
                blocked=data.get("blocked", False),
                block_reason=data.get("block_reason"),
                client_ip=data.get("client_ip"),
                user_agent=data.get("user_agent"),
                response_time_ms=data.get("response_time_ms", 0)
            )
            session.add(log_entry)
            await session.commit()
            return request_id
    
    async def get_stats(self) -> Dict:
        """Get statistics from database including PII metrics"""
        async with self.async_session() as session:
            # Total requests
            total = await session.scalar(select(func.count()).select_from(LLMRequestLog))
            
            # Blocked requests
            blocked = await session.scalar(
                select(func.count()).where(LLMRequestLog.blocked == True)
            )
            
            # PII detections
            pii_count = await session.scalar(
                select(func.count()).where(LLMRequestLog.pii_detected == True)
            )
            
            # Injection detections (for Week 3)
            injection_count = await session.scalar(
                select(func.count()).where(LLMRequestLog.prompt_injection_detected == True)
            )
            
            # Get top PII types detected
            # Note: This is a simplified version; for complex JSON queries, consider using raw SQL
            all_logs = await session.execute(select(LLMRequestLog.pii_types).where(LLMRequestLog.pii_detected == True))
            pii_type_counts = {}
            for row in all_logs:
                if row[0]:
                    types = json.loads(row[0])
                    for t in types:
                        pii_type_counts[t] = pii_type_counts.get(t, 0) + 1
            
            top_pii_types = sorted(pii_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                "total_requests": total or 0,
                "blocked_requests": blocked or 0,
                "block_rate_percent": round((blocked or 0) / (total or 1) * 100, 2),
                "pii_detections": pii_count or 0,
                "pii_detection_rate": round((pii_count or 0) / (total or 1) * 100, 2),
                "prompt_injections": injection_count or 0,
                "top_pii_types": dict(top_pii_types),
                "database_type": "SQLite" if self._using_sqlite else "PostgreSQL"
            }
    
    async def get_logs(self, limit: int = 20, user_id: Optional[str] = None) -> list:
        """Get recent audit logs with PII information"""
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
                    "pii_types": json.loads(log.pii_types) if log.pii_types else [],
                    "pii_count": log.pii_count,
                    "prompt_injection_detected": log.prompt_injection_detected,
                    "response_time_ms": log.response_time_ms
                }
                for log in logs
            ]
    
    async def get_pii_report(self, limit: int = 50) -> Dict:
        """Get detailed PII detection report for compliance"""
        async with self.async_session() as session:
            # Get logs with PII detected
            query = select(LLMRequestLog).where(
                LLMRequestLog.pii_detected == True
            ).order_by(LLMRequestLog.timestamp.desc()).limit(limit)
            
            result = await session.execute(query)
            logs = result.scalars().all()
            
            return {
                "total_pii_incidents": len(logs),
                "recent_incidents": [
                    {
                        "timestamp": log.timestamp.isoformat(),
                        "user_id": log.user_id,
                        "pii_types": json.loads(log.pii_types) if log.pii_types else [],
                        "pii_count": log.pii_count,
                        "prompt_preview": log.original_prompt[:200] if log.original_prompt else ""
                    }
                    for log in logs[:20]
                ]
            }