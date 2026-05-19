# app/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, Float, Index
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class LLMRequestLog(Base):
    """Audit log table for compliance (GDPR/HIPAA/SOC2)"""
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
    
    # Content (original and redacted for compliance)
    original_prompt = Column(Text)
    redacted_prompt = Column(Text)
    original_response = Column(Text)
    redacted_response = Column(Text)
    
    # Security flags
    pii_detected = Column(Boolean, default=False, index=True)
    pii_types = Column(JSON)
    prompt_injection_detected = Column(Boolean, default=False, index=True)
    
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
    )