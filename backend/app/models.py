import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Integer, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(String, primary_key=True, default=generate_uuid)
    type = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False, index=True)
    severity = Column(String, nullable=False, default="MEDIUM", index=True)
    confidence = Column(Float, default=0.85)
    risk_score = Column(Float, default=0.0)
    source = Column(String, default="Honeypot Session")
    context = Column(Text, nullable=True)
    metadata_json = Column(JSON, nullable=True)
    detected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class HoneypotSession(Base):
    __tablename__ = "honeypot_sessions"

    id = Column(String, primary_key=True, default=lambda: f"TF-{uuid.uuid4().hex[:6].upper()}")
    persona = Column(String, default="victim")
    status = Column(String, default="ACTIVE")
    turn_count = Column(Integer, default=0)
    tactics_json = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    messages = relationship("HoneypotMessage", back_populates="session", cascade="all, delete-orphan")

class HoneypotMessage(Base):
    __tablename__ = "honeypot_messages"

    id = Column(String, primary_key=True, default=generate_uuid)
    session_id = Column(String, ForeignKey("honeypot_sessions.id"), nullable=False)
    sender_role = Column(String, nullable=False)  # "scammer" or "agent"
    text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    session = relationship("HoneypotSession", back_populates="messages")

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id = Column(String, primary_key=True, default=generate_uuid)
    message = Column(Text, nullable=False)
    sender = Column(String, nullable=True)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String, nullable=False)
    summary = Column(Text, nullable=False)
    breakdown_json = Column(JSON, nullable=True)
    recommendations_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
