from __future__ import annotations
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, func, Index
from sqlalchemy.orm import relationship
from db import Base

class Upload(Base):
    __tablename__ = "uploads"

    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # pipeline state
    status = Column(String(32), nullable=True)         # uploaded | processing | summarizing | done | failed
    progress = Column(Integer, nullable=True)          # 0–100

    # raw uploaded content (parsed later)
    raw_content = Column(Text, nullable=True)

    # cached overall AI summary (single LLM call per upload)
    ai_summary = Column(Text, nullable=True)
    ai_summary_model = Column(String(120), nullable=True)
    ai_summary_at = Column(DateTime(timezone=True), nullable=True)

    # relationships
    events = relationship("LogEvent", back_populates="upload", cascade="all, delete-orphan")
    anomalies = relationship("Anomaly", back_populates="upload", cascade="all, delete-orphan")

class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True)
    upload_id = Column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), index=True, nullable=False)

    ts = Column(DateTime(timezone=True), nullable=True)
    src_ip = Column(String(64), nullable=True)
    user = Column(String(128), nullable=True)
    url = Column(Text, nullable=True)
    action = Column(String(64), nullable=True)
    status = Column(Integer, nullable=True)
    bytes = Column(Integer, nullable=True)
    user_agent = Column(Text, nullable=True)
    raw = Column(Text, nullable=True)

    upload = relationship("Upload", back_populates="events")

# Helpful indexes for common queries
Index("ix_log_events_upload_ts", LogEvent.upload_id, LogEvent.ts)
Index("ix_log_events_srcip", LogEvent.upload_id, LogEvent.src_ip)

class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True)
    upload_id = Column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), index=True, nullable=False)
    event_id = Column(Integer, ForeignKey("log_events.id", ondelete="SET NULL"), nullable=True)

    reason = Column(Text, nullable=True)
    score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    upload = relationship("Upload", back_populates="anomalies")
