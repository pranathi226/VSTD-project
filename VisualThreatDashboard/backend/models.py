"""
SQLAlchemy ORM Models — users, scan_results, api_keys, tools
"""

from sqlalchemy import (
    Column, Integer, String, Text, Float, DateTime, Boolean, JSON, ForeignKey,
)
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    password_hash = Column(String(200), nullable=False)
    role = Column(String(20), default="user")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    scan_results = relationship("ScanResult", back_populates="user", cascade="all, delete-orphan")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False, index=True)
    selected_tool = Column(String(50), nullable=False)
    raw_output = Column(Text, nullable=True)
    parsed_result = Column(JSON, nullable=True)
    threat_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="Low")
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    created_at = Column(DateTime, default=datetime.utcnow)

    # Foreign key
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="scan_results")


class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    service = Column(String(50), nullable=False)  # e.g. virustotal, shodan, etc.
    encrypted_key = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Foreign key
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="api_keys")


class Tool(Base):
    __tablename__ = "tools"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
