"""
Pydantic schemas for request / response validation.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Any
from datetime import datetime


# ──────────────────── Auth ────────────────────

class UserRegister(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8)
    confirm_password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# ──────────────────── Scans ────────────────────

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=255)
    selected_tool: str = Field(..., pattern="^(nmap|zap|virustotal|custom)$")


class ScanResultOut(BaseModel):
    id: int
    target: str
    selected_tool: str
    raw_output: Optional[str] = None
    parsed_result: Optional[Any] = None
    threat_score: float
    risk_level: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


# ──────────────────── API Keys ────────────────────

class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    service: str = Field(..., min_length=1, max_length=50)
    key: str = Field(..., min_length=1)


class APIKeyOut(BaseModel):
    id: int
    name: str
    service: str
    masked_key: str
    created_at: datetime

    class Config:
        from_attributes = True


# ──────────────────── Tools ────────────────────

class ToolOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True
