"""
FastAPI Application Entry Point
"""

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

# Load .env before anything else
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .database import engine, Base, get_db
from .models import User, ScanResult, APIKey, Tool
from .schemas import UserRegister, UserLogin, TokenOut, UserOut, ToolOut
from .auth import (
    register_user,
    login_user,
    get_current_user,
    hash_password,
)


# ── Lifespan — create tables on startup ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables (Alembic will handle migrations in production)
    Base.metadata.create_all(bind=engine)

    # Seed default tools if table is empty
    from .database import SessionLocal
    db = SessionLocal()
    try:
        if db.query(Tool).count() == 0:
            default_tools = [
                Tool(name="nmap", description="Port scanning & service detection"),
                Tool(name="zap", description="OWASP ZAP web vulnerability scanner"),
                Tool(name="virustotal", description="VirusTotal threat intelligence API"),
                Tool(name="custom", description="Custom Python threat analyzer"),
            ]
            db.add_all(default_tools)
            db.commit()
    finally:
        db.close()

    yield  # app is running
    # shutdown cleanup (if needed)


# ── Create app ──

app = FastAPI(
    title="VSTD — Visual Threat Detection API",
    version="1.0.0",
    description="Enterprise threat detection backend with multi-tool scanning",
    lifespan=lifespan,
)

# CORS — allow the Flask frontend (port 5000) and dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5000", "http://127.0.0.1:5000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth Routes (inline since they are small) ──

@app.post("/auth/register", response_model=dict)
def api_register(data: UserRegister, db: Session = Depends(get_db)):
    success, message = register_user(data, db)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"success": True, "message": message}


@app.post("/auth/login", response_model=TokenOut)
def api_login(data: UserLogin, db: Session = Depends(get_db)):
    success, message, token_data = login_user(data, db)
    if not success:
        raise HTTPException(status_code=401, detail=message)
    return token_data


@app.get("/auth/me", response_model=UserOut)
def api_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── Include routers ──

from .routers.scans import router as scans_router
from .routers.api_keys import router as api_keys_router

app.include_router(scans_router)
app.include_router(api_keys_router)


# ── Tools listing (public) ──

@app.get("/tools", response_model=list[ToolOut])
def list_tools(db: Session = Depends(get_db)):
    return db.query(Tool).filter(Tool.is_active == True).all()


# ── Health ──

@app.get("/health")
def health():
    return {"status": "ok", "service": "VSTD Backend"}
