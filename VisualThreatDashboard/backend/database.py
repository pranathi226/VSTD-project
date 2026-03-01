"""
Database configuration — SQLAlchemy engine + session factory.
Supports PostgreSQL (production) with automatic SQLite fallback (development).
"""

import os
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load .env from project root
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@localhost:5432/vstd_db",
)


def _try_postgres(url: str) -> bool:
    """Quick check if PostgreSQL is reachable."""
    try:
        eng = create_engine(url, pool_pre_ping=True)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        eng.dispose()
        return True
    except Exception:
        return False


# Try PostgreSQL first; fall back to SQLite for local dev
if DATABASE_URL.startswith("postgresql") and not _try_postgres(DATABASE_URL):
    _base_dir = os.path.dirname(os.path.dirname(__file__))
    _sqlite_path = os.path.join(_base_dir, "instance", "vstd.db")
    os.makedirs(os.path.dirname(_sqlite_path), exist_ok=True)
    DATABASE_URL = f"sqlite:///{_sqlite_path}"
    print(f"[DB] PostgreSQL unavailable — using SQLite: {_sqlite_path}")

# SQLite needs connect_args for thread safety
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=_connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and ensures cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
