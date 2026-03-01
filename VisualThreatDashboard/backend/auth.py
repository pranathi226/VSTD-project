"""
JWT authentication — token creation, verification, and FastAPI dependency.
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session

from .database import get_db
from .models import User
from .schemas import UserRegister, UserLogin, UserOut, TokenOut

# ── Config ──
JWT_SECRET = os.getenv("JWT_SECRET", "jwt-secret-key-vstd-2025")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ── Helpers ──

def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return check_password_hash(hashed, plain)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=JWT_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ── Dependencies ──

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Decode JWT and return the authenticated User from the DB."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


# ── Auth service functions (used by the router) ──

def register_user(data: UserRegister, db: Session):
    """Register a new user. Returns (success, message)."""
    if data.password != data.confirm_password:
        return False, "Passwords do not match"

    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        return False, "Email already registered"

    user = User(
        email=data.email,
        name=data.name,
        password_hash=hash_password(data.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return True, "Registration successful"


def login_user(data: UserLogin, db: Session):
    """Authenticate user. Returns (success, message, token_data | None)."""
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.password_hash):
        return False, "Invalid email or password", None

    if not user.is_active:
        return False, "Account is deactivated", None

    user.last_login = datetime.utcnow()
    db.commit()

    token = create_access_token({"user_id": user.id, "email": user.email})

    return True, "Login successful", TokenOut(
        access_token=token,
        user=UserOut.model_validate(user),
    )
