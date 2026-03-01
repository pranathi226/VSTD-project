"""
API Keys router — POST /api-keys, GET /api-keys, DELETE /api-keys/{id}
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import APIKey, User
from ..schemas import APIKeyCreate, APIKeyOut
from ..auth import get_current_user
from ..services.crypto import encrypt_api_key, decrypt_api_key, mask_api_key

router = APIRouter(prefix="/api-keys", tags=["API Keys"])


def _to_out(key: APIKey) -> APIKeyOut:
    """Convert an APIKey ORM object to the output schema with a masked key."""
    # Decrypt to mask (we only show masked version)
    try:
        plain = decrypt_api_key(key.encrypted_key)
        masked = mask_api_key(plain)
    except Exception:
        masked = "****"

    return APIKeyOut(
        id=key.id,
        name=key.name,
        service=key.service,
        masked_key=masked,
        created_at=key.created_at,
    )


@router.post("", response_model=APIKeyOut, status_code=201)
def create_api_key(
    req: APIKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Save a new API key (encrypted)."""
    encrypted = encrypt_api_key(req.key)

    api_key = APIKey(
        name=req.name,
        service=req.service,
        encrypted_key=encrypted,
        user_id=current_user.id,
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return _to_out(api_key)


@router.get("", response_model=List[APIKeyOut])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all API keys for the authenticated user (masked)."""
    keys = (
        db.query(APIKey)
        .filter(APIKey.user_id == current_user.id)
        .order_by(APIKey.created_at.desc())
        .all()
    )
    return [_to_out(k) for k in keys]


@router.delete("/{key_id}", status_code=204)
def delete_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete an API key."""
    api_key = (
        db.query(APIKey)
        .filter(APIKey.id == key_id, APIKey.user_id == current_user.id)
        .first()
    )
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    db.delete(api_key)
    db.commit()
