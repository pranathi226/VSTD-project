"""
Fernet-based encryption / decryption for API keys.
"""

import os
import base64
import hashlib
from cryptography.fernet import Fernet


def _get_fernet() -> Fernet:
    """Derive a Fernet key from the ENCRYPTION_KEY env var."""
    raw_key = os.getenv("ENCRYPTION_KEY", "your-32-byte-encryption-key-here!")
    # Derive a 32-byte key via SHA-256, then base64-encode for Fernet
    digest = hashlib.sha256(raw_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(digest)
    return Fernet(fernet_key)


def encrypt_api_key(plain_key: str) -> str:
    """Encrypt an API key string and return the cipher-text as a UTF-8 string."""
    f = _get_fernet()
    return f.encrypt(plain_key.encode()).decode()


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt an API key cipher-text back to plain text."""
    f = _get_fernet()
    return f.decrypt(encrypted_key.encode()).decode()


def mask_api_key(plain_key: str) -> str:
    """Return a masked version of the key showing only first 4 and last 4 chars."""
    if len(plain_key) <= 8:
        return "****"
    return plain_key[:4] + "*" * (len(plain_key) - 8) + plain_key[-4:]
