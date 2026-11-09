import hashlib
import hmac
import json
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet

from gateway.config import get_settings

_hasher = PasswordHasher()
# Verified against when the username is unknown, so both paths cost the same.
_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _fernet() -> Fernet:
    return Fernet(get_settings().secret_key.encode())


def encrypt_env(env: dict[str, str]) -> str | None:
    return _fernet().encrypt(json.dumps(env).encode()).decode() if env else None


def decrypt_env(blob: str | None) -> dict[str, str]:
    return json.loads(_fernet().decrypt(blob.encode())) if blob else {}


def derived_key(purpose: str) -> str:
    return hmac.new(get_settings().secret_key.encode(), purpose.encode(), hashlib.sha256).hexdigest()
