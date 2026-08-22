import os
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import jwt

from django.conf import settings

from accounts.services.keys import generate_rsa_keypair


ALGORITHM = "RS256"


@lru_cache(maxsize=None)
def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def ensure_keypair() -> None:
    private_path = settings.JWT_PRIVATE_KEY_PATH
    public_path = settings.JWT_PUBLIC_KEY_PATH
    if not (os.path.exists(private_path) and os.path.exists(public_path)):
        generate_rsa_keypair(private_path, public_path)


def _private_key() -> bytes:
    return _read_file(settings.JWT_PRIVATE_KEY_PATH)


def public_key() -> bytes:
    return _read_file(settings.JWT_PUBLIC_KEY_PATH)


def generate_access_token(user) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "token_type": "access",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=settings.ACCESS_TOKEN_TTL_SECONDS),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, _private_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        public_key(),
        algorithms=[ALGORITHM],
        issuer=settings.JWT_ISSUER,
        audience=settings.JWT_AUDIENCE,
    )
