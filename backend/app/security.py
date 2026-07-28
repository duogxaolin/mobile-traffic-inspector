from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .database import get_db
from .models import Admin

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def issue_session(admin: Admin, settings: Settings) -> str:
    payload = {
        "sub": str(admin.id),
        "ver": admin.session_version,
        "iat": int(time.time()),
        "exp": int(time.time()) + 8 * 60 * 60,
        "nonce": secrets.token_urlsafe(16),
    }
    encoded = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64(hmac.new(settings.session_secret, encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def parse_session(token: str, settings: Settings) -> dict:
    try:
        encoded, signature = token.split(".", 1)
        expected = _b64(hmac.new(settings.session_secret, encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if int(payload["exp"]) < int(time.time()):
            raise ValueError
        return payload
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session") from exc


async def current_admin(
    mti_session: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Admin:
    if not mti_session:
        raise HTTPException(status_code=401, detail="authentication required")
    payload = parse_session(mti_session, settings)
    admin = await db.get(Admin, uuid.UUID(payload["sub"]))
    if admin is None or admin.session_version != int(payload["ver"]):
        raise HTTPException(status_code=401, detail="session revoked")
    return admin


async def require_csrf(
    request: Request,
    csrf_cookie: str | None = Cookie(default=None, alias="mti_csrf"),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> None:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


class LoginLimiter:
    def __init__(self, attempts: int = 5, window_seconds: int = 300) -> None:
        self.attempts = attempts
        self.window = window_seconds
        self.entries: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        attempts = self.entries[key]
        while attempts and now - attempts[0] > self.window:
            attempts.popleft()
        if len(attempts) >= self.attempts:
            raise HTTPException(status_code=429, detail="too many login attempts")

    def failure(self, key: str) -> None:
        self.entries[key].append(time.monotonic())

    def success(self, key: str) -> None:
        self.entries.pop(key, None)


login_limiter = LoginLimiter()


@dataclass
class RevealGrant:
    admin_id: uuid.UUID
    flow_id: uuid.UUID
    expires_at: float


class RevealStore:
    def __init__(self) -> None:
        self._grants: dict[str, RevealGrant] = {}

    def issue(self, admin_id: uuid.UUID, flow_id: uuid.UUID) -> str:
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        self._grants[digest] = RevealGrant(admin_id, flow_id, time.monotonic() + 60)
        return token

    def verify(self, token: str | None, admin_id: uuid.UUID, flow_id: uuid.UUID) -> bool:
        if not token:
            return False
        digest = hashlib.sha256(token.encode()).hexdigest()
        grant = self._grants.get(digest)
        if grant is None or grant.expires_at < time.monotonic():
            self._grants.pop(digest, None)
            return False
        return grant.admin_id == admin_id and grant.flow_id == flow_id


reveal_store = RevealStore()

