from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .database import get_db
from .models import Admin, AuditEvent
from .schemas import LoginInput
from .security import current_admin, issue_session, login_limiter, require_csrf, verify_password

router = APIRouter(prefix="/auth")


@router.post("/login")
async def login(
    payload: LoginInput,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    source = request.client.host if request.client else "unknown"
    login_limiter.check(source)
    admin = await db.scalar(select(Admin).where(Admin.username == payload.username))
    if admin is None or not verify_password(admin.password_hash, payload.password):
        login_limiter.failure(source)
        db.add(AuditEvent(admin_id=admin.id if admin else None, action="login.failed", source_ip=source))
        await db.commit()
        raise HTTPException(status_code=401, detail="invalid credentials")
    login_limiter.success(source)
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "mti_session",
        issue_session(admin, settings),
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=8 * 60 * 60,
        path="/",
    )
    response.set_cookie(
        "mti_csrf",
        csrf,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=8 * 60 * 60,
        path="/",
    )
    db.add(AuditEvent(admin_id=admin.id, action="login.succeeded", source_ip=source))
    await db.commit()
    return {"username": admin.username, "csrfToken": csrf}


@router.post("/logout", dependencies=[Depends(require_csrf)])
async def logout(
    response: Response,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    admin.session_version += 1
    await db.commit()
    response.delete_cookie("mti_session", path="/")
    response.delete_cookie("mti_csrf", path="/")
    return {"loggedOut": True}


@router.get("/me")
async def me(admin: Admin = Depends(current_admin)) -> dict:
    return {"username": admin.username}

