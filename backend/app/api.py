from __future__ import annotations

import base64
import re
import shutil
import uuid
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import desc, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .crypto import Vault
from .database import get_db
from .dependencies import require_ingest_token
from .events import hub
from .models import Admin, AuditEvent, CaptureSession, Device, Flow, SystemState, WebSocketMessage
from .redaction import redact_body, redact_headers, redact_query
from .schemas import (
    CaptureMetrics,
    CompleteEvent,
    DeviceInput,
    DeviceProfileInput,
    HeaderEvent,
    IngestEvent,
    PauseInput,
    ReauthInput,
)
from .security import current_admin, require_csrf, reveal_store, verify_password

router = APIRouter(prefix="/api", dependencies=[Depends(require_csrf)])
internal = APIRouter(prefix="/internal", dependencies=[Depends(require_ingest_token)])


def _decode_encrypted(value: str | None) -> bytes | None:
    if value is None:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid encrypted field") from exc


def _wireguard_config_value(profile: str, key: str) -> str | None:
    for line in profile.splitlines():
        name, separator, value = line.partition("=")
        if separator and name.strip() == key:
            return value.strip()
    return None


def _derive_wireguard_public_key(private_key_b64: str) -> str:
    try:
        private_bytes = base64.b64decode(private_key_b64, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="wireguard private key is not base64") from exc
    if len(private_bytes) != 32:
        raise HTTPException(status_code=500, detail="wireguard private key must be 32 bytes")
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_bytes).decode()


def _wireguard_tunnel_ip(profile: str) -> str | None:
    address = _wireguard_config_value(profile, "Address")
    if not address:
        return None
    first = address.split(",", 1)[0].strip()
    return first.split("/", 1)[0] if first else None


def _safe_profile_filename(name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name.strip()).strip(".-")
    return f"{safe_name or 'device'}.conf"


def _flow_summary(flow: Flow) -> dict:
    return {
        "id": str(flow.id),
        "captureId": flow.capture_id,
        "sessionId": str(flow.session_id),
        "protocol": flow.protocol,
        "method": flow.method,
        "host": flow.host,
        "path": flow.path,
        "status": flow.status_code,
        "requestContentType": flow.request_content_type,
        "responseContentType": flow.response_content_type,
        "requestBytes": flow.request_body_size,
        "responseBytes": flow.response_body_size,
        "startedAt": flow.started_at.isoformat(),
        "completedAt": flow.completed_at.isoformat() if flow.completed_at else None,
        "durationMs": flow.duration_ms,
        "state": flow.state,
        "errorCode": flow.error_code,
        "notCapturedReason": flow.not_captured_reason,
        "websocket": flow.websocket,
    }


async def _audit(
    db: AsyncSession,
    request: Request,
    admin: Admin | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
) -> None:
    db.add(
        AuditEvent(
            admin_id=admin.id if admin else None,
            action=action,
            target_type=target_type,
            target_id=target_id,
            source_ip=request.client.host if request.client else None,
        )
    )


async def _session_payload_size(db: AsyncSession, session_id: uuid.UUID) -> int:
    body_size = await db.scalar(
        select(func.coalesce(func.sum(Flow.request_body_size + Flow.response_body_size), 0)).where(
            Flow.session_id == session_id
        )
    )
    websocket_size = await db.scalar(
        select(func.coalesce(func.sum(WebSocketMessage.payload_size), 0))
        .join(Flow, WebSocketMessage.flow_id == Flow.id)
        .where(Flow.session_id == session_id)
    )
    return int(body_size or 0) + int(websocket_size or 0)


async def _purge_session(
    db: AsyncSession, session: CaptureSession, settings: Settings, action: str | None
) -> int:
    paths = (
        await db.execute(
            select(Flow.request_body_path, Flow.response_body_path, WebSocketMessage.payload_path)
            .outerjoin(WebSocketMessage, WebSocketMessage.flow_id == Flow.id)
            .where(Flow.session_id == session.id)
        )
    ).all()
    vault = Vault(settings.application_key, settings.body_root)
    for request_path, response_path, websocket_path in paths:
        for relative in (request_path, response_path, websocket_path):
            if relative:
                vault.safe_path(relative).unlink(missing_ok=True)
    removed = await _session_payload_size(db, session.id)
    session.deleted_at = datetime.now(UTC)
    if action:
        db.add(AuditEvent(action=action, target_type="session", target_id=str(session.id)))
    return removed


async def _enforce_storage_limits(
    db: AsyncSession, settings: Settings, preserve_session_id: uuid.UUID | None = None
) -> None:
    if settings.retention_days:
        cutoff = datetime.now(UTC) - timedelta(days=settings.retention_days)
        expired = (
            await db.scalars(
                select(CaptureSession).where(
                    CaptureSession.deleted_at.is_(None), CaptureSession.started_at < cutoff
                )
            )
        ).all()
        for session in expired:
            await _purge_session(db, session, settings, "retention.deleted")
    if not settings.storage_quota_bytes:
        return
    active = (
        await db.scalars(select(CaptureSession).where(CaptureSession.deleted_at.is_(None)))
    ).all()
    usage = sum([await _session_payload_size(db, session.id) for session in active])
    if usage <= settings.storage_quota_bytes:
        return
    candidates = (
        await db.scalars(
            select(CaptureSession)
            .where(CaptureSession.deleted_at.is_(None), CaptureSession.id != preserve_session_id)
            .order_by(CaptureSession.started_at)
        )
    ).all()
    for session in candidates:
        if usage <= settings.storage_quota_bytes:
            break
        usage -= await _purge_session(db, session, settings, "quota.deleted")


def _websocket_preview(message: WebSocketMessage, vault: Vault, raw: bool, max_bytes: int) -> dict:
    if not message.payload_path:
        return {"state": "not-captured", "encoding": "base64", "content": "", "view": "none", "raw": raw, "truncated": False}
    try:
        content, truncated = vault.read_preview(message.payload_path, max_bytes)
    except (FileNotFoundError, ValueError):
        return {"state": "error", "encoding": "base64", "content": "", "view": "error", "raw": raw, "truncated": False}
    content_type = "text/plain" if message.opcode == 1 else "application/octet-stream"
    rendered, view = (content, "raw") if raw else redact_body(content, content_type)
    return {
        "state": "truncated" if truncated else "complete",
        "encoding": "base64",
        "content": base64.b64encode(rendered).decode(),
        "view": view,
        "raw": raw,
        "truncated": truncated,
    }


@router.get("/flows")
async def list_flows(
    q: str | None = Query(default=None, max_length=256),
    method: str | None = Query(default=None, max_length=16),
    host: str | None = Query(default=None, max_length=255),
    path: str | None = Query(default=None, max_length=512),
    status_code: int | None = None,
    content_type: str | None = Query(default=None, max_length=128),
    since: datetime | None = None,
    until: datetime | None = None,
    session_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    conditions = []
    if q:
        pattern = f"%{q}%"
        conditions.append(or_(Flow.host.ilike(pattern), Flow.path.ilike(pattern)))
    if method:
        conditions.append(Flow.method == method.upper())
    if host:
        conditions.append(Flow.host.ilike(f"%{host}%"))
    if path:
        conditions.append(Flow.path.ilike(f"%{path}%"))
    if status_code is not None:
        conditions.append(Flow.status_code == status_code)
    if content_type:
        pattern = f"%{content_type}%"
        conditions.append(or_(Flow.request_content_type.ilike(pattern), Flow.response_content_type.ilike(pattern)))
    if since:
        conditions.append(Flow.started_at >= since)
    if until:
        conditions.append(Flow.started_at <= until)
    if session_id:
        conditions.append(Flow.session_id == session_id)
    conditions.append(CaptureSession.deleted_at.is_(None))
    statement = (
        select(Flow)
        .join(CaptureSession)
        .where(*conditions)
        .order_by(desc(Flow.started_at))
        .limit(limit)
        .offset(offset)
    )
    rows = (await db.scalars(statement)).all()
    return {"items": [_flow_summary(flow) for flow in rows], "limit": limit, "offset": offset}


@router.get("/flows/{flow_id}")
async def flow_detail(
    flow_id: uuid.UUID,
    x_reveal_token: str | None = Header(default=None),
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    flow = await db.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    raw = reveal_store.verify(x_reveal_token, admin.id, flow.id)
    vault = Vault(settings.application_key, settings.body_root)
    request_headers = vault.decrypt_json(flow.request_headers_enc) or []
    response_headers = vault.decrypt_json(flow.response_headers_enc) or []
    query = vault.decrypt_json(flow.query_enc) or []
    url = vault.decrypt_json(flow.url_enc)
    detail = _flow_summary(flow)
    detail.update(
        {
            "raw": raw,
            "url": url if raw else f"{flow.scheme}://{flow.host}{flow.path or ''}",
            "query": query if raw else redact_query(query),
            "requestHeaders": request_headers if raw else redact_headers(request_headers),
            "responseHeaders": response_headers if raw else redact_headers(response_headers),
        }
    )
    return detail


@router.get("/flows/{flow_id}/body/{direction}")
async def body_preview(
    flow_id: uuid.UUID,
    direction: str,
    x_reveal_token: str | None = Header(default=None),
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    if direction not in {"request", "response"}:
        raise HTTPException(status_code=404, detail="invalid direction")
    flow = await db.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    relative = flow.request_body_path if direction == "request" else flow.response_body_path
    if not relative:
        return JSONResponse({"state": "not-captured", "content": "", "truncated": False})
    vault = Vault(settings.application_key, settings.body_root)
    try:
        content, truncated = vault.read_preview(relative, settings.preview_bytes)
    except (FileNotFoundError, ValueError):
        return JSONResponse(
            {"state": "error", "content": "", "truncated": False, "error": "body unavailable"},
            status_code=410,
        )
    raw = reveal_store.verify(x_reveal_token, admin.id, flow.id)
    content_type = flow.request_content_type if direction == "request" else flow.response_content_type
    if raw:
        rendered, view = content, "raw"
    else:
        rendered, view = redact_body(content, content_type)
    return JSONResponse(
        {
            "state": "truncated" if truncated else "complete",
            "encoding": "base64",
            "content": base64.b64encode(rendered).decode(),
            "contentType": content_type,
            "view": view,
            "raw": raw,
            "truncated": truncated,
        }
    )


@router.get("/flows/{flow_id}/body/{direction}/download")
async def download_body(
    flow_id: uuid.UUID,
    direction: str,
    x_reveal_token: str | None = Header(default=None),
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> StreamingResponse:
    if direction not in {"request", "response"}:
        raise HTTPException(status_code=404, detail="invalid direction")
    flow = await db.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    if not reveal_store.verify(x_reveal_token, admin.id, flow.id):
        raise HTTPException(status_code=403, detail="raw download requires recent re-authentication")
    relative = flow.request_body_path if direction == "request" else flow.response_body_path
    if not relative:
        raise HTTPException(status_code=404, detail="body not captured")
    vault = Vault(settings.application_key, settings.body_root)
    return StreamingResponse(
        vault.decrypt_chunks(relative),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{flow.id}-{direction}.bin"', "Cache-Control": "no-store"},
    )


@router.get("/flows/{flow_id}/websocket")
async def websocket_messages(
    flow_id: uuid.UUID,
    x_reveal_token: str | None = Header(default=None),
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    flow = await db.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    raw = reveal_store.verify(x_reveal_token, admin.id, flow.id)
    vault = Vault(settings.application_key, settings.body_root)
    rows = (
        await db.scalars(
            select(WebSocketMessage)
            .where(WebSocketMessage.flow_id == flow.id)
            .order_by(WebSocketMessage.sequence, WebSocketMessage.created_at)
        )
    ).all()
    return {
        "items": [
            {
                "id": str(message.id),
                "sequence": message.sequence,
                "fromClient": message.from_client,
                "opcode": message.opcode,
                "payloadSize": message.payload_size,
                "timestamp": message.timestamp.isoformat(),
                "payload": _websocket_preview(message, vault, raw, settings.preview_bytes),
            }
            for message in rows
        ],
        "raw": raw,
    }


@router.post("/flows/{flow_id}/reveal")
async def reveal_flow(
    flow_id: uuid.UUID,
    payload: ReauthInput,
    request: Request,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    if not verify_password(admin.password_hash, payload.password):
        await _audit(db, request, admin, "reveal.denied", "flow", str(flow_id))
        await db.commit()
        raise HTTPException(status_code=403, detail="password verification failed")
    if await db.get(Flow, flow_id) is None:
        raise HTTPException(status_code=404, detail="flow not found")
    token = reveal_store.issue(admin.id, flow_id)
    await _audit(db, request, admin, "reveal.granted", "flow", str(flow_id))
    await db.commit()
    return {"token": token, "expiresIn": 60}


@router.post("/flows/{flow_id}/export")
async def export_flow(
    flow_id: uuid.UUID,
    request: Request,
    payload: ReauthInput | None = None,
    raw: bool = False,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    flow = await db.get(Flow, flow_id)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    vault = Vault(settings.application_key, settings.body_root)
    headers = vault.decrypt_json(flow.request_headers_enc) or []
    response_headers = vault.decrypt_json(flow.response_headers_enc) or []
    query = vault.decrypt_json(flow.query_enc) or []
    if raw:
        if payload is None or not verify_password(admin.password_hash, payload.password):
            await _audit(db, request, admin, "export.raw.denied", "flow", str(flow.id))
            await db.commit()
            raise HTTPException(status_code=403, detail="raw export requires password")
        await _audit(db, request, admin, "export.raw", "flow", str(flow.id))
    else:
        headers, response_headers, query = redact_headers(headers), redact_headers(response_headers), redact_query(query)
        await _audit(db, request, admin, "export.redacted", "flow", str(flow.id))
    await db.commit()
    document = _flow_summary(flow) | {
        "url": vault.decrypt_json(flow.url_enc) if raw else f"{flow.scheme}://{flow.host}{flow.path or ''}",
        "query": query,
        "requestHeaders": headers,
        "responseHeaders": response_headers,
    }
    return JSONResponse(document, headers={"Content-Disposition": f'attachment; filename="{flow.id}.json"'})


@router.get("/sessions")
async def list_sessions(
    _: Admin = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    count = func.count(Flow.id)
    size = func.coalesce(func.sum(Flow.request_body_size + Flow.response_body_size), 0)
    result = await db.execute(
        select(CaptureSession, count, size)
        .outerjoin(Flow)
        .where(CaptureSession.deleted_at.is_(None))
        .group_by(CaptureSession.id)
        .order_by(desc(CaptureSession.started_at))
    )
    return [
        {
            "id": str(session.id),
            "name": session.name,
            "startedAt": session.started_at.isoformat(),
            "endedAt": session.ended_at.isoformat() if session.ended_at else None,
            "flowCount": flow_count,
            "bytes": total_bytes,
        }
        for session, flow_count, total_bytes in result.all()
    ]


@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: uuid.UUID,
    request: Request,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Response:
    session = await db.get(CaptureSession, session_id)
    if session is None or session.deleted_at is not None:
        raise HTTPException(status_code=404, detail="session not found")
    await _purge_session(db, session, settings, None)
    await _audit(db, request, admin, "session.deleted", "session", str(session_id))
    await db.commit()
    return Response(status_code=204)


@router.get("/devices")
async def list_devices(
    _: Admin = Depends(current_admin), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    devices = (await db.scalars(select(Device).order_by(Device.created_at))).all()
    return [
        {
            "id": str(device.id),
            "name": device.name,
            "peerPublicKey": device.peer_public_key,
            "tunnelIp": device.tunnel_ip,
            "lastSeenAt": device.last_seen_at.isoformat() if device.last_seen_at else None,
            "revokedAt": device.revoked_at.isoformat() if device.revoked_at else None,
        }
        for device in devices
    ]


@router.post("/devices", status_code=201)
async def create_device(
    payload: DeviceInput,
    request: Request,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    device = Device(**payload.model_dump())
    db.add(device)
    await _audit(db, request, admin, "device.created", "device", str(device.id))
    await db.commit()
    return {"id": str(device.id), "name": device.name}


@router.post("/devices/profile", status_code=201)
async def create_device_profile(
    payload: DeviceProfileInput,
    request: Request,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    try:
        profile = settings.wireguard_profile_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise HTTPException(status_code=409, detail="wireguard profile is not ready yet") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=409, detail="wireguard profile is not readable by api") from exc
    private_key = _wireguard_config_value(profile, "PrivateKey")
    if not private_key:
        raise HTTPException(status_code=500, detail="wireguard profile has no private key")
    peer_public_key = _derive_wireguard_public_key(private_key)
    tunnel_ip = _wireguard_tunnel_ip(profile)
    device = await db.scalar(select(Device).where(Device.peer_public_key == peer_public_key))
    if device is None:
        device = Device(name=payload.name, peer_public_key=peer_public_key, tunnel_ip=tunnel_ip)
        db.add(device)
    else:
        device.name = payload.name
        device.tunnel_ip = tunnel_ip
        device.revoked_at = None
    try:
        await db.flush()
        await _audit(db, request, admin, "device.profile.generated", "device", str(device.id))
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="wireguard tunnel IP is already registered") from exc
    return {
        "deviceId": str(device.id),
        "name": device.name,
        "profile": profile + "\n",
        "peerPublicKey": peer_public_key,
        "tunnelIp": tunnel_ip,
        "filename": _safe_profile_filename(payload.name),
    }


@router.post("/devices/{device_id}/revoke")
async def revoke_device(
    device_id: uuid.UUID,
    request: Request,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="device not found")
    device.revoked_at = datetime.now(UTC)
    await _audit(db, request, admin, "device.revoked", "device", str(device_id))
    await db.commit()
    return {"revoked": True}


@router.get("/system")
async def system_status(
    _: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    state = await db.get(SystemState, 1)
    usage = shutil.disk_usage(settings.body_root)
    recorded = await db.scalar(select(func.coalesce(func.sum(Flow.request_body_size + Flow.response_body_size), 0)))
    return {
        "recordingPaused": state.recording_paused if state else False,
        "droppedEvents": state.dropped_events if state else 0,
        "spooledEvents": state.spooled_events if state else 0,
        "recordedBodyBytes": recorded,
        "disk": {"total": usage.total, "used": usage.used, "free": usage.free},
        "retentionDays": settings.retention_days,
        "storageQuotaBytes": settings.storage_quota_bytes,
        "previewBytes": settings.preview_bytes,
    }


@router.put("/system/pause")
async def set_pause(
    payload: PauseInput,
    request: Request,
    admin: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    state = await db.get(SystemState, 1)
    if state is None:
        state = SystemState(id=1)
        db.add(state)
    state.recording_paused = payload.paused
    await _audit(db, request, admin, "capture.paused" if payload.paused else "capture.resumed")
    await db.commit()
    await hub.publish({"type": "control", "recordingPaused": payload.paused})
    return {"recordingPaused": payload.paused}


@router.get("/audit")
async def audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    _: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    rows = (await db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(limit))).all()
    return [
        {
            "id": str(row.id),
            "action": row.action,
            "targetType": row.target_type,
            "targetId": row.target_id,
            "sourceIp": row.source_ip,
            "createdAt": row.created_at.isoformat(),
        }
        for row in rows
    ]


@internal.get("/control")
async def internal_control(db: AsyncSession = Depends(get_db)) -> dict:
    state = await db.get(SystemState, 1)
    revoked_tunnel_ips = (
        await db.scalars(
            select(Device.tunnel_ip).where(Device.revoked_at.is_not(None), Device.tunnel_ip.is_not(None))
        )
    ).all()
    return {
        "recording": not (state and state.recording_paused),
        "revokedTunnelIps": revoked_tunnel_ips,
    }


@internal.post("/metrics", status_code=202)
async def capture_metrics(event: CaptureMetrics, db: AsyncSession = Depends(get_db)) -> dict:
    state = await db.get(SystemState, 1)
    if state is None:
        state = SystemState(id=1)
        db.add(state)
    state.spooled_events = event.spooled_events
    state.dropped_events = event.dropped_events
    await db.commit()
    return {"accepted": True}


@internal.post("/ingest", status_code=202)
async def ingest(
    event: IngestEvent,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    state = await db.get(SystemState, 1)
    if state and state.recording_paused:
        return {"accepted": False, "recording": False}

    if isinstance(event, HeaderEvent):
        existing = await db.scalar(select(Flow).where(Flow.capture_id == event.capture_id))
        if existing is not None:
            return {"accepted": True, "recording": True}
        device = None
        if event.device_ip:
            device = await db.scalar(
                select(Device).where(Device.tunnel_ip == event.device_ip, Device.revoked_at.is_(None))
            )
        session = await db.scalar(select(CaptureSession).where(CaptureSession.session_key == event.session_key))
        if session is None:
            session = CaptureSession(
                name=f"Capture {event.started_at:%Y-%m-%d %H:%M:%S} {event.session_key[-8:]}",
                session_key=event.session_key,
                device_id=device.id if device else None,
                started_at=event.started_at,
            )
            db.add(session)
            await db.flush()
        flow = Flow(
            capture_id=event.capture_id,
            session_id=session.id,
            device_id=device.id if device else None,
            protocol=event.protocol,
            method=event.method,
            scheme=event.scheme,
            host=event.host,
            port=event.port,
            path=event.path,
            request_content_type=event.request_content_type,
            started_at=event.started_at,
            request_headers_enc=_decode_encrypted(event.request_headers_enc),
            url_enc=_decode_encrypted(event.url_enc),
            query_enc=_decode_encrypted(event.query_enc),
            state="loading",
        )
        db.add(flow)
        if device:
            device.last_seen_at = datetime.now(UTC)
        await db.flush()
        await _enforce_storage_limits(db, settings, session.id)
        await db.commit()
        payload = {"type": "flow.headers", "flow": _flow_summary(flow)}
    elif isinstance(event, CompleteEvent):
        flow = await db.scalar(select(Flow).where(Flow.capture_id == event.capture_id))
        if flow is None:
            raise HTTPException(status_code=409, detail="headers event not found")
        flow.completed_at = event.completed_at
        flow.status_code = event.status_code
        flow.response_content_type = event.response_content_type
        flow.response_headers_enc = _decode_encrypted(event.response_headers_enc)
        flow.request_body_path = event.request_body_path
        flow.response_body_path = event.response_body_path
        flow.request_body_size = event.request_body_size
        flow.response_body_size = event.response_body_size
        flow.duration_ms = event.duration_ms
        flow.error_code = event.error_code
        flow.error_enc = _decode_encrypted(event.error_enc)
        flow.not_captured_reason = event.not_captured_reason
        flow.websocket = event.websocket
        flow.state = "error" if event.event == "error" else "complete"
        session = await db.get(CaptureSession, flow.session_id)
        if session:
            session.ended_at = event.completed_at
        await db.flush()
        await _enforce_storage_limits(db, settings, flow.session_id)
        await db.commit()
        payload = {"type": f"flow.{flow.state}", "flow": _flow_summary(flow)}
    else:
        flow = await db.scalar(select(Flow).where(Flow.capture_id == event.capture_id))
        if flow is None:
            raise HTTPException(status_code=409, detail="flow not found")
        existing = await db.scalar(
            select(WebSocketMessage).where(
                WebSocketMessage.flow_id == flow.id, WebSocketMessage.sequence == event.sequence
            )
        )
        if existing is None:
            db.add(
                WebSocketMessage(
                    flow_id=flow.id,
                    sequence=event.sequence,
                    from_client=event.from_client,
                    opcode=event.opcode,
                    payload_path=event.payload_path,
                    payload_size=event.payload_size,
                    timestamp=event.timestamp,
                )
            )
        await db.commit()
        payload = {"type": "websocket.message", "flowId": str(flow.id), "sequence": event.sequence}
    await hub.publish(payload)
    return {"accepted": True, "recording": True}
