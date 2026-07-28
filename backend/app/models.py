from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base, TimestampMixin


class Admin(Base, TimestampMixin):
    __tablename__ = "admins"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, default="admin")
    password_hash: Mapped[str] = mapped_column(Text)
    session_version: Mapped[int] = mapped_column(Integer, default=1)


class Device(Base, TimestampMixin):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128))
    peer_public_key: Mapped[str] = mapped_column(String(128), unique=True)
    tunnel_ip: Mapped[str | None] = mapped_column(String(64), unique=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class CaptureSession(Base, TimestampMixin):
    __tablename__ = "capture_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(180))
    session_key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    device: Mapped[Device | None] = relationship()


class Flow(Base, TimestampMixin):
    __tablename__ = "flows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    capture_id: Mapped[str] = mapped_column(String(128), unique=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("capture_sessions.id", ondelete="CASCADE"), index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    protocol: Mapped[str] = mapped_column(String(24), default="HTTP/1.1")
    method: Mapped[str | None] = mapped_column(String(16), index=True)
    scheme: Mapped[str | None] = mapped_column(String(16))
    host: Mapped[str] = mapped_column(String(512), index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    path: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer, index=True)
    request_content_type: Mapped[str | None] = mapped_column(String(255), index=True)
    response_content_type: Mapped[str | None] = mapped_column(String(255), index=True)
    request_headers_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    response_headers_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    url_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    query_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    request_body_path: Mapped[str | None] = mapped_column(Text)
    response_body_path: Mapped[str | None] = mapped_column(Text)
    request_body_size: Mapped[int] = mapped_column(BigInteger, default=0)
    response_body_size: Mapped[int] = mapped_column(BigInteger, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(24), default="loading", index=True)
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    not_captured_reason: Mapped[str | None] = mapped_column(String(160))
    websocket: Mapped[bool] = mapped_column(Boolean, default=False)
    session: Mapped[CaptureSession] = relationship()

    __table_args__ = (Index("ix_flows_host_path_time", "host", "started_at"),)


class WebSocketMessage(Base, TimestampMixin):
    __tablename__ = "websocket_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    from_client: Mapped[bool] = mapped_column(Boolean)
    opcode: Mapped[int] = mapped_column(Integer)
    payload_path: Mapped[str | None] = mapped_column(Text)
    payload_size: Mapped[int] = mapped_column(BigInteger, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    admin_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("admins.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(96), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(128))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    detail_enc: Mapped[bytes | None] = mapped_column(LargeBinary)


class SystemState(Base):
    __tablename__ = "system_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    recording_paused: Mapped[bool] = mapped_column(Boolean, default=False)
    dropped_events: Mapped[int] = mapped_column(BigInteger, default=0)
    spooled_events: Mapped[int] = mapped_column(BigInteger, default=0)
