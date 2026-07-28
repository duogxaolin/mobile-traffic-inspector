from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


class LoginInput(BaseModel):
    username: str = "admin"
    password: str = Field(min_length=12, max_length=512)


class ReauthInput(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class DeviceInput(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    peer_public_key: str = Field(min_length=32, max_length=128)
    tunnel_ip: str | None = Field(default=None, max_length=64)


class PauseInput(BaseModel):
    paused: bool


class CaptureMetrics(BaseModel):
    spooled_events: int = Field(ge=0)
    dropped_events: int = Field(ge=0)


class HeaderEvent(BaseModel):
    event: Literal["headers"]
    capture_id: str = Field(max_length=128)
    device_ip: str | None = Field(default=None, max_length=64)
    session_key: str = Field(max_length=128)
    protocol: str = Field(max_length=24)
    method: str | None = Field(default=None, max_length=16)
    scheme: str | None = Field(default=None, max_length=16)
    host: str = Field(max_length=512)
    port: int | None = None
    path: str | None = Field(default=None, max_length=8192)
    request_content_type: str | None = Field(default=None, max_length=255)
    started_at: datetime
    request_headers_enc: str | None = None
    url_enc: str | None = None
    query_enc: str | None = None


class CompleteEvent(BaseModel):
    event: Literal["complete", "error"]
    capture_id: str = Field(max_length=128)
    completed_at: datetime
    status_code: int | None = None
    response_content_type: str | None = Field(default=None, max_length=255)
    response_headers_enc: str | None = None
    request_body_path: str | None = Field(default=None, max_length=1024)
    response_body_path: str | None = Field(default=None, max_length=1024)
    request_body_size: int = Field(default=0, ge=0)
    response_body_size: int = Field(default=0, ge=0)
    duration_ms: int | None = Field(default=None, ge=0)
    error_enc: str | None = None
    error_code: str | None = Field(default=None, max_length=80)
    not_captured_reason: str | None = Field(default=None, max_length=160)
    websocket: bool = False


class WebSocketEvent(BaseModel):
    event: Literal["websocket"]
    capture_id: str = Field(max_length=128)
    sequence: int = Field(ge=0)
    from_client: bool
    opcode: int
    payload_path: str | None = Field(default=None, max_length=1024)
    payload_size: int = Field(default=0, ge=0)
    timestamp: datetime


IngestEvent = HeaderEvent | CompleteEvent | WebSocketEvent
