from __future__ import annotations

import base64
import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _secret(name: str, default: str | None = None) -> str:
    file_name = os.getenv(f"{name}_FILE")
    if file_name:
        return Path(file_name).read_text(encoding="utf-8").strip()
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"{name} or {name}_FILE is required")
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    database_url: str = ""
    application_key: bytes = b""
    session_secret: bytes = b""
    ingest_token: str = ""
    admin_password: str = ""
    body_root: Path = Path("/var/lib/traffic-inspector/bodies")
    wireguard_profile_path: Path = Path("/var/lib/traffic-inspector/mitmproxy/wireguard.conf")
    preview_bytes: int = Field(default=262_144, ge=4096)
    retention_days: int = Field(default=0, ge=0)
    storage_quota_bytes: int = Field(default=0, ge=0)
    secure_cookies: bool = True

    @classmethod
    def load(cls) -> "Settings":
        raw_key = _secret("APPLICATION_KEY")
        try:
            key = base64.b64decode(raw_key, validate=True)
        except ValueError as exc:
            raise RuntimeError("APPLICATION_KEY must be base64") from exc
        if len(key) != 32:
            raise RuntimeError("APPLICATION_KEY must decode to exactly 32 bytes")
        return cls(
            database_url=_secret("DATABASE_URL"),
            application_key=key,
            session_secret=_secret("SESSION_SECRET").encode(),
            ingest_token=_secret("INGEST_TOKEN"),
            admin_password=_secret("ADMIN_PASSWORD"),
            body_root=Path(os.getenv("BODY_ROOT", "/var/lib/traffic-inspector/bodies")),
            wireguard_profile_path=Path(
                os.getenv("WIREGUARD_PROFILE_PATH", "/var/lib/traffic-inspector/mitmproxy/wireguard.conf")
            ),
            preview_bytes=int(os.getenv("PREVIEW_BYTES", "262144")),
            retention_days=int(os.getenv("RETENTION_DAYS", "0")),
            storage_quota_bytes=int(os.getenv("STORAGE_QUOTA_BYTES", "0")),
            secure_cookies=os.getenv("SECURE_COOKIES", "true").lower() == "true",
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.load()
