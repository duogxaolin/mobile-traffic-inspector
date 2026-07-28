from __future__ import annotations

import hmac

from fastapi import Depends, Header, HTTPException

from .config import Settings, get_settings


def require_ingest_token(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    expected = f"Bearer {settings.ingest_token}"
    if authorization is None or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid ingest credential")

