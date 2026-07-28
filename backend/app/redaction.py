from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode

SENSITIVE_NAME = re.compile(
    r"(^|[-_])(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|api[-_]?key|"
    r"access[-_]?token|refresh[-_]?token|token|password|passwd|passcode|otp|secret)($|[-_])",
    re.IGNORECASE,
)
INLINE_SECRET = re.compile(
    r"(?i)(\"?(?:token|password|passwd|passcode|otp|secret|api[_-]?key)\"?\s*[:=]\s*)"
    r"([^&\s,;}]+)"
)
REDACTED = "••••••••"


def sensitive(name: str) -> bool:
    return bool(SENSITIVE_NAME.search(name))


def redact_headers(headers: list[list[str]] | None) -> list[list[str]]:
    return [[name, REDACTED if sensitive(name) else value] for name, value in (headers or [])]


def _redact_value(value: Any, key: str = "") -> Any:
    if key and sensitive(key):
        return REDACTED
    if isinstance(value, dict):
        return {k: _redact_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    return value


def redact_body(content: bytes, content_type: str | None) -> tuple[bytes, str]:
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type.endswith("+json") or media_type == "application/json":
        try:
            value = json.loads(content)
            return json.dumps(_redact_value(value), ensure_ascii=False, indent=2).encode(), "json"
        except (ValueError, UnicodeDecodeError):
            pass
    if media_type == "application/x-www-form-urlencoded":
        try:
            fields = [
                (key, REDACTED if sensitive(key) else value)
                for key, value in parse_qsl(content.decode(), keep_blank_values=True)
            ]
            return urlencode(fields).encode(), "form"
        except UnicodeDecodeError:
            pass
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return content, "binary"
    return INLINE_SECRET.sub(r"\1" + REDACTED, text).encode(), "text"


def redact_query(query: list[list[str]] | None) -> list[list[str]]:
    return [[name, REDACTED if sensitive(name) else value] for name, value in (query or [])]

