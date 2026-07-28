from __future__ import annotations

import json
import os
import struct
from collections.abc import AsyncIterator, Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"MTIB1\x00"
CHUNK_SIZE = 1024 * 1024


class Vault:
    def __init__(self, key: bytes, root: Path) -> None:
        self._aes = AESGCM(key)
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def encrypt_json(self, value: Any) -> bytes:
        nonce = os.urandom(12)
        plain = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        return nonce + self._aes.encrypt(nonce, plain, b"mti-json-v1")

    def decrypt_json(self, value: bytes | None) -> Any:
        if not value:
            return None
        plain = self._aes.decrypt(value[:12], value[12:], b"mti-json-v1")
        return json.loads(plain)

    def safe_path(self, relative: str) -> Path:
        candidate = PurePosixPath(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("invalid body path")
        resolved = (self.root / Path(*candidate.parts)).resolve()
        if self.root not in resolved.parents:
            raise ValueError("body path escapes storage root")
        return resolved

    def decrypt_chunks(self, relative: str, max_bytes: int | None = None) -> Iterator[bytes]:
        path = self.safe_path(relative)
        emitted = 0
        with path.open("rb") as source:
            if source.read(len(MAGIC)) != MAGIC:
                raise ValueError("unsupported encrypted body format")
            while True:
                raw_size = source.read(4)
                if not raw_size:
                    break
                if len(raw_size) != 4:
                    raise ValueError("truncated encrypted body")
                ciphertext_size = struct.unpack(">I", raw_size)[0]
                nonce = source.read(12)
                ciphertext = source.read(ciphertext_size)
                if len(nonce) != 12 or len(ciphertext) != ciphertext_size:
                    raise ValueError("truncated encrypted chunk")
                chunk = self._aes.decrypt(nonce, ciphertext, b"mti-body-v1")
                if max_bytes is not None:
                    remaining = max_bytes - emitted
                    if remaining <= 0:
                        return
                    chunk = chunk[:remaining]
                emitted += len(chunk)
                if chunk:
                    yield chunk

    def read_preview(self, relative: str, max_bytes: int) -> tuple[bytes, bool]:
        content = b"".join(self.decrypt_chunks(relative, max_bytes + 1))
        return content[:max_bytes], len(content) > max_bytes


def encrypted_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0

