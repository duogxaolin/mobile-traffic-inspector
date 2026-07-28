import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.api import _websocket_preview
from app.crypto import MAGIC, Vault
from app.models import WebSocketMessage


def test_websocket_preview_is_redacted_unless_raw_reveal_is_active(tmp_path: Path):
    key = b"k" * 32
    payload = b'token=do-not-show&message=hello'
    nonce = b"n" * 12
    ciphertext = AESGCM(key).encrypt(nonce, payload, b"mti-body-v1")
    (tmp_path / "message.mti").write_bytes(MAGIC + len(ciphertext).to_bytes(4, "big") + nonce + ciphertext)
    message = WebSocketMessage(sequence=0, from_client=True, opcode=1, payload_path="message.mti", payload_size=len(payload))
    vault = Vault(key, tmp_path)

    redacted = _websocket_preview(message, vault, raw=False, max_bytes=1024)
    revealed = _websocket_preview(message, vault, raw=True, max_bytes=1024)

    assert b"do-not-show" not in base64.b64decode(redacted["content"])
    assert b"do-not-show" in base64.b64decode(revealed["content"])
