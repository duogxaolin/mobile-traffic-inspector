from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto import MAGIC, Vault


def test_json_encryption_round_trip_and_body_stream(tmp_path: Path):
    vault = Vault(b"k" * 32, tmp_path)
    encrypted = vault.encrypt_json([["Authorization", "secret"]])
    assert vault.decrypt_json(encrypted) == [["Authorization", "secret"]]

    nonce = b"n" * 12
    payload = b"body bytes" * 100
    encrypted_file = tmp_path / "body.mti"
    encrypted_file.write_bytes(
        MAGIC + len(AESGCM(b"k" * 32).encrypt(nonce, payload, b"mti-body-v1")).to_bytes(4, "big")
        + nonce
        + AESGCM(b"k" * 32).encrypt(nonce, payload, b"mti-body-v1")
    )
    assert b"".join(vault.decrypt_chunks("body.mti")) == payload
    preview, truncated = vault.read_preview("body.mti", 20)
    assert preview == payload[:20]
    assert truncated is True


def test_body_path_cannot_escape_storage(tmp_path: Path):
    vault = Vault(b"k" * 32, tmp_path)
    try:
        vault.safe_path("../outside")
    except ValueError:
        pass
    else:
        raise AssertionError("path traversal should be rejected")
