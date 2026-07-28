import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.api import (
    _derive_wireguard_public_key,
    _safe_profile_filename,
    _wireguard_config_value,
    _wireguard_tunnel_ip,
)


def test_wireguard_profile_helpers_parse_current_client_profile():
    profile = """
    [Interface]
    PrivateKey = abc=
    Address = 10.0.0.2/32, fd00::2/128

    [Peer]
    PublicKey = server=
    Endpoint = example.com:51820
    """

    assert _wireguard_config_value(profile, "PrivateKey") == "abc="
    assert _wireguard_config_value(profile, "Endpoint") == "example.com:51820"
    assert _wireguard_tunnel_ip(profile) == "10.0.0.2"


def test_wireguard_public_key_derivation_uses_x25519_raw_key():
    private_bytes = b"\x01" * 32
    private_key_b64 = base64.b64encode(private_bytes).decode()
    expected_public_key = base64.b64encode(
        x25519.X25519PrivateKey.from_private_bytes(private_bytes).public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode()

    assert _derive_wireguard_public_key(private_key_b64) == expected_public_key


def test_safe_profile_filename_removes_path_characters():
    assert _safe_profile_filename("my phone") == "my-phone.conf"
    assert _safe_profile_filename("../secret/key") == "secret-key.conf"
    assert _safe_profile_filename("   ") == "device.conf"
