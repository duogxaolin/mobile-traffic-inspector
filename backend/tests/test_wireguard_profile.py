import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi import HTTPException

from app.api import (
    _derive_wireguard_public_key,
    _safe_profile_filename,
    _wireguard_client_profile,
    _wireguard_config_value,
    _wireguard_endpoint,
    _wireguard_tunnel_ip,
)


def _private_key(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


def test_wireguard_key_state_builds_valid_client_profile():
    client_key = _private_key(1)
    server_key = _private_key(2)
    profile = _wireguard_client_profile(
        json.dumps({"server_key": server_key, "client_key": client_key}),
        "proxy.example.com",
        51820,
    )

    assert _wireguard_config_value(profile, "PrivateKey") == client_key
    assert _wireguard_config_value(profile, "Address") == "10.0.0.1/32"
    assert _wireguard_config_value(profile, "DNS") == "10.0.0.53"
    assert _wireguard_config_value(profile, "PublicKey") == _derive_wireguard_public_key(server_key)
    assert _wireguard_config_value(profile, "AllowedIPs") == "0.0.0.0/0"
    assert _wireguard_config_value(profile, "Endpoint") == "proxy.example.com:51820"
    assert _wireguard_tunnel_ip(profile) == "10.0.0.1"
    assert server_key not in profile


def test_wireguard_profile_preserves_legacy_ini_client_profile():
    profile = """
    [Interface]
    PrivateKey = {client_key}
    Address = 10.0.0.2/32, fd00::2/128

    [Peer]
    PublicKey = public-key
    Endpoint = example.com:51820
    """.format(client_key=_private_key(3))
    generated = _wireguard_client_profile(profile, "", 51820)

    assert generated == profile.strip() + "\n"
    assert _wireguard_config_value(generated, "Endpoint") == "example.com:51820"
    assert _wireguard_tunnel_ip(generated) == "10.0.0.2"


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        ("{not-json", "wireguard key state is invalid JSON"),
        (json.dumps([]), "wireguard key state must be a JSON object"),
        (json.dumps({"server_key": _private_key(1)}), "wireguard key state has no client key"),
        (json.dumps({"client_key": _private_key(1)}), "wireguard key state has no server key"),
        (
            json.dumps({"server_key": "invalid", "client_key": _private_key(1)}),
            "wireguard private key is not base64",
        ),
    ],
)
def test_wireguard_profile_rejects_malformed_key_state(source: str, detail: str):
    with pytest.raises(HTTPException) as error:
        _wireguard_client_profile(source, "proxy.example.com", 51820)

    assert error.value.status_code == 500
    assert error.value.detail == detail


@pytest.mark.parametrize(
    "site_address",
    [
        "",
        " proxy.example.com",
        "https://proxy.example.com",
        "proxy.example.com\nEndpoint = attacker.example:1",
        "proxy.example.com:51820",
        "[127.0.0.1]",
    ],
)
def test_wireguard_endpoint_rejects_invalid_or_injectable_hosts(site_address: str):
    with pytest.raises(HTTPException) as error:
        _wireguard_endpoint(site_address, 51820)

    assert error.value.detail == "SITE_ADDRESS is not a valid endpoint host"


def test_wireguard_endpoint_formats_ipv6_with_brackets():
    assert _wireguard_endpoint("2001:db8::1", 51820) == "[2001:db8::1]:51820"
    assert _wireguard_endpoint("[2001:db8::1]", 51820) == "[2001:db8::1]:51820"


@pytest.mark.parametrize("port", [0, 65536, True])
def test_wireguard_endpoint_rejects_invalid_ports(port):
    with pytest.raises(HTTPException) as error:
        _wireguard_endpoint("proxy.example.com", port)

    assert error.value.detail == "WIREGUARD_PORT is not a valid UDP port"


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
