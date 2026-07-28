import socket

from guard import destination_allowed, resolve_destination


def test_guard_rejects_private_loopback_metadata_and_accepts_explicit_override():
    assert destination_allowed("127.0.0.1", 443) is False
    assert destination_allowed("169.254.169.254", 80) is False
    assert destination_allowed("10.0.0.4", 443) is False
    assert destination_allowed("10.0.0.4", 443, {"10.0.0.4"}) is True


def test_resolved_ip_is_pinned_before_a_rebinding_lookup(monkeypatch):
    calls = 0

    def answers(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        address = "93.184.216.34" if calls == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    monkeypatch.setattr(socket, "getaddrinfo", answers)
    pinned = resolve_destination("example.test", 443)
    assert pinned == "93.184.216.34"
    assert resolve_destination(pinned, 443) == pinned
    assert calls == 1


def test_capture_all_admits_unknown_peers_but_blocks_revoked_tunnel_ips():
    from guard import client_allowed

    assert client_allowed("10.20.0.12", set()) is True
    assert client_allowed("10.20.0.12", {"10.20.0.12"}) is False
