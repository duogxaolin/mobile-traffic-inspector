from __future__ import annotations

import ipaddress
import socket

METADATA_HOSTS = {
    "169.254.169.254",
    "100.100.100.200",
    "168.63.129.16",
    "metadata.google.internal",
    "metadata.azure.internal",
}


def resolve_destination(host: str | None, port: int | None = None, overrides: set[str] | None = None) -> str | None:
    """Return one approved IP address for a destination, pinned for a connection.

    Callers must connect to the returned literal address rather than resolve the
    hostname again. This closes DNS-rebinding gaps between policy evaluation and
    connection establishment. Hostname overrides remain explicit operator policy;
    cloud metadata names and addresses are never overrideable.
    """
    allowed_overrides = overrides or set()
    if not host:
        return None
    clean = host.strip("[]").lower().rstrip(".")
    if clean in METADATA_HOSTS:
        return None
    try:
        addresses = [ipaddress.ip_address(clean)]
    except ValueError:
        try:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(clean, port or 443, type=0)
            ]
        except (OSError, socket.gaierror):
            return None
    if not addresses:
        return None
    for address in addresses:
        address_text = str(address)
        if address_text in METADATA_HOSTS:
            return None
        explicitly_allowed = clean in allowed_overrides or address_text in allowed_overrides
        if not explicitly_allowed and (
            not address.is_global
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
        ):
            return None
    return str(addresses[0])


def destination_allowed(host: str | None, port: int | None = None, overrides: set[str] | None = None) -> bool:
    return resolve_destination(host, port, overrides) is not None


def client_allowed(peer_ip: str | None, revoked_tunnel_ips: set[str]) -> bool:
    """Keep capture-all behavior while blocking only explicitly revoked tunnel peers."""
    return not peer_ip or peer_ip not in revoked_tunnel_ips
