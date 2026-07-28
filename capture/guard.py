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


def destination_allowed(host: str | None, port: int | None = None, overrides: set[str] | None = None) -> bool:
    """Resolve a destination at connect time and reject non-global addresses.

    Re-resolving on every connection prevents DNS rebinding from turning the
    inspector into a route to the VPS, LAN, loopback, or cloud metadata service.
    Overrides are deliberately explicit and supplied by operator configuration.
    """
    allowed_overrides = overrides or set()
    if not host:
        return False
    clean = host.strip("[]").lower().rstrip(".")
    if clean in allowed_overrides:
        return True
    if clean in METADATA_HOSTS:
        return False
    try:
        addresses = [ipaddress.ip_address(clean)]
    except ValueError:
        try:
            addresses = [
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(clean, port or 443, type=socket.SOCK_STREAM)
            ]
        except (OSError, socket.gaierror):
            return False
    return all(
        address.is_global
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and str(address) not in allowed_overrides
        for address in addresses
    )
