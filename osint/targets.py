from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain"}


def hostname_from_target(target: str) -> str:
    raw = target.strip()
    if not raw:
        raise ValueError("Target cannot be empty.")
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = parsed.hostname or raw.split("/")[0].split(":")[0]
    host = host.strip().lower().strip(".")
    if not host or " " in host:
        raise ValueError("Target must be a valid hostname or URL.")
    return host


def assert_public_hostname(target: str) -> str:
    host = hostname_from_target(target)
    if host in BLOCKED_HOSTNAMES or host.endswith(".local"):
        raise ValueError("Local/private targets are blocked. Use a public staging domain you own.")

    try:
        ip = ipaddress.ip_address(host)
        _assert_public_ip(ip)
        return host
    except ValueError as exc:
        if "Local/private" in str(exc):
            raise

    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        _assert_public_ip(ip)
    return host


def assert_public_url(target: str) -> str:
    raw = target.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP/HTTPS URLs are supported.")
    host = assert_public_hostname(parsed.hostname or "")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{host}{port}{path}{query}"


def _assert_public_ip(ip: ipaddress._BaseAddress) -> None:
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    ):
        raise ValueError("Local/private targets are blocked. Use a public staging domain you own.")
