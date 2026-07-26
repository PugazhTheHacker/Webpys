from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$"
)


def _is_valid_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _is_valid_domain(host: str) -> bool:
    if host.endswith("."):
        host = host[:-1]
    return bool(_DOMAIN_RE.match(host))


def validate_host(host: str) -> bool:
    host = host.strip().lower()
    return _is_valid_ip(host) or _is_valid_domain(host)


def split_host_port(target: str) -> tuple[str, int | None]:
    parsed = urlparse(target if "://" in target else f"placeholder://{target}")
    if not parsed.hostname:
        raise ValueError("Target does not contain a valid host")
    host = parsed.hostname.lower()
    port = parsed.port
    return host, port


def normalize_target(target: str, default_scheme: str = "https") -> str:
    value = target.strip()
    if not value:
        raise ValueError("Target cannot be empty")

    if "://" not in value:
        value = f"{default_scheme}://{value}"

    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError("Target host could not be parsed")

    host = parsed.hostname.lower()
    if not validate_host(host):
        raise ValueError(f"Invalid host: {host}")

    port_part = f":{parsed.port}" if parsed.port else ""
    netloc = f"{host}{port_part}"
    path = parsed.path or "/"

    return urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, ""))


def parse_ports(ports_spec: str | None) -> list[int]:
    if not ports_spec:
        return list(range(1, 1025))

    ports: set[int] = set()
    for chunk in ports_spec.split(","):
        part = chunk.strip()
        if not part:
            continue

        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start > end:
                raise ValueError(f"Invalid range: {part}")
            for port in range(start, end + 1):
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
            continue

        port = int(part)
        if port < 1 or port > 65535:
            raise ValueError(f"Port out of range: {port}")
        ports.add(port)

    if not ports:
        raise ValueError("No valid ports were provided")

    return sorted(ports)

