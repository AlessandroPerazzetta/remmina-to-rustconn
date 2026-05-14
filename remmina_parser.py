"""Parse Remmina .remmina INI profile files into normalised connection dicts."""

from __future__ import annotations

import configparser
from pathlib import Path

DEFAULT_PORTS: dict[str, int] = {"SSH": 22, "RDP": 3389, "VNC": 5900}
SUPPORTED_PROTOCOLS: frozenset[str] = frozenset(DEFAULT_PORTS)


def _int(value: str, default: int) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _bool(value: str) -> bool:
    return value.strip() == "1"


def _parse_server(server: str, default_port: int) -> tuple[str, int]:
    """Split 'host:port' into (host, port), handling plain hostnames too."""
    server = server.strip()
    if ":" in server:
        host, _, port_str = server.rpartition(":")
        try:
            return host.strip(), int(port_str.strip())
        except ValueError:
            pass
    return server, default_port


def parse_remmina_file(path: Path) -> dict | None:
    """Parse a single .remmina file. Returns None if unsupported or malformed."""
    cp = configparser.RawConfigParser()
    try:
        cp.read(path, encoding="utf-8")
    except Exception:
        return None

    if "remmina" not in cp:
        return None

    s = cp["remmina"]
    protocol = s.get("protocol", "").strip().upper()
    if protocol not in SUPPORTED_PROTOCOLS:
        return None

    server = s.get("server", "").strip()
    host, port = _parse_server(server, DEFAULT_PORTS[protocol])
    if not host:
        return None

    group = s.get("group", "").strip()

    return {
        "name": s.get("name", path.stem).strip(),
        "protocol": protocol,
        "host": host,
        "port": port,
        "source_file": str(path),
        "username": s.get("username", "").strip(),
        "group": group,
        "window_maximize": _bool(s.get("window_maximize", "0")),
        # SSH
        "ssh_auth": s.get("ssh_auth", "0").strip(),
        "ssh_privatekey": s.get("ssh_privatekey", "").strip(),
        "ssh_tunnel_enabled": _bool(s.get("ssh_tunnel_enabled", "0")),
        "ssh_tunnel_server": s.get("ssh_tunnel_server", "").strip(),
        "ssh_tunnel_username": s.get("ssh_tunnel_username", "").strip(),
        "ssh_tunnel_auth": s.get("ssh_tunnel_auth", "0").strip(),
        "ssh_tunnel_privatekey": s.get("ssh_tunnel_privatekey", "").strip(),
        "ssh_compression": _bool(s.get("ssh_compression", "0")),
        "ssh_forward_x11": _bool(s.get("ssh_forward_x11", "0")),
        # RDP
        "colordepth": _int(s.get("colordepth", "16"), 16),
        "rdp_quality": s.get("quality", "2").strip(),
        "disableclipboard": _bool(s.get("disableclipboard", "0")),
        "cert_ignore": _bool(
            s.get("cert_ignore", s.get("ignore-tls-errors", "0"))
        ),
        "security": s.get("security", "").strip(),
        # VNC
        "viewonly": _bool(s.get("viewonly", "0")),
        "showcursor": _bool(s.get("showcursor", "0")),
        "vnc_quality": s.get("quality", "2").strip(),
    }


def parse_remmina_dir(path: Path) -> list[dict]:
    """Parse all .remmina files in a directory, skipping unrecognised files."""
    connections: list[dict] = []
    for f in sorted(path.glob("*.remmina")):
        conn = parse_remmina_file(f)
        if conn is not None:
            connections.append(conn)
    return connections
