"""Serialise parsed Remmina connections to RustConn connections.toml format."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

# Namespace UUID for deterministic group UUIDs (uuid5)
_GROUP_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")

# RDP quality map: Remmina quality value → RustConn performance_mode
# Remmina: 0=Poor (fastest), 1=Medium, 2=Good, 9=Best (slowest)
# RustConn: speed | balanced | quality
_RDP_QUALITY: dict[str, str] = {
    "0": "speed",
    "1": "balanced",
    "2": "quality",
    "9": "quality",
}

# VNC quality map: Remmina quality value → RustConn performance_mode
# Remmina: 0=Poor (fastest), 1=Medium, 2=Good, 9=Best (slowest)
# RustConn: speed | balanced | quality
_VNC_QUALITY: dict[str, str] = {
    "0": "speed",
    "1": "balanced",
    "2": "quality",
    "9": "quality",
}

# SSH auth map: Remmina ssh_auth → RustConn auth_method
_SSH_AUTH: dict[str, str] = {
    "0": "password",
    "1": "ssh_agent",
    "2": "public_key",
    "3": "public_key",
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


def _group_uuid(group_path: str) -> str:
    """Return a deterministic UUID v5 for a given group path string."""
    return str(uuid.uuid5(_GROUP_NAMESPACE, group_path))


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _toml_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _build_common_fields(
    conn: dict, group_id: str, sort_order: int, ts: str, has_credential: bool = False
) -> list[str]:
    window_mode = "fullscreen" if conn["window_maximize"] else "embedded"
    password_source = "vault" if has_credential else "none"
    return [
        f'id = {_toml_str(str(uuid.uuid4()))}',
        f'name = {_toml_str(conn["name"])}',
        f'protocol = {_toml_str(conn["protocol"].lower())}',
        f'host = {_toml_str(conn["host"])}',
        f'port = {conn["port"]}',
        f'username = {_toml_str(conn["username"])}',
        f'group_id = {_toml_str(group_id)}',
        f'created_at = {_toml_str(ts)}',
        f'updated_at = {_toml_str(ts)}',
        f'sort_order = {sort_order}',
        f'password_source = "{password_source}"',
        f'window_mode = {_toml_str(window_mode)}',
        "remember_window_position = false",
        "skip_port_check = false",
        "is_pinned = false",
        "pin_order = 0",
        "session_recording_enabled = false",
        "is_dynamic = false",
    ]


def _build_ssh_config(conn: dict) -> list[str]:
    auth_method = _SSH_AUTH.get(conn["ssh_auth"], "password")
    lines = [
        'type = "Ssh"',
        f'auth_method = {_toml_str(auth_method)}',
        "identities_only = false",
        "use_control_master = false",
        "agent_forwarding = false",
        f'x11_forwarding = {_toml_bool(conn["ssh_forward_x11"])}',
        f'compression = {_toml_bool(conn["ssh_compression"])}',
        "sftp_enabled = false",
        "waypipe = false",
        "verbose = false",
    ]
    if auth_method == "public_key" and conn["ssh_privatekey"]:
        lines.insert(2, f'private_key_path = {_toml_str(conn["ssh_privatekey"])}')
    if conn["ssh_tunnel_enabled"] and conn["ssh_tunnel_server"]:
        tunnel_auth = _SSH_AUTH.get(conn["ssh_tunnel_auth"], "password")
        lines += [
            "",
            "[connections.protocol_config.tunnel]",
            f'server = {_toml_str(conn["ssh_tunnel_server"])}',
            f'username = {_toml_str(conn["ssh_tunnel_username"])}',
            f'auth_method = {_toml_str(tunnel_auth)}',
        ]
        if conn["ssh_tunnel_privatekey"]:
            lines.append(f'private_key_path = {_toml_str(conn["ssh_tunnel_privatekey"])}')
    return lines


def _build_rdp_config(conn: dict) -> list[str]:
    perf = _RDP_QUALITY.get(conn["rdp_quality"], "quality")
    clipboard = _toml_bool(not conn["disableclipboard"])
    security_layer = conn["security"] if conn["security"] else "negotiate"
    return [
        'type = "Rdp"',
        'client_mode = "embedded"',
        f'performance_mode = {_toml_str(perf)}',
        f'color_depth = {conn["colordepth"]}',
        "audio_redirect = false",
        'scale_override = "auto"',
        "disable_nla = false",
        f'security_layer = {_toml_str(security_layer)}',
        f'ignore_certificate = {_toml_bool(conn["cert_ignore"])}',
        f'clipboard_enabled = {clipboard}',
        "show_local_cursor = false",
        "jiggler_enabled = false",
        "jiggler_interval_secs = 0",
        "autotype_delay_ms = 0",
        "autotype_initial_delay_ms = 0",
    ]


def _build_vnc_config(conn: dict) -> list[str]:
    perf = _VNC_QUALITY.get(conn["vnc_quality"], "quality")
    clipboard = _toml_bool(not conn["disableclipboard"])
    return [
        'type = "Vnc"',
        'client_mode = "embedded"',
        f'performance_mode = {_toml_str(perf)}',
        f'view_only = {_toml_bool(conn["viewonly"])}',
        "scaling = false",
        f'clipboard_enabled = {clipboard}',
        'scale_override = "auto"',
        f'show_local_cursor = {_toml_bool(conn["showcursor"])}',
    ]


def _build_protocol_config(conn: dict) -> list[str]:
    protocol = conn["protocol"].upper()
    if protocol == "SSH":
        return _build_ssh_config(conn)
    if protocol == "RDP":
        return _build_rdp_config(conn)
    if protocol == "VNC":
        return _build_vnc_config(conn)
    return []


def _format_connection_block(
    conn: dict, group_id: str, sort_order: int, ts: str, has_credential: bool = False
) -> str:
    lines: list[str] = ["[[connections]]"]
    lines.extend(_build_common_fields(conn, group_id, sort_order, ts, has_credential))
    lines.append("")
    lines.append("[connections.protocol_config]")
    lines.extend(_build_protocol_config(conn))
    lines.append("")
    lines.append("[connections.automation]")
    lines.append("")
    return "\n".join(lines)


def build_group_map(connections: list[dict]) -> dict[str, str]:
    """Return {group_path: group_uuid} for all unique leaf groups (flat map)."""
    groups: dict[str, str] = {}
    for conn in connections:
        path = conn["group"]
        if path and path not in groups:
            groups[path] = _group_uuid(path)
    return groups


def build_full_group_hierarchy(
    connections: list[dict], root_key: str
) -> dict[str, dict]:
    """Build the complete nested group tree needed for groups.toml.

    Returns a dict keyed by the internal path string, each value is a dict with:
      id, name, parent_id (absent on root), full_path

    Remmina group fields (e.g. "SSH - KLAND/PROXMOX") are split on "/" to
    produce intermediate nodes.  The root group (root_key) is always included.
    """
    result: dict[str, dict] = {}

    # Root group — no parent_id
    result[root_key] = {
        "id": _group_uuid(root_key),
        "name": root_key,
    }

    for conn in connections:
        group_path = conn["group"].strip().replace("\\", "/")
        if not group_path:
            continue

        parts = [p.strip() for p in group_path.split("/") if p.strip()]

        for depth, part in enumerate(parts):
            current_path = "/".join(parts[: depth + 1])
            if current_path in result:
                continue

            parent_path = root_key if depth == 0 else "/".join(parts[:depth])
            result[current_path] = {
                "id": _group_uuid(current_path),
                "name": part,
                "parent_id": _group_uuid(parent_path),
            }

    return result


def write_groups_toml(
    group_hierarchy: dict[str, dict],
    output_path: Path,
    ts: str | None = None,
) -> None:
    """Write groups.toml from the hierarchy produced by build_full_group_hierarchy."""
    if not group_hierarchy:
        return

    if ts is None:
        ts = _now_utc()

    output_path.parent.mkdir(parents=True, exist_ok=True)

    blocks: list[str] = []
    for entry in group_hierarchy.values():
        lines = ["[[groups]]"]
        lines.append(f'id = {_toml_str(entry["id"])}')
        lines.append(f'name = {_toml_str(entry["name"])}')
        if "parent_id" in entry:
            lines.append(f'parent_id = {_toml_str(entry["parent_id"])}')
        lines.append("expanded = true")
        lines.append(f'created_at = {_toml_str(ts)}')
        lines.append("sort_order = 0")
        lines.append('sync_mode = "None"')
        lines.append("")
        blocks.append("\n".join(lines))

    output_path.write_text("\n".join(blocks), encoding="utf-8")


def write_connections_toml(
    connections: list[dict],
    output_path: Path,
    credentials: dict[int, str] | None = None,
    root_key: str = "Connections",
) -> dict[str, str]:
    """Write connections.toml and return the flat group map used.

    credentials maps connection index → password (from keyring_reader).
    Connections present in credentials get password_source = "vault".
    Connections with no group are assigned to the root group.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ts = _now_utc()
    group_map = build_group_map(connections)
    root_uuid = _group_uuid(root_key)
    creds = credentials or {}

    blocks: list[str] = []
    for i, conn in enumerate(connections):
        group_id = group_map.get(conn["group"], root_uuid)
        blocks.append(_format_connection_block(conn, group_id, i, ts, has_credential=i in creds))

    output_path.write_text("\n".join(blocks), encoding="utf-8")
    return group_map
