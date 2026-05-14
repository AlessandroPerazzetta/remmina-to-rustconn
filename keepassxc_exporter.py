"""Generate a KeePassXC-importable CSV from Remmina connections and keyring data."""

from __future__ import annotations

import csv
from pathlib import Path


def _keepassxc_group(conn: dict, root_key: str) -> str:
    """Build the KeePassXC group path for a connection.

    Format: RustConn/<root_key>[/<subgroups>]
    "Root" is KeePassXC's implicit root group — including it causes Root/Root/...
    The Remmina `group` field may itself contain slashes for sub-levels.
    """
    base = f"RustConn/{root_key}"
    group = conn.get("group", "").strip()
    if group:
        return f"{base}/{group}"
    return base


def _connection_url(conn: dict) -> str:
    protocol = conn["protocol"].lower()
    host = conn["host"]
    port = conn["port"]
    return f"{protocol}://{host}:{port}"


def write_keepassxc_csv(
    connections: list[dict],
    credentials: dict[int, str],
    output_path: Path,
    root_key: str = "Connections",
) -> int:
    """Write KeePassXC CSV. Returns the number of entries written.

    credentials is a mapping of connection index → plaintext password,
    as returned by keyring_reader.match_credentials().
    All connections are exported; password is empty when not found in keyring.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[list[str]] = []
    for idx, conn in enumerate(connections):
        group = _keepassxc_group(conn, root_key)
        title = conn["name"]
        username = conn["username"]
        password = credentials.get(idx, "")
        url = _connection_url(conn)
        notes = f"Imported from Remmina | protocol={conn['protocol']}"
        rows.append([group, title, username, password, url, notes])

    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(["Group", "Title", "Username", "Password", "URL", "Notes"])
        writer.writerows(rows)

    return len(rows)
