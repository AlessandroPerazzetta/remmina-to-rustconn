"""GNOME Keyring credential reader using the secretstorage D-Bus API.

The GNOME keyring daemon (gnome-keyring-daemon) must be running and the target
collection must be unlocked.  If a .keyring binary file is supplied, its header
is parsed to extract the collection label used for filtering.
"""

from __future__ import annotations

import struct
from pathlib import Path

_GNOME_KEYRING_MAGIC = b"GnomeKeyring\n\r\x00\n"


def is_gnome_keyring(path: Path) -> bool:
    """Return True if *path* starts with the GNOME keyring magic bytes."""
    try:
        return path.read_bytes()[:16] == _GNOME_KEYRING_MAGIC
    except OSError:
        return False


def _identify_keyring_label(path: Path) -> str | None:
    """Return the collection label embedded in a .keyring binary, or None."""
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if len(data) < 29 or data[:16] != _GNOME_KEYRING_MAGIC:
        return None

    name_len = struct.unpack_from(">I", data, 20)[0]
    if 24 + name_len > len(data):
        return None

    return data[24: 24 + name_len].decode("utf-8", errors="replace")


def read_gnome_keyring(keyring_arg: str) -> list[dict]:
    """Connect to the GNOME keyring daemon and return a list of credential dicts.

    Each dict has keys: label, username, password, server, attributes.

    keyring_arg may be:
    - A file path to a .keyring binary (label is extracted from the header)
    - A plain collection label string
    - An empty string (all unlocked collections are read)
    """
    try:
        import secretstorage
    except ImportError as exc:
        raise RuntimeError(
            "secretstorage is not installed. "
            "Run: pip install secretstorage"
        ) from exc

    label_filter: str | None = None

    if keyring_arg:
        p = Path(keyring_arg)
        if p.is_file():
            label = _identify_keyring_label(p)
            if label:
                label_filter = label
            else:
                # File exists but is not a recognised keyring binary — treat
                # the argument as a plain collection label.
                label_filter = keyring_arg
        else:
            label_filter = keyring_arg

    conn = secretstorage.dbus_init()
    all_collections = list(secretstorage.get_all_collections(conn))

    if label_filter:
        collections = [
            c for c in all_collections
            if c.get_label().lower() == label_filter.lower()
        ]
        if not collections:
            available = [c.get_label() for c in all_collections]
            raise RuntimeError(
                f"No GNOME keyring collection matching '{label_filter}'. "
                f"Available: {available}"
            )
    else:
        collections = all_collections

    entries: list[dict] = []
    for collection in collections:
        if collection.is_locked():
            print(
                f"[gnome-keyring] Skipping locked collection: "
                f"'{collection.get_label()}'"
            )
            continue

        for item in collection.get_all_items():
            raw_secret = item.get_secret()
            password = (
                raw_secret.decode("utf-8", errors="replace").rstrip("\x00")
                if raw_secret
                else ""
            )
            attrs = item.get_attributes()
            username = (
                attrs.get("account")
                or attrs.get("username")
                or attrs.get("user")
                or ""
            )
            server = (
                attrs.get("service")
                or attrs.get("server")
                or attrs.get("host")
                or ""
            )
            entries.append(
                {
                    "label": item.get_label() or "",
                    "username": username,
                    "password": password,
                    "server": server,
                    "attributes": attrs,
                }
            )

    return entries
