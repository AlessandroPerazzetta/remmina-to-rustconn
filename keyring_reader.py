"""Keyring credential reader — auto-detects GNOME or KDE wallet and dispatches
to the appropriate backend module.

Supported backends
------------------
  GNOME Keyring  (.keyring binary or collection label)
                 via the secretstorage / org.freedesktop.Secret.Service D-Bus API.
                 Default path: ~/.local/share/keyrings/login.keyring

  KDE Wallet     (.kwl binary)
                 via kwalletd's SecretService D-Bus compatibility layer.
                 An optional companion file ({stem}_attributes.json) may be
                 present in the same directory as the .kwl file to enrich
                 item attributes, but its absence does not prevent reading.
                 Default path: ~/.local/share/kwalletd/kdewallet.kwl
"""

from __future__ import annotations

from pathlib import Path

from _keyring_gnome import is_gnome_keyring, read_gnome_keyring
from _keyring_kde import is_kde_wallet, read_kde_keyring

# Default keyring file locations for each desktop environment.
GNOME_DEFAULT = Path.home() / ".local/share/keyrings/login.keyring"
KDE_DEFAULT   = Path.home() / ".local/share/kwalletd/kdewallet.kwl"


def _find_keyring_in_dir(directory: Path) -> tuple[Path | None, str]:
    """Scan *directory* for a recognised keyring file.

    Returns ``(path, kind)`` for the first match, or ``(None, '')`` if none
    is found.  GNOME ``.keyring`` files are preferred over KDE ``.kwl`` files
    when both are present.
    """
    for candidate in sorted(directory.iterdir()):
        if not candidate.is_file():
            continue
        if is_gnome_keyring(candidate):
            return candidate, "gnome"
        if is_kde_wallet(candidate):
            return candidate, "kde"
    return None, ""


def detect_keyring_type(path: Path) -> str:
    """Return ``'gnome'``, ``'kde'``, or ``'unknown'`` based on magic bytes."""
    if is_gnome_keyring(path):
        return "gnome"
    if is_kde_wallet(path):
        return "kde"
    return "unknown"


def read_keyring(keyring_arg: str) -> list[dict]:
    """Detect keyring type and return a normalised list of credential dicts.

    Each dict has keys: label, username, password, server, attributes.

    keyring_arg may be:
    - A file path to a .keyring binary  → GNOME (label extracted from header)
    - A file path to a .kwl binary      → KDE   (optional companion files used if present)
    - A directory path                  → scanned for the first valid keyring file
    - A plain collection label string   → GNOME (label passed directly)
    - An empty string / None            → GNOME (all unlocked collections)

    Raises RuntimeError with a user-friendly message on any validation or
    connection error so the caller can halt and display the error cleanly.
    """
    if keyring_arg:
        p = Path(keyring_arg)
        if p.is_dir():
            found, ktype = _find_keyring_in_dir(p)
            if found is None:
                raise RuntimeError(
                    f"No recognised keyring file found in directory: {p}"
                )
            print(f"[keyring] Found {ktype.upper()} keyring in directory: {found}")
            p = found
        if p.is_file():
            ktype = detect_keyring_type(p)
            if ktype == "kde":
                return read_kde_keyring(p)
            # "gnome" or "unknown" → GNOME reader handles both cases
            return read_gnome_keyring(str(p))
    return read_gnome_keyring(keyring_arg or "")


def detect_default_keyring() -> tuple[Path | None, str | None]:
    """Probe default locations and return ``(path, kind)`` for the first valid keyring found.

    *kind* is ``'GNOME'``, ``'KDE'``, or ``None`` when nothing is found.
    """
    if GNOME_DEFAULT.is_file() and is_gnome_keyring(GNOME_DEFAULT):
        return GNOME_DEFAULT, "GNOME"
    if KDE_DEFAULT.is_file() and is_kde_wallet(KDE_DEFAULT):
        return KDE_DEFAULT, "KDE"
    return None, None


def match_credentials(
    connections: list[dict], keyring_entries: list[dict]
) -> dict[int, str]:
    """Return {connection_index: password} for connections matched in keyring.

    For Remmina keyring entries (xdg:schema=org.remmina.Password), matching is
    done by comparing the basename of the 'filename' attribute against the
    connection's source_file basename.  For all other entries, matching falls
    back to host substring + optional username comparison.
    """
    # Split entries by type for efficiency
    remmina_entries = [
        e for e in keyring_entries
        if e["attributes"].get("xdg:schema") == "org.remmina.Password"
    ]
    other_entries = [
        e for e in keyring_entries
        if e["attributes"].get("xdg:schema") != "org.remmina.Password"
    ]

    matched: dict[int, str] = {}
    for idx, conn in enumerate(connections):
        # -- Remmina filename match (most reliable) --------------------------
        source_file = Path(conn.get("source_file", "")).name  # basename only
        if source_file:
            for entry in remmina_entries:
                kr_filename = Path(entry["attributes"].get("filename", "")).name
                if kr_filename and kr_filename == source_file:
                    matched[idx] = entry["password"]
                    break
            if idx in matched:
                continue

        # -- Fallback: host + username match for non-Remmina entries ---------
        conn_host = conn["host"].lower()
        conn_user = conn["username"].lower()
        for entry in other_entries:
            kr_server = entry["server"].lower()
            kr_user = entry["username"].lower()
            if conn_host and kr_server and (conn_host in kr_server or kr_server in conn_host):
                if not conn_user or not kr_user or conn_user == kr_user:
                    matched[idx] = entry["password"]
                    break

    return matched
