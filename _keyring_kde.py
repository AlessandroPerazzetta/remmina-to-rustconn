"""KDE Wallet (KWallet) credential reader using the SecretService D-Bus API.

KDE Wallet daemon (kwalletd5 / kwalletd6) must be running and the target wallet
must be unlocked.  An optional companion file may be present in the *same
directory* as the .kwl file:

  {stem}_attributes.json    — attribute index exported from kwalletd

When present, the attributes JSON supplements item attributes that kwalletd does
not always expose through its SecretService compatibility layer (e.g. the
``filename`` attribute on Remmina entries used for reliable matching).  The file
is loaded on a best-effort basis; missing or malformed files are silently ignored
and credentials are read from D-Bus alone.

Default wallet path (when the user does not specify --keyring):
  ~/.local/share/kwalletd/kdewallet.kwl
"""

from __future__ import annotations

import json
from pathlib import Path

_KWALLET_MAGIC = b"KWALLET\n\r\x00\r\n\x00"


def is_kde_wallet(path: Path) -> bool:
    """Return True if *path* starts with the KWallet magic bytes."""
    try:
        return path.read_bytes()[:13] == _KWALLET_MAGIC
    except OSError:
        return False


def _load_kde_wallet_attributes(kwl_path: Path) -> dict:
    """Try to load the companion attribute index; return an empty dict if unavailable.

    Missing, unreadable, or malformed files are silently ignored so that
    read_kde_keyring() can still read credentials from D-Bus alone.
    """
    attrs_file = kwl_path.parent / f"{kwl_path.stem}_attributes.json"
    if not attrs_file.is_file():
        return {}
    try:
        attrs_data = json.loads(attrs_file.read_text(encoding="utf-8"))
        if isinstance(attrs_data, dict):
            return attrs_data
    except (OSError, ValueError):
        pass
    return {}


def read_kde_keyring(kwl_path: Path) -> list[dict]:
    """Read credentials from a KDE wallet via the SecretService D-Bus API.

    Returns a list of credential dicts with keys:
      label, username, password, server, attributes.

    Raises RuntimeError if the kwalletd daemon is not running or if the wallet
    collection cannot be found.  The optional companion attributes file is
    loaded on a best-effort basis and does not cause failures when absent.
    """
    kwl_path = kwl_path.resolve()
    attrs_data = _load_kde_wallet_attributes(kwl_path)

    # Build item-label → attributes lookup from the JSON index.
    # Keys in the JSON are "Folder/ItemLabel" paths; strip the folder prefix
    # to obtain the label as exposed through the SecretService interface.
    label_to_attrs: dict[str, dict] = {}
    for key, value in attrs_data.items():
        if isinstance(value, dict) and "attributes" in value:
            item_label = key.split("/", 1)[-1] if "/" in key else key
            label_to_attrs[item_label] = value["attributes"]

    try:
        import secretstorage
    except ImportError as exc:
        raise RuntimeError(
            "secretstorage is not installed. "
            "Run: pip install secretstorage"
        ) from exc

    wallet_name = kwl_path.stem  # e.g. "kdewallet"
    conn = secretstorage.dbus_init()
    all_collections = list(secretstorage.get_all_collections(conn))

    collections = [
        c for c in all_collections
        if c.get_label().lower() == wallet_name.lower()
    ]
    if not collections:
        available = [c.get_label() for c in all_collections]
        raise RuntimeError(
            f"No KDE wallet collection matching '{wallet_name}'. "
            f"Available collections: {available}. "
            "Ensure kwalletd is running and the wallet is unlocked."
        )

    entries: list[dict] = []
    for collection in collections:
        if collection.is_locked():
            print(
                f"[kde-keyring] Skipping locked wallet: "
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
            item_label = item.get_label() or ""

            # Retrieve attributes from D-Bus; supplement from the JSON index
            # for items whose attributes were not exposed via SecretService
            # (e.g. items originally stored through the KWallet native API).
            attrs = item.get_attributes()
            if not attrs.get("xdg:schema") and item_label in label_to_attrs:
                attrs = {**label_to_attrs[item_label], **attrs}

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
                    "label": item_label,
                    "username": username,
                    "password": password,
                    "server": server,
                    "attributes": attrs,
                }
            )

    return entries
