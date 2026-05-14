"""remmina-to-rustconn — export Remmina profiles to RustConn + KeePassXC CSV.

Usage
-----
  python run.py [options]

Examples
--------
  # Use reference data (outputs go to tests/)
  python run.py --remmina-path references/Remmina --rustconn-output tests

  # Production use
  python run.py --remmina-path ~/.local/share/remmina \
                --rustconn-output ~/.config/rustconn \
                --keyring ~/.local/share/keyrings/login.keyring \
                --keepassxc-output ~/Desktop/keepassxc_import.csv \
                --root-key MyConnections
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from remmina_parser import parse_remmina_dir
from rustconn_writer import (
    write_connections_toml,
    build_full_group_hierarchy,
    write_groups_toml,
)
from keepassxc_exporter import write_keepassxc_csv

# ---------------------------------------------------------------------------
# Colour helpers (no external deps — plain ANSI codes)
# ---------------------------------------------------------------------------
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_CYAN   = "\033[36m"
_RED    = "\033[31m"
_DIM    = "\033[2m"


def _ok(msg: str) -> str:   return f"{_GREEN}✔{_RESET}  {msg}"
def _info(msg: str) -> str: return f"{_CYAN}ℹ{_RESET}  {msg}"
def _warn(msg: str) -> str: return f"{_YELLOW}⚠{_RESET}  {_BOLD}{msg}{_RESET}"
def _err(msg: str) -> str:  return f"{_RED}✖{_RESET}  {_BOLD}{msg}{_RESET}"
def _dim(msg: str) -> str:  return f"{_DIM}{msg}{_RESET}"
def _head(msg: str) -> str: return f"\n{_BOLD}{_CYAN}{msg}{_RESET}"

def _prompt(question: str) -> str:
    """Print *question* and return the stripped, lowercased user input."""
    try:
        return input(question).strip().lower()
    except EOFError:
        return ""


_CANCEL = "__CANCEL__"


def _resolve_keyring(explicit_arg: str | None) -> str | None:
    """Return the keyring path/label to use, None to skip, or _CANCEL to abort.

    - Explicit --keyring provided → return as-is, no prompts.
    - Not provided, default found  → notify user and ask for confirmation.
    - Not provided, nothing found  → ask whether to continue without credentials
                                     or abort entirely.
    """
    if explicit_arg is not None:
        return explicit_arg

    from keyring_reader import detect_default_keyring, GNOME_DEFAULT, KDE_DEFAULT
    path, kind = detect_default_keyring()

    if path is not None:
        print(_warn("No --keyring argument provided."))
        print(_info(f"Detected {kind} keyring at default path:"))
        print(f"        {_dim(str(path))}")
        answer = _prompt("   Use this keyring for credential export? [y/n]: ")
        if answer in ("y", "yes"):
            return str(path)
        print(_info("Skipping credential export — Remmina connections will be exported without passwords."))
        return None

    print(_warn("No --keyring argument provided and no default keyring was found."))
    print(f"   {_dim(f'Checked (GNOME): {GNOME_DEFAULT}')}")
    print(f"   {_dim(f'Checked  (KDE) : {KDE_DEFAULT}')}")
    answer = _prompt("   Export Remmina connections without credentials? [y/n]: ")
    if answer in ("y", "yes"):
        print(_info("Proceeding without credential export."))
        return None
    print(_err("Export cancelled by user."))
    return _CANCEL


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Remmina profiles to RustConn connections.toml and KeePassXC CSV.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python run.py --remmina-path references/Remmina "
            "--rustconn-output tests\n"
            "  python run.py --remmina-path ~/.local/share/remmina "
            "--rustconn-output ~/.config/rustconn\n"
        ),
    )
    parser.add_argument(
        "--remmina-path",
        default=str(Path.home() / ".local/share/remmina"),
        metavar="DIR",
        help="Directory containing .remmina profile files "
             "(default: ~/.local/share/remmina/)",
    )
    parser.add_argument(
        "--rustconn-output",
        default=str(Path.home() / ".config/rustconn"),
        metavar="DIR",
        help="Directory for connections.toml and groups.toml output "
             "(default: ~/.config/rustconn/)",
    )
    parser.add_argument(
        "--keyring",
        default=None,
        metavar="FILE_OR_LABEL",
        help="Keyring file path or collection label. The type is auto-detected "
             "from the file's magic bytes: .keyring → GNOME Keyring, "
             ".kwl → KDE Wallet (kdewallet.salt and kdewallet_attributes.json "
             "must be in the same directory). A plain label string is passed "
             "directly to the GNOME backend. "
             "Default paths: GNOME ~/.local/share/keyrings/login.keyring, "
             "KDE ~/.local/share/kwalletd/kdewallet.kwl",
    )
    parser.add_argument(
        "--keepassxc-output",
        default="tests/keepassxc.csv",
        metavar="FILE",
        help="Path for the KeePassXC CSV output (default: tests/keepassxc.csv). "
             "Only written when --keyring is given.",
    )
    parser.add_argument(
        "--root-key",
        default="Connections",
        metavar="NAME",
        help="Root group name used in RustConn and KeePassXC hierarchy "
             "(default: Connections)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    remmina_path = Path(args.remmina_path)
    rustconn_dir = Path(args.rustconn_output)
    output_path = rustconn_dir / "connections.toml"
    groups_path = rustconn_dir / "groups.toml"
    keepassxc_path = Path(args.keepassxc_output)

    # Validate input directory
    if not remmina_path.is_dir():
        print(_err(f"Remmina profile directory not found: {remmina_path}"), file=sys.stderr)
        return 1

    # Ensure output directory exists
    rustconn_dir.mkdir(parents=True, exist_ok=True)

    # ── Parse .remmina files ────────────────────────────────────────────────
    print(_head("Remmina profiles"))
    print(_info(f"Source: {remmina_path}"))
    connections = parse_remmina_dir(remmina_path)
    if not connections:
        print(_warn("No supported .remmina profiles found."), file=sys.stderr)
    else:
        print(_ok(f"{len(connections)} connection(s) parsed."))

    # ── Resolve keyring (may prompt the user) ───────────────────────────────
    print()
    keyring_arg = _resolve_keyring(args.keyring)
    if keyring_arg is _CANCEL:
        return 1

    # ── Optionally read keyring (before writing TOML) ───────────────────────
    credentials: dict[int, str] = {}
    if keyring_arg:
        from keyring_reader import read_keyring, match_credentials

        print(_head("Keyring"))
        try:
            print(_info(f"Source: {keyring_arg}"))
            keyring_entries = read_keyring(keyring_arg)
            print(_ok(f"{len(keyring_entries)} keyring item(s) found."))

            credentials = match_credentials(connections, keyring_entries)
            print(_ok(f"{len(credentials)} credential(s) matched to connections."))
        except RuntimeError as exc:
            print(_err(f"Keyring error: {exc}"), file=sys.stderr)
            return 1

    # ── Write connections.toml ──────────────────────────────────────────────
    print(_head("RustConn export"))
    group_map = write_connections_toml(
        connections, output_path, credentials=credentials, root_key=args.root_key
    )
    print(_ok(f"connections.toml → {output_path}"))

    # ── Write groups.toml ──────────────────────────────────────────────────
    group_hierarchy = build_full_group_hierarchy(connections, args.root_key)
    write_groups_toml(group_hierarchy, groups_path)
    print(_ok(f"groups.toml → {groups_path}"))
    print(_info(f"{len(group_hierarchy)} group(s):"))
    for path, entry in sorted(group_hierarchy.items()):
        indent = "  " * (path.count("/") + (0 if path == args.root_key else 1))
        print(f"   {indent}{_dim(entry['id'])}  {entry['name']}")

    # Per-connection summary
    for i, conn in enumerate(connections):
        source = "vault" if i in credentials else "none"
        source_tag = (
            f"{_GREEN}vault{_RESET}" if source == "vault" else _dim("none")
        )
        proto = conn["protocol"].upper()
        print(
            f"   {_dim('·')} {conn['name']:{30}}  "
            f"{_CYAN}{proto:3}{_RESET}  "
            f"{conn['host']}:{conn['port']}  "
            f"pw={source_tag}"
        )

    # ── Write KeePassXC CSV ─────────────────────────────────────────────────
    if keyring_arg:
        print(_head("KeePassXC export"))
        keepassxc_path.parent.mkdir(parents=True, exist_ok=True)
        count = write_keepassxc_csv(
            connections, credentials, keepassxc_path, root_key=args.root_key
        )
        print(_ok(f"keepassxc.csv → {keepassxc_path}  ({count} entries)"))
        print(_warn("CSV contains plaintext passwords — delete after importing into KeePassXC."))

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
