# Remmina to RustConn

Export [Remmina](https://remmina.org/) connection profiles to [RustConn](https://github.com/totoshko88/RustConn) (`connections.toml`) and optionally extract credentials from a **GNOME Keyring** or **KDE Wallet (KWallet)** into a [KeePassXC](https://keepassxc.org/)-importable CSV.

## Features

- Converts SSH, RDP, and VNC Remmina profiles to the RustConn TOML schema
- Preserves group hierarchy (e.g. `SSH - SERVER/PROXMOX`) in both RustConn and KeePassXC
- Extracts credentials from a **GNOME Keyring** or **KDE Wallet** via the D-Bus / SecretService API — auto-detected from the file type
- Exports a KeePassXC CSV ready for import (used as RustConn's authentication backend)
- Modular codebase — each concern is a separate Python module

## Requirements

- Python 3.10+
- A running keyring daemon — only needed for credential export:
  - **GNOME**: `gnome-keyring-daemon` (standard on GNOME desktops)
  - **KDE**: `kwalletd5` or `kwalletd6` (standard on KDE Plasma desktops)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python run.py [options]
```

| Argument | Description | Default |
|---|---|---|
| `--remmina-path DIR` | Directory containing `.remmina` profile files | `~/.local/share/remmina/` |
| `--rustconn-output DIR` | Directory for `connections.toml` and `groups.toml` output | `~/.config/rustconn/` |
| `--keyring FILE_OR_LABEL_OR_DIR` | Keyring file path, directory to scan for a keyring file, or GNOME collection label — type auto-detected from file magic bytes | *(optional)* |
| `--keepassxc-output FILE` | Path for the KeePassXC CSV output | `tests/keepassxc.csv` |
| `--root-key NAME` | Root group name used in RustConn and KeePassXC hierarchy | `Connections` |

### Examples

```bash
# Convert reference profiles only (no credentials)
python run.py --remmina-path references/Remmina --rustconn-output tests

# GNOME — extract credentials from a keyring binary file
python run.py --remmina-path references/Remmina --rustconn-output tests \
  --keyring ~/.local/share/keyrings/login.keyring

# KDE — extract credentials from a KWallet file
python run.py --remmina-path references/Remmina --rustconn-output tests \
  --keyring ~/.local/share/kwalletd/kdewallet.kwl

# KDE — pass the wallet directory; the .kwl file is auto-detected inside it
python run.py --remmina-path references/Remmina --rustconn-output tests \
  --keyring ~/.local/share/kwalletd

# Production use — read live profiles and export to custom paths
python run.py \
  --remmina-path ~/.local/share/remmina \
  --rustconn-output ~/.config/rustconn \
  --keyring ~/.local/share/keyrings/login.keyring \
  --keepassxc-output ~/Desktop/keepassxc_import.csv \
  --root-key MyConnections
```

> **Warning:** The KeePassXC CSV contains plaintext passwords. Delete it after importing into KeePassXC.

### Keyring auto-detection behaviour

When `--keyring` is omitted, the tool probes the default locations and interacts with the user before proceeding:

| Scenario | Prompt shown | Outcome |
|---|---|---|
| `--keyring` explicitly provided | *(none)* | Proceeds directly with credential export |
| No `--keyring`, default GNOME/KDE keyring found | "Detected … keyring at default path. Use it? [y/n]" | `y` → uses it and exports credentials; `n` → exports connections only |
| No `--keyring`, no default keyring found | "Export Remmina connections without credentials? [y/n]" | `y` → exports connections only; `n` → export cancelled |

Default paths probed (in order):
- **GNOME**: `~/.local/share/keyrings/login.keyring`
- **KDE**: `~/.local/share/kwalletd/kdewallet.kwl`

## KeePassXC & RustConn Integration

After running the export, two manual steps are required before RustConn can authenticate connections.

### 1 — Import the CSV into KeePassXC

Open KeePassXC and import the generated CSV into a **new or existing vault**:

1. Go to **Database → Import → KeePassXC CSV…**
2. Select the generated `keepassxc_import.csv` file.
3. Map the CSV columns if prompted (Title, Username, Password, Group, URL).
4. Save the database.

> **Delete the CSV file immediately after importing** — it contains plaintext passwords.

### 2 — Configure RustConn to use the KeePassXC vault

RustConn retrieves credentials at runtime via the KeePassXC secret service integration. You must point it to the correct vault in its **Secret Settings**:

1. Open RustConn → **Settings → Secrets**.
2. Set the secret backend to **KeePassXC**.
3. Select the `.kdbx` vault file that you imported into.

### KeePassXC ↔ RustConn group path alignment

RustConn looks up credentials using the group path defined in `connections.toml`. The KeePassXC tree must include a parent folder that corresponds to the RustConn root (by default `Connections`) so paths align correctly.

| Layer | Example path |
|---|---|
| KeePassXC | `Root / Rust / Connections / SSH - SERVER / PROXMOX / VM 100` |
| RustConn | `Connections / SSH - SERVER / PROXMOX / VM 100` |

The `--root-key` argument (default: `Connections`) controls the root group name written into both `connections.toml` and the KeePassXC CSV. Whatever folder sits above that root in KeePassXC (e.g. `Rust`) is irrelevant to RustConn — only the `Connections/…` sub-tree must match.

## Group Hierarchy

Remmina groups with sub-levels (separated by `/`) are replicated in both outputs.

**Example** — a Remmina connection in group `SSH - SERVER/PROXMOX` named `VM 100 - TEST (ssh)`:

| Output | Path |
|--------|------|
| RustConn | `Connections/SSH - SERVER/PROXMOX` → `VM 100 - TEST (ssh)` |
| KeePassXC | `RustConn/Connections/SSH - SERVER/PROXMOX` → `VM 100 - TEST (ssh)` |

The root path prefix (`Connections` by default) can be changed with `--root-key`.

## Output Files

- **`tests/connections.toml`**: `[[connections]]` entries matching RustConn's schema
- **`tests/groups.toml`**: `[[groups]]` entries with full parent/child hierarchy
- **`tests/keepassxc.csv`**: KeePassXC import CSV with full group paths

## Project Structure

```
run.py                  # CLI entry point
remmina_parser.py       # Parse .remmina INI files
rustconn_writer.py      # Serialise to RustConn TOML format (connections + groups)
keyring_reader.py       # Keyring dispatcher — auto-detects GNOME or KDE and delegates
_keyring_gnome.py       # GNOME Keyring reader (secretstorage / D-Bus)
_keyring_kde.py         # KDE Wallet reader (kwalletd SecretService / D-Bus)
keepassxc_exporter.py   # Write KeePassXC-importable CSV
requirements.txt        # Python dependencies
references/             # Read-only reference material
  Remmina/              # Sample .remmina profiles
  connections.toml      # Reference RustConn connections schema
  groups.toml           # Reference RustConn groups schema
  keyrings/
    gnome/
      login.keyring     # Sample GNOME keyring binary
    kde/
      kdewallet.kwl     # Sample KDE wallet binary
      kdewallet_attributes.json  # KDE attribute index (optional companion file)
  keyring-export.py     # Original keyring export reference script
tests/                  # Generated output (gitignored)
  connections.toml
  groups.toml
  keepassxc.csv
```

### KDE wallet companion file

When using a KDE wallet, an optional companion file may be placed **in the same directory** as the `.kwl` file:

| File | Purpose |
|---|---|
| `{stem}_attributes.json` | Attribute index exported from kwalletd — provides `xdg:schema` and `filename` attributes for items not fully exposed through the SecretService layer |

The file is loaded on a best-effort basis. If it is absent or cannot be parsed the tool continues reading credentials from D-Bus alone, with no error.

### Passing a directory to `--keyring`

Instead of a specific file path, `--keyring` also accepts a **directory**. The tool scans the directory for the first recognised keyring file (GNOME `.keyring` files are preferred over KDE `.kwl` files when both are present) and uses it automatically:

```bash
python run.py --keyring ~/.local/share/keyrings
python run.py --keyring ~/.local/share/kwalletd
```
