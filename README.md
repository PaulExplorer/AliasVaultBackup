# aliasvault-backup (`avb`)

[![tests](https://github.com/PaulExplorer/AliasVaultBackup/actions/workflows/tests.yml/badge.svg)](https://github.com/PaulExplorer/AliasVaultBackup/actions/workflows/tests.yml)

Unofficial, independent backup tool for [AliasVault](https://aliasvault.com)
vaults. It logs in to the official hosted service (`app.aliasvault.com`) with
your master password, downloads the encrypted vault, and writes:

- a standard **`.avex`** export that any AliasVault client can import, and
- an optional **`.avbak`** raw snapshot containing the encrypted API frames and
  the encrypted account key chain.

The point is recoverability: you keep a copy of your data even if AliasVault
disappears, has an outage, or corrupts a server-side revision. Everything can
be decrypted and exported offline with this tool.

> This project is not affiliated with or endorsed by AliasVault.
> It is licensed AGPL-3.0-or-later.

## Requirements

- Python 3.11 or newer
- [`uv`](https://docs.astral.sh/uv/)
- An AliasVault Cloud account on the official hosted instance

The tool talks to AliasVault's v2 HTTP API directly. It does not use a browser
and does not need Docker, Node.js, or the AliasVault desktop app.

## Install

From GitHub:

```bash
uv tool install git+https://github.com/PaulExplorer/AliasVaultBackup
avb --version
```

From a local clone:

```bash
git clone https://github.com/PaulExplorer/AliasVaultBackup
cd AliasVaultBackup
uv tool install .
avb --version
```

For development:

```bash
uv sync --extra dev
uv run avb --help
uv run pytest
```

## Quick start

Log in once. `avb` asks for the master password, stores the refresh token, and
caches the vault keys:

```bash
avb login --username you@example.com --store-password
```

`--store-password` is optional. Without it, the master password is never
written to disk, but unattended backups need `ALIASVAULT_PASSWORD` or another
interactive login. See [Secret storage](#secret-storage).

Choose an export-password policy. The default is to encrypt `.avex` with the
master password. To use a separate random password instead:

```bash
avb login \
  --username you@example.com \
  --store-password \
  --generate-export-password
```

`--generate-export-password` prints the new password once and stores it in the
private secrets file. Keep a copy somewhere safe; without it, the `.avex` file
cannot be opened.

Run a backup:

```bash
avb backup
```

By default this writes both files to `~/AliasVaultBackups`, verifies the
`.avex` by decrypting it again, verifies the raw snapshot structurally (and
decrypts every manifest and blob when a master password or cached key is
available), and keeps the last 30 files of each type.

Useful commands:

```bash
avb status                 # configuration, session, recent backups
avb paths                  # config, secrets, and backup locations
avb backup --dry-run       # fetch and decrypt, but write nothing
avb backup --mode avex     # only the portable export
avb backup --mode raw      # only the encrypted raw snapshot
avb verify FILE            # verify an .avex or an .avbak
avb decrypt FILE -o DIR    # extract a decrypted .avex
avb prune --keep 14        # apply retention manually
```

`avb backup --help` and the other subcommands list every option.

## The two formats

### `.avex` — portable encrypted export

The `.avex` format is AliasVault's own encrypted export container. Its payload
is an unencrypted **`.avux`** ZIP containing:

```
manifest.json
attachments/<item-id>_<attachment-id>_<filename>
logos/<source>_<logo-id>.png
```

`manifest.json` contains items, field values, field histories, folders, tags,
field definitions, TOTP codes, passkeys, attachments, and logos. Passwords are
plaintext inside the `.avux` ZIP; the outer `.avex` layer protects the whole
ZIP with AES-256-GCM and an Argon2id-derived key.

The `.avex` file can be imported through the normal AliasVault import flow
(AliasVault → Import → AliasVault export). To recover without any AliasVault
software:

```bash
avb decrypt ~/AliasVaultBackups/your-vault.avex -o recovered/
```

That writes `manifest.json` plus all attachment and logo files. Use
`--avux recovered.avux` if you want the ZIP instead of an extracted directory.
`--manifest` and `--list-items` inspect the file without extracting anything
unless you also pass `-o` or `--avux`.

If the export password is the master password (the default), this is enough:

```bash
ALIASVAULT_PASSWORD='...' avb decrypt FILE.avex -o recovered/
```

### `.avbak` — raw encrypted snapshot

The raw snapshot is a ZIP containing the exact encrypted frames the server
served:

```
meta.json
unlock-method.json     # encrypted account key chain
vault.frame            # encrypted manifests and buckets
blobs/<manifest-id>.frame
RECOVERY.txt
```

It is zero-knowledge in the sense that it contains no plaintext passwords, but
it also contains the encrypted vault keys. Keep it as private as the master
password.

`meta.json` records the server URL, username, storage format, manifest IDs, and
snapshot time. The `.frame` files use the same binary framing as the AliasVault
API: a 4-byte big-endian JSON-header length, the JSON header, then the
ciphertexts referenced by the header.

To turn a raw snapshot into a portable `.avex` offline:

```bash
avb export ~/AliasVaultBackups/your-vault.avbak -o recovered.avex
```

That command asks for the master password. It does not contact the server.
Then decrypt the result as described above. To verify a raw snapshot and
decrypt every manifest and blob:

```bash
avb verify ~/AliasVaultBackups/your-vault.avbak --with-password
```

`.avbak` is the better disaster-recovery artifact if you want to keep the
option of re-exporting later: it preserves the encrypted key hierarchy and the
per-manifest blob addresses, not just the final plaintext export.

If the account currently exposes no password unlock method (for example a
legacy `sqlite-blob` account), `--mode raw` still writes the encrypted snapshot
and verifies it structurally. Offline `.avex` conversion needs the unlock
method and is not possible until the account provides one.

## What gets backed up

- Personal vault items, field values, and field histories
- Folders, tags, and item-tag links
- Custom field definitions
- TOTP secrets
- Passkeys (including credential IDs, PRF keys, and additional data)
- Attachments and custom logos
- Shared vaults, when your account has grant keys for them

Deleted rows are omitted from `.avex`, matching the official exporter. The raw
snapshot keeps the full server state.

The legacy `sqlite-blob` storage format is recognised but not converted. A raw
snapshot of it is still written in `raw` mode; open the current AliasVault app
once to migrate the account to the manifest format, then run a normal backup.

## Secret storage

By default, private state lives in:

```
~/.config/aliasvault-backup/config.toml
~/.config/aliasvault-backup/secrets.json   # mode 0600
```

`secrets.json` can contain:

- the access and refresh tokens,
- the optional master password (`--store-password`),
- the optional separate `.avex` export password,
- the optional TOTP secret,
- cached per-manifest vault encryption keys (VEKs).

**The secrets file is sensitive.** A cached VEK can decrypt the corresponding
vault, and the refresh token lets someone download the encrypted data. Treat
`secrets.json` like the master password itself: full-disk encryption, mode
`0600`, and a private account. `avb` tightens permissions automatically if it
finds the file readable by other users.

To remove individual items:

```bash
avb forget --tokens
avb forget --password
avb forget --export-password
avb forget --veks
avb forget --all          # delete the whole secrets file
```

`avb show export-password` prints the stored separate export password.
`avb show master-password --reveal` prints the stored master password.

There is no OS-keyring integration yet. For unattended runs, environment
variables are often the cleanest option:

```bash
export ALIASVAULT_PASSWORD='...'
export ALIASVAULT_EXPORT_PASSWORD='...'
avb backup
```

Put those in a mode-`0600` environment file rather than in a shell history or a
world-readable unit file.

## Configuration

`~/.config/aliasvault-backup/config.toml`:

```toml
# Official hosted instance. Do not change this for app.aliasvault.com.
api_url = "https://app.aliasvault.com/api"
username = "you@example.com"
backup_dir = "~/AliasVaultBackups"

# avex, raw, or both
mode = "both"

# Keep the newest N of each type. 0 disables pruning.
keep = 30

# Ask the server for a longer refresh-token lifetime.
remember_me = true

# Store the master password in secrets.json. Off by default.
store_password = false

# master | stored | env | prompt
export_password_source = "master"
```

`avb login` writes this file. You can also edit it by hand.

Selected environment variables:

| Variable | Meaning |
| --- | --- |
| `ALIASVAULT_PASSWORD` | Master password for unattended runs |
| `ALIASVAULT_EXPORT_PASSWORD` | Separate `.avex` password (`export_password_source = "env"`) |
| `AVB_CONFIG_DIR` | Override the configuration directory |
| `AVB_SECRETS_FILE` | Override the secrets file path |
| `AVB_BACKUP_DIR` | Override the backup directory |

## Automation

The tool is designed to be invoked by cron or systemd. It exits non-zero on
failure and prints a concise summary; use `--json` for machine-readable output.

### systemd user timer

Create `~/.config/aliasvault-backup/avb.env` with mode `0600`:

```bash
ALIASVAULT_PASSWORD='your-master-password'
# Optional, if export_password_source = "env":
# ALIASVAULT_EXPORT_PASSWORD='your-export-password'
```

Quote values that contain spaces or shell metacharacters. systemd also reads
single-quoted values in an `EnvironmentFile`.

`~/.config/systemd/user/avb.service`:

```ini
[Unit]
Description=AliasVault backup
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=%h/.config/aliasvault-backup/avb.env
ExecStart=%h/.local/bin/avb backup
UMask=0077
Nice=10
```

`~/.config/systemd/user/avb.timer`:

```ini
[Unit]
Description=Run the AliasVault backup daily

[Timer]
OnCalendar=*-*-* 03:17:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now avb.timer
systemctl --user list-timers avb.timer
journalctl --user -u avb.service -n 50
```

If `avb` is installed system-wide, use `/usr/local/bin/avb` and a system unit
with `User=your-user` instead.

### cron

```cron
17 3 * * * umask 077; set -a; . "$HOME/.config/aliasvault-backup/avb.env"; set +a; flock -n "$HOME/.local/state/avb.lock" "$HOME/.local/bin/avb" backup >> "$HOME/.local/state/avb.log" 2>&1
```

Create `~/.local/state` first if needed. `flock` prevents overlapping runs.

The backup runs fine on a different machine than the one you use AliasVault
on, as long as that machine can reach `https://app.aliasvault.com` and has the
master password (or a valid stored session and cached VEK). The client header
sent to the server is `avb-<version>`; the server does not need a browser
fingerprint.

## Recovery checklist

1. Keep at least one `.avbak` and one `.avex` in a second location.
2. Keep the master password in a password manager or offline safe.
3. If you use a separate `.avex` password, keep that too.
4. Test recovery now: `avb verify FILE --with-password` for `.avbak`, and
   `avb decrypt FILE.avex -o DIR` for `.avex`.
5. If AliasVault is gone, use `avb export` and `avb decrypt`; the source code
   is AGPL and does not depend on AliasVault libraries or servers for
   decryption.
6. If you need to move to another password manager, the decrypted
   `manifest.json` and attachment files are readable without AliasVault. The
   `.avux` ZIP and `manifest.json` field names are documented in
   [`docs/FORMAT.md`](docs/FORMAT.md).

## Security notes

- `.avex` and `.avbak` are encrypted, but decrypted output is not. `avb
  decrypt` creates a directory with mode `0700` and files with mode `0600`; do
  not sync that directory to an untrusted location.
- The default `.avex` password is the master password. A separate export
  password limits the blast radius if one password leaks, at the cost of
  having another secret to keep.
- The raw snapshot preserves the key chain. If an attacker has both the
  snapshot and the master password, they have the vault. If they have the
  secrets file and its cached VEKs, they may have the vault without the master
  password.
- TLS certificate verification is enabled. `api_url` is restricted to
  `https://`, except for a localhost test server.
- No telemetry, analytics, or third-party network calls are made beyond the
  configured AliasVault API.
- This is a backup tool, not an audit of AliasVault's cryptography. The format
  implementation follows AliasVault's AGPL Rust/TypeScript source and is tested
  against an official `.avex` fixture.

## Limitations

- Targets the official `app.aliasvault.com` v2 API. A future server change can
  break login or snapshot download; keep the raw snapshots you already have.
- Shared vaults are implemented but not exercised against a live shared vault
  in this repository's tests.
- Two-factor authentication is supported through `--totp-secret`,
  `--totp-code`, and `--recovery-code`, although the common no-2FA setup does
  not need it.
- The legacy `sqlite-blob` format is raw-only.
- Restoring data back into a server is out of scope. Use the AliasVault app to
  import the `.avex` file.

## Development

```bash
uv sync --extra dev
uv run pytest
uv run avb --help

uvx ruff format src tests
uvx ruff check src tests
uv run --with pyright pyright src/aliasvault_backup
```

GitHub Actions runs the test suite on Python 3.11, 3.12, and 3.13. Ruff and
Pyright run as non-blocking checks, so style issues are reported without
rejecting a pull request.

The tests cover:

- fixed SRP-6a vectors from AliasVault's implementation,
- Argon2id/HKDF/AES-GCM primitives and RFC 5869 HKDF,
- decryption of the official `official-0.28.0.avex` fixture,
- `.avux` building from synthetic manifests,
- a full offline `.avbak` → `.avex` → decrypt round trip,
- a local fake API server that exercises login, SRP validation, refresh, vault
  download, blob download, CLI backup, decryption, and verification.

The official fixture is AGPL-3.0-or-later and is used only for compatibility
testing; see `tests/fixtures/README.md`.
