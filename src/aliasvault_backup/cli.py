"""Command line interface for aliasvault-backup."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__, backup, crypto
from . import totp as totp_module
from .api import ApiClient
from .config import load_config, save_config
from .errors import AvbError, ConfigError, CryptoError
from .secrets import Secrets, SecretStore
from .util import atomic_write, ensure_private_dir, human_size, jwt_expiry

if TYPE_CHECKING:
    from .config import AppConfig


def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--config", default=argparse.SUPPRESS, help="Path to config.toml"
    )
    parser.add_argument(
        "--secrets-file",
        default=argparse.SUPPRESS,
        help="Path to secrets.json (tokens, optional passwords, VEK cache)",
    )
    parser.add_argument("--debug", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument("-q", "--quiet", action="store_true", default=argparse.SUPPRESS)
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=argparse.SUPPRESS
    )
    return parser


def _runtime(args: argparse.Namespace) -> tuple[AppConfig, SecretStore, Secrets]:
    config_path = (
        Path(args.config).expanduser() if getattr(args, "config", None) else None
    )
    config = load_config(config_path)
    secrets_override = getattr(args, "secrets_file", None)
    if secrets_override:
        config.secrets_path = Path(secrets_override).expanduser()
    store = SecretStore(config.secrets_path)
    secrets = store.load()
    if secrets.was_insecure and not getattr(args, "quiet", False):
        print(
            f"warning: tightened permissions on {config.secrets_path} (it was readable by others)",
            file=sys.stderr,
        )
    return config, store, secrets


def _log(verbose: bool, message: str) -> None:
    if verbose:
        print(message, file=sys.stderr)


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def _backup_human(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    if summary.get("avex"):
        lines.append(f"Wrote .avex: {summary['avex']}")
    if summary.get("raw"):
        lines.append(f"Wrote raw snapshot: {summary['raw']}")
    if summary.get("avexVerification"):
        verification = summary["avexVerification"]
        lines.append(
            f"Verified .avex: {verification.get('items', 0)} items, "
            f"{verification.get('attachments', 0)} attachments, {human_size(verification.get('size', 0))}"
        )
    if summary.get("rawVerification"):
        verification = summary["rawVerification"]
        detail = f"{verification.get('manifests', 0)} manifests, {verification.get('blobFrames', 0)} blob frames"
        if verification.get("verified"):
            detail += f", {verification.get('items', 0)} items"
        lines.append(f"Verified raw snapshot: {detail}")
    if summary.get("pruned"):
        lines.append(f"Pruned {len(summary['pruned'])} old backup(s)")
    if summary.get("wouldWrite"):
        lines.append("Dry run; no files were written:")
        for kind, path in summary["wouldWrite"].items():
            if path:
                lines.append(f"  {kind}: {path}")
    return "\n".join(lines) if lines else "Backup completed."


def _password_candidates(
    args: argparse.Namespace,
    secrets: Secrets,
) -> list[str]:
    """Return plausible passwords for an .avex file, most specific first.

    An old backup may have been encrypted with the master password while a
    newer one uses the stored export password, so callers try each in turn.
    The environment always wins, then the stored export password, then the
    stored master password.
    """

    values: list[str] = []

    def add(value: str | None) -> None:
        if value and value not in values:
            values.append(value)

    env_name = getattr(args, "password_env", None) or backup.EXPORT_PASSWORD_ENV
    add(os.environ.get(env_name))
    if env_name != backup.MASTER_PASSWORD_ENV:
        add(os.environ.get(backup.MASTER_PASSWORD_ENV))
    add(secrets.export_password)
    add(secrets.master_password)
    return values


def _decrypt_avex_bytes(
    args: argparse.Namespace,
    secrets: Secrets,
    data: bytes,
    *,
    prompt: bool = True,
) -> bytes:
    # Validate the container before treating a failure as a wrong password.
    header, _payload = crypto.parse_avex(data)
    crypto.avex_params(header)
    candidates = _password_candidates(args, secrets)
    last_error: CryptoError | None = None
    for password in candidates:
        try:
            return crypto.decrypt_avex(data, password)
        except CryptoError as exc:
            last_error = exc
    if prompt and sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        if password:
            try:
                return crypto.decrypt_avex(data, password)
            except CryptoError as exc:
                last_error = exc
    raise ConfigError(
        "Could not decrypt the .avex file. Set "
        f"{getattr(args, 'password_env', backup.EXPORT_PASSWORD_ENV)} or "
        f"{backup.MASTER_PASSWORD_ENV}, or run interactively."
    ) from last_error


def cmd_login(args: argparse.Namespace) -> int:
    config, store, secrets = _runtime(args)
    if getattr(args, "url", None):
        config.api_url = str(args.url).rstrip("/")
    if getattr(args, "username", None):
        config.username = str(args.username).strip().lower()
    if not config.username:
        if not sys.stdin.isatty():
            raise ConfigError("No username configured; pass --username")
        config.username = input("AliasVault email address: ").strip().lower()
    if getattr(args, "backup_dir", None):
        config.backup_dir = Path(args.backup_dir).expanduser()
    if getattr(args, "mode", None):
        config.mode = args.mode
    if getattr(args, "keep", None) is not None:
        config.keep = args.keep
    if getattr(args, "remember_me", None) is not None:
        config.remember_me = bool(args.remember_me)
    if getattr(args, "export_password_source", None):
        config.export_password_source = args.export_password_source
    config.validate()
    ensure_private_dir(config.backup_dir)

    password = backup.required_master_password(
        secrets,
        prompt=True,
        env_var=getattr(args, "password_env", backup.MASTER_PASSWORD_ENV),
    )
    totp_secret = getattr(args, "totp_secret", None) or secrets.totp_secret
    client = ApiClient(config.api_url)
    try:
        result = client.login(
            config.username,
            password,
            remember_me=config.remember_me,
            totp_secret=totp_secret,
            totp_code=getattr(args, "totp_code", None),
            recovery_code=getattr(args, "recovery_code", None),
        )
        secrets.tokens = dict(result.tokens)
        if totp_secret:
            secrets.totp_secret = totp_secret
        store.save(secrets)

        store_password = getattr(args, "store_password", None)
        if store_password is None:
            store_password = config.store_password
        config.store_password = bool(store_password)
        if store_password:
            secrets.master_password = password
        else:
            secrets.master_password = None
        store.save(secrets)

        generated_export = False
        if getattr(args, "generate_export_password", False):
            secrets.export_password = backup.generate_export_password()
            config.export_password_source = "stored"
            store.save(secrets)
            generated_export = True
            print("Generated .avex export password:", file=sys.stderr)
            print(secrets.export_password, file=sys.stderr)
            print(
                "Store it somewhere safe; it is also in the secrets file.",
                file=sys.stderr,
            )

        cache_info: dict[str, Any] | None = None
        cache_error: str | None = None
        try:
            cache_info = backup.cache_veks(client, secrets, password=password)
        except AvbError as exc:
            cache_error = str(exc)
        # A 401 retry during key caching may rotate the token pair. Persist it
        # even when caching fails, so the stored refresh token stays usable.
        if client.tokens:
            secrets.tokens = dict(client.tokens)
        store.save(secrets)
        save_config(config)

        expiry = jwt_expiry(secrets.tokens.get("token")) if secrets.tokens else None
        summary = {
            "username": config.username,
            "apiUrl": config.api_url,
            "storePassword": config.store_password,
            "exportPasswordSource": config.export_password_source,
            "exportPasswordGenerated": generated_export,
            "cache": cache_info,
            "cacheWarning": cache_error,
            "accessTokenExpires": expiry.isoformat() if expiry else None,
        }
        if getattr(args, "json", False):
            _print_json(summary)
            return 0

        print(f"Logged in as {config.username} at {config.api_url}.")
        if cache_info is not None:
            if cache_info.get("legacy"):
                print(
                    "This account still uses the legacy sqlite-blob format; "
                    "only raw .avbak backups are available until it is migrated."
                )
            else:
                print(
                    f"Opened {cache_info.get('manifests', 0)} manifest(s), "
                    f"{cache_info.get('items', 0)} item(s); cached the vault keys."
                )
        else:
            print(
                f"warning: logged in but could not cache vault keys: {cache_error}",
                file=sys.stderr,
            )
        if expiry:
            print(
                f"Access token expires at {expiry.isoformat()} (refresh token is stored)."
            )
        return 0
    finally:
        client.close()


def cmd_backup(args: argparse.Namespace) -> int:
    config, store, secrets = _runtime(args)
    config.validate()
    master_password = backup.optional_master_password(
        secrets,
        prompt=False,
        env_var=getattr(args, "password_env", backup.MASTER_PASSWORD_ENV),
    )
    summary = backup.run_backup(
        config,
        secrets,
        store,
        mode=getattr(args, "mode", None),
        output_dir=Path(args.out).expanduser() if getattr(args, "out", None) else None,
        keep=getattr(args, "keep", None),
        verify=not getattr(args, "no_verify", False),
        dry_run=bool(getattr(args, "dry_run", False)),
        master_password=master_password,
        master_password_env=getattr(args, "password_env", backup.MASTER_PASSWORD_ENV),
        export_password_env=getattr(
            args, "export_password_env", backup.EXPORT_PASSWORD_ENV
        ),
        totp_code=getattr(args, "totp_code", None),
        recovery_code=getattr(args, "recovery_code", None),
        log=lambda message: _log(bool(getattr(args, "verbose", False)), message),
    )
    if getattr(args, "json", False):
        _print_json(summary)
    else:
        print(_backup_human(summary))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    config, store, secrets = _runtime(args)
    raw_path = Path(args.input).expanduser()
    if not raw_path.exists():
        raise ConfigError(f"Raw backup not found: {raw_path}")
    output_path = (
        Path(args.output).expanduser()
        if getattr(args, "output", None)
        else raw_path.with_suffix(".avex")
    )
    if output_path.exists() and not getattr(args, "force", False):
        raise ConfigError(f"{output_path} already exists; use --force to overwrite it")
    if output_path.resolve() == raw_path.resolve():
        raise ConfigError(
            "The output .avex path must differ from the input .avbak path"
        )
    master_password = backup.required_master_password(
        secrets,
        prompt=True,
        env_var=getattr(args, "password_env", backup.MASTER_PASSWORD_ENV),
    )
    export_password, generated = backup.export_password_for(
        config,
        secrets,
        master_password=master_password,
        prompt=True,
        generate_if_missing=True,
        env_var=getattr(args, "export_password_env", backup.EXPORT_PASSWORD_ENV),
    )
    assert export_password is not None
    if generated:
        store.save(secrets)
        print("Generated .avex export password:", file=sys.stderr)
        print(export_password, file=sys.stderr)
    summary = backup.export_raw_to_avex(
        raw_path,
        output_path,
        password=master_password,
        export_password=export_password,
        verify=not getattr(args, "no_verify", False),
    )
    if getattr(args, "json", False):
        _print_json(summary)
    else:
        print(
            f"Wrote {summary['output']} ({summary['items']} items, {human_size(summary['size'])})"
        )
        if summary.get("verification"):
            print(
                f"Verified: {summary['verification']['items']} items, "
                f"{summary['verification']['attachments']} attachments"
            )
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    _config, _store, secrets = _runtime(args)
    input_path = Path(args.input).expanduser()
    if not input_path.exists():
        raise ConfigError(f".avex file not found: {input_path}")
    avux_bytes = _decrypt_avex_bytes(args, secrets, input_path.read_bytes())

    inspect_only = bool(
        (getattr(args, "manifest", False) or getattr(args, "list_items", False))
        and not getattr(args, "avux", None)
        and not getattr(args, "output_dir", None)
    )

    if inspect_only:
        result = {"size": len(avux_bytes)}
    elif getattr(args, "avux", None):
        avux_path = Path(args.avux).expanduser()
        if avux_path.resolve() == input_path.resolve():
            raise ConfigError("The .avux output must differ from the input .avex file")
        if avux_path.exists() and not getattr(args, "overwrite", False):
            raise ConfigError(
                f"{avux_path} already exists; use --overwrite to replace it"
            )
        atomic_write(avux_path, avux_bytes, mode=0o600)
        result = {"avux": str(avux_path), "size": len(avux_bytes)}
    else:
        destination = (
            Path(args.output_dir).expanduser()
            if getattr(args, "output_dir", None)
            else input_path.with_suffix("")
        )
        from . import avux as avux_module

        written = avux_module.extract_avux(
            avux_bytes,
            destination,
            overwrite=bool(getattr(args, "overwrite", False)),
        )
        result = {
            "destination": str(destination),
            "extracted": len(written),
            "size": len(avux_bytes),
        }

    if getattr(args, "manifest", False):
        from .avux import read_avux

        _print_json(read_avux(avux_bytes))
    elif getattr(args, "list_items", False):
        from .avux import list_items

        items = list_items(avux_bytes)
        if getattr(args, "json", False):
            _print_json(items)
        else:
            for item in items:
                usernames = ", ".join(item["usernames"]) if item["usernames"] else ""
                print(f"{item['name'] or '(unnamed)'}\t{item['type']}\t{usernames}")
    elif getattr(args, "json", False):
        _print_json(result)
    else:
        if result.get("avux"):
            print(
                f"Wrote unencrypted .avux: {result['avux']} ({human_size(result['size'])})"
            )
        else:
            print(f"Extracted to {result['destination']} ({result['extracted']} files)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    _config, _store, secrets = _runtime(args)
    path = Path(args.input).expanduser()
    if not path.exists():
        raise ConfigError(f"File not found: {path}")
    suffix = path.suffix.lower()
    if suffix == ".avbak":
        password = None
        if getattr(args, "with_password", False):
            password = backup.required_master_password(
                secrets,
                prompt=True,
                env_var=getattr(
                    args, "master_password_env", backup.MASTER_PASSWORD_ENV
                ),
            )
        summary = backup.verify_raw_file(path, password)
    else:
        data = path.read_bytes()
        avux_bytes = _decrypt_avex_bytes(args, secrets, data)
        summary = backup.verify_avux_bytes(avux_bytes, size=len(data))
    if getattr(args, "json", False):
        _print_json(summary)
    else:
        if suffix == ".avbak":
            print(
                f"{path}: raw snapshot, {summary.get('manifests', 0)} manifests, "
                f"{summary.get('blobFrames', 0)} blob frames, {human_size(summary.get('size', 0))}"
            )
            if summary.get("verified"):
                print(
                    f"Decrypted: {summary.get('items', 0)} items, {summary.get('blobs', 0)} blobs"
                )
        else:
            print(
                f"{path}: valid .avex, {summary.get('items', 0)} items, "
                f"{summary.get('attachments', 0)} attachments, {human_size(summary.get('size', 0))}"
            )
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    config, _store, _secrets = _runtime(args)
    directory = (
        Path(args.directory).expanduser()
        if getattr(args, "directory", None)
        else config.backup_dir
    )
    keep = args.keep if getattr(args, "keep", None) is not None else config.keep
    if keep < 0:
        raise ConfigError("keep must be zero or positive")
    removed = backup.prune_backups(
        directory, keep, dry_run=bool(getattr(args, "dry_run", False))
    )
    if getattr(args, "json", False):
        _print_json(
            {
                "removed": [str(path) for path in removed],
                "dryRun": bool(getattr(args, "dry_run", False)),
            }
        )
    else:
        for path in removed:
            print(
                ("would remove " if getattr(args, "dry_run", False) else "removed ")
                + str(path)
            )
        if not removed:
            print("Nothing to prune.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    config, _store, secrets = _runtime(args)
    backups: list[dict[str, Any]] = []
    if config.backup_dir.exists():
        files = [
            path
            for pattern in ("aliasvault-*.avex", "aliasvault-*.avbak")
            for path in config.backup_dir.glob(pattern)
            if path.is_file()
        ]
        files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        for path in files[:10]:
            backups.append(
                {
                    "path": str(path),
                    "size": path.stat().st_size,
                    "modified": path.stat().st_mtime,
                }
            )
    expiry = jwt_expiry(secrets.tokens.get("token") if secrets.tokens else None)
    status: dict[str, Any] = {
        "config": str(config.config_path),
        "secrets": str(config.secrets_path),
        "apiUrl": config.api_url,
        "username": config.username or None,
        "backupDir": str(config.backup_dir),
        "mode": config.mode,
        "keep": config.keep,
        "storePassword": config.store_password,
        "exportPasswordSource": config.export_password_source,
        "hasSession": secrets.has_tokens,
        "accessTokenExpires": expiry.isoformat() if expiry else None,
        "masterPasswordStored": bool(secrets.master_password),
        "exportPasswordStored": bool(secrets.export_password),
        "cachedVeks": len(secrets.veks),
        "recentBackups": backups,
    }
    if getattr(args, "json", False):
        _print_json(status)
    else:
        print(f"Config:        {status['config']}")
        print(f"Secrets:       {status['secrets']}")
        print(f"Server:        {status['apiUrl']}")
        print(f"Username:      {status['username'] or '(not configured)'}")
        print(f"Backup dir:    {status['backupDir']}")
        print(f"Mode:          {status['mode']} (keep {status['keep']})")
        print(f"Session:       {'stored' if status['hasSession'] else 'missing'}")
        if status["accessTokenExpires"]:
            print(f"Token expires: {status['accessTokenExpires']}")
        print(f"Master stored: {'yes' if status['masterPasswordStored'] else 'no'}")
        print(f"Export passwd: {status['exportPasswordSource']}")
        print(f"Cached VEKs:   {status['cachedVeks']}")
        if backups:
            print("Recent backups:")
            for item in backups:
                print(f"  {item['path']}  {human_size(item['size'])}")
        else:
            print("Recent backups: none")
    return 0


def cmd_paths(args: argparse.Namespace) -> int:
    config, _store, _secrets = _runtime(args)
    values = {
        "config": str(config.config_path),
        "secrets": str(config.secrets_path),
        "backups": str(config.backup_dir),
    }
    if getattr(args, "json", False):
        _print_json(values)
    else:
        for key, value in values.items():
            print(f"{key}: {value}")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    config, store, secrets = _runtime(args)
    all_values = bool(getattr(args, "all", False))
    if all_values:
        store.delete()
        print(f"Deleted {config.secrets_path}")
        return 0
    changed = False
    if getattr(args, "tokens", False):
        secrets.tokens = None
        changed = True
    if getattr(args, "password", False):
        secrets.master_password = None
        changed = True
    if getattr(args, "export_password", False):
        secrets.export_password = None
        changed = True
    if getattr(args, "veks", False):
        secrets.veks = {}
        changed = True
    if getattr(args, "totp", False):
        secrets.totp_secret = None
        changed = True
    if not changed:
        raise ConfigError(
            "Choose what to forget: --tokens, --password, --export-password, --veks, --totp, or --all"
        )
    store.save(secrets)
    print("Updated the secrets file.")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    _config, _store, secrets = _runtime(args)
    what = args.what
    if what == "export-password":
        if not secrets.export_password:
            raise ConfigError("No export password is stored")
        print(secrets.export_password)
    elif what == "totp":
        if not secrets.totp_secret:
            raise ConfigError("No TOTP secret is stored")
        print(totp_module.totp(secrets.totp_secret))
    elif what == "master-password":
        if not getattr(args, "reveal", False):
            raise ConfigError("Pass --reveal to print the stored master password")
        if not secrets.master_password:
            raise ConfigError("No master password is stored")
        print(secrets.master_password)
    else:
        raise ConfigError(f"Unknown value: {what}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="avb",
        description="Unofficial automatic backup tool for AliasVault vaults",
        parents=[common],
    )
    parser.add_argument(
        "--version", action="version", version=f"aliasvault-backup {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser(
        "login", parents=[common], help="Authenticate and store session tokens"
    )
    p.add_argument(
        "--url", help="API base URL (default: https://app.aliasvault.com/api)"
    )
    p.add_argument("--username", help="AliasVault email address")
    p.add_argument("--password-env", default=backup.MASTER_PASSWORD_ENV)
    p.add_argument("--store-password", dest="store_password", action="store_true")
    p.add_argument("--no-store-password", dest="store_password", action="store_false")
    p.set_defaults(store_password=None)
    p.add_argument("--totp-secret", help="Base32 TOTP secret for unattended 2FA")
    p.add_argument("--totp-code", help="One-time 2FA code")
    p.add_argument("--recovery-code", help="One-time 2FA recovery code")
    p.add_argument("--remember-me", dest="remember_me", action="store_true")
    p.add_argument("--no-remember-me", dest="remember_me", action="store_false")
    p.set_defaults(remember_me=None)
    p.add_argument("--backup-dir", help="Directory for backups")
    p.add_argument("--mode", choices=("avex", "raw", "both"))
    p.add_argument("--keep", type=int)
    p.add_argument(
        "--export-password-source", choices=("master", "stored", "env", "prompt")
    )
    p.add_argument("--generate-export-password", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("backup", parents=[common], help="Download and write a backup")
    p.add_argument("--mode", choices=("avex", "raw", "both"))
    p.add_argument("--out", help="Directory for this run's backups")
    p.add_argument("--keep", type=int)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--password-env", default=backup.MASTER_PASSWORD_ENV)
    p.add_argument("--export-password-env", default=backup.EXPORT_PASSWORD_ENV)
    p.add_argument("--totp-code")
    p.add_argument("--recovery-code")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser(
        "export",
        parents=[common],
        help="Convert a raw .avbak snapshot to .avex offline",
    )
    p.add_argument("input", help="Path to the .avbak file")
    p.add_argument("-o", "--output", help="Output .avex path")
    p.add_argument("--password-env", default=backup.MASTER_PASSWORD_ENV)
    p.add_argument("--export-password-env", default=backup.EXPORT_PASSWORD_ENV)
    p.add_argument("--no-verify", action="store_true")
    p.add_argument("--force", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser(
        "decrypt", parents=[common], help="Decrypt an .avex export offline"
    )
    p.add_argument("input", help="Path to the .avex file")
    p.add_argument(
        "-o",
        "--output-dir",
        help="Directory to extract manifest.json, attachments, and logos",
    )
    p.add_argument(
        "--avux",
        help="Write the decrypted .avux ZIP to this path instead of extracting",
    )
    p.add_argument("--password-env", default=backup.EXPORT_PASSWORD_ENV)
    p.add_argument("--overwrite", action="store_true")
    p.add_argument(
        "--manifest",
        action="store_true",
        help="Print the full manifest as JSON (sensitive)",
    )
    p.add_argument(
        "--list-items", action="store_true", help="List item names and usernames"
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("verify", parents=[common], help="Verify a backup file")
    p.add_argument("input", help="Path to an .avex or .avbak file")
    p.add_argument("--password-env", default=backup.EXPORT_PASSWORD_ENV)
    p.add_argument("--master-password-env", default=backup.MASTER_PASSWORD_ENV)
    p.add_argument(
        "--with-password", action="store_true", help="Also decrypt a raw snapshot"
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("prune", parents=[common], help="Apply the retention policy")
    p.add_argument(
        "--dir", dest="directory", help="Backup directory (default: configured)"
    )
    p.add_argument("--keep", type=int)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_prune)

    p = sub.add_parser(
        "status", parents=[common], help="Show configuration and recent backups"
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser(
        "paths", parents=[common], help="Print configuration file locations"
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_paths)

    p = sub.add_parser(
        "forget", parents=[common], help="Remove stored tokens, passwords, or keys"
    )
    p.add_argument("--all", action="store_true", help="Delete the entire secrets file")
    p.add_argument("--tokens", action="store_true")
    p.add_argument("--password", action="store_true")
    p.add_argument("--export-password", action="store_true")
    p.add_argument("--veks", action="store_true")
    p.add_argument("--totp", action="store_true")
    p.set_defaults(func=cmd_forget)

    p = sub.add_parser(
        "show", parents=[common], help="Print a stored secret (use with care)"
    )
    p.add_argument("what", choices=("export-password", "totp", "master-password"))
    p.add_argument("--reveal", action="store_true", help="Required for master-password")
    p.set_defaults(func=cmd_show)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AvbError as exc:
        print(f"avb: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("avb: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        if getattr(args, "debug", False):
            traceback.print_exc()
        else:
            print(f"avb: unexpected error: {exc}", file=sys.stderr)
            print("Run with --debug for a full traceback.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
