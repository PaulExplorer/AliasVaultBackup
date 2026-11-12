"""Backup orchestration, .avbak raw snapshots, and retention."""

from __future__ import annotations

import datetime as _dt
import getpass
import io
import json
import os
import secrets as _secrets
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__, avux, crypto, vault
from .api import ApiClient, LoginResult
from .config import AppConfig
from .errors import AuthError, ConfigError, CryptoError, UnsupportedVaultError
from .secrets import Secrets
from .util import (
    atomic_write,
    ensure_private_dir,
    now_iso,
    parse_frame,
    slugify,
)

RAW_FORMAT = "aliasvault-raw-backup"
RAW_VERSION = 1
EXPORT_PASSWORD_ENV = "ALIASVAULT_EXPORT_PASSWORD"
MASTER_PASSWORD_ENV = "ALIASVAULT_PASSWORD"


@dataclass
class RawBundle:
    path: Path
    meta: dict[str, Any]
    unlock_method: dict[str, Any] | None
    snapshot: vault.Snapshot
    blob_frames: dict[str, bytes]


# ---------------------------------------------------------------------------
# Password helpers


def generate_export_password() -> str:
    return _secrets.token_urlsafe(32)


def optional_master_password(
    secrets: Secrets,
    *,
    prompt: bool = False,
    env_var: str = MASTER_PASSWORD_ENV,
) -> str | None:
    value = os.environ.get(env_var)
    if value:
        return value
    if secrets.master_password:
        return secrets.master_password
    if prompt and sys.stdin.isatty():
        entered = getpass.getpass("AliasVault master password: ")
        return entered or None
    return None


def required_master_password(
    secrets: Secrets, *, prompt: bool = True, env_var: str = MASTER_PASSWORD_ENV
) -> str:
    value = optional_master_password(secrets, prompt=prompt, env_var=env_var)
    if not value:
        raise ConfigError(
            "The master password is required but was not provided. Set "
            f"{env_var}, use --store-password at login, or run interactively."
        )
    return value


def export_password_for(
    config: AppConfig,
    secrets: Secrets,
    *,
    master_password: str | None,
    prompt: bool = False,
    generate_if_missing: bool = True,
    env_var: str = EXPORT_PASSWORD_ENV,
) -> tuple[str | None, bool]:
    """Return ``(password, generated)`` for the .avex export."""
    source = config.export_password_source
    if source == "master":
        return master_password, False
    if source == "stored":
        if secrets.export_password:
            return secrets.export_password, False
        if not generate_if_missing:
            return None, False
        generated = generate_export_password()
        secrets.export_password = generated
        return generated, True
    if source == "env":
        value = os.environ.get(env_var)
        if not value:
            raise ConfigError(
                f"export_password_source is 'env' but {env_var} is not set"
            )
        return value, False
    if source == "prompt":
        if not prompt or not sys.stdin.isatty():
            raise ConfigError(
                "export_password_source is 'prompt' but no terminal is available. "
                "Use 'stored', 'env', or 'master' for unattended backups."
            )
        value = getpass.getpass("Export password for the .avex file: ")
        if not value:
            raise ConfigError("No export password was entered")
        return value, False
    raise ConfigError(f"Unknown export password source: {source}")


# ---------------------------------------------------------------------------
# Raw .avbak snapshots


def _safe_zip_name(name: str) -> str:
    return name.replace("\\", "_").replace("/", "_")


def write_raw_backup(
    path: Path,
    *,
    snapshot: vault.Snapshot,
    unlock_method: dict[str, Any] | None,
    blob_collection: vault.BlobCollection,
    config: AppConfig,
) -> None:
    manifest_ids = [str(item.get("manifestId", "")) for item in snapshot.manifests]
    meta = {
        "format": RAW_FORMAT,
        "version": RAW_VERSION,
        "createdAt": now_iso(),
        "toolVersion": __version__,
        "apiUrl": config.api_url,
        "username": config.username,
        "storageFormat": snapshot.storage_format,
        "personalManifestId": snapshot.personal_manifest_id,
        "manifestIds": manifest_ids,
        "blobFrames": sorted(blob_collection.frames),
    }
    recovery = (
        "AliasVault raw encrypted snapshot\n"
        "=================================\n\n"
        "This archive is zero-knowledge: it contains the encrypted vault frames\n"
        "exactly as the AliasVault server served them, plus your encrypted account\n"
        "key chain. It is not useful without your AliasVault master password.\n\n"
        "To turn it into a portable .avex export later:\n\n"
        "    avb export this-file.avbak -o recovered.avex\n\n"
        "Then decrypt it with:\n\n"
        "    avb decrypt recovered.avex -o recovered-vault\n\n"
        "Do not edit or extract the .frame files. Generated by "
        f"aliasvault-backup {__version__}.\n"
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("meta.json", json.dumps(meta, indent=2, ensure_ascii=False))
        archive.writestr(
            "unlock-method.json",
            json.dumps(unlock_method, indent=2, ensure_ascii=False)
            if unlock_method is not None
            else "null",
        )
        archive.writestr("vault.frame", snapshot.raw)
        for manifest_id, frame in blob_collection.frames.items():
            archive.writestr(f"blobs/{_safe_zip_name(manifest_id)}.frame", frame)
        archive.writestr("RECOVERY.txt", recovery)
    atomic_write(path, buffer.getvalue(), mode=0o600)


def read_raw_backup(path: Path) -> RawBundle:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if "meta.json" not in names or "vault.frame" not in names:
                raise CryptoError("This is not an aliasvault-backup raw snapshot")
            meta = json.loads(archive.read("meta.json"))
            if not isinstance(meta, dict) or meta.get("format") != RAW_FORMAT:
                raise CryptoError("Unknown raw snapshot format")
            version = meta.get("version")
            if not isinstance(version, int) or isinstance(version, bool) or version < 1:
                raise CryptoError("The raw snapshot has no valid format version")
            if version > RAW_VERSION:
                raise UnsupportedVaultError(
                    f"This raw snapshot uses format version {version}; this tool reads {RAW_VERSION}. "
                    "Update aliasvault-backup to open it."
                )
            unlock_method = (
                json.loads(archive.read("unlock-method.json"))
                if "unlock-method.json" in names
                else None
            )
            if unlock_method is not None and not isinstance(unlock_method, dict):
                unlock_method = None
            raw_snapshot = archive.read("vault.frame")
            blob_frames: dict[str, bytes] = {}
            for name in names:
                if name.startswith("blobs/") and name.endswith(".frame"):
                    manifest_id = name[len("blobs/") : -len(".frame")]
                    blob_frames[manifest_id] = archive.read(name)
    except zipfile.BadZipFile as exc:
        raise CryptoError(f"{path} is not a valid ZIP archive") from exc
    except (
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        KeyError,
        RuntimeError,
        zlib.error,
    ) as exc:
        raise CryptoError(f"Cannot read raw backup {path}: {exc}") from exc
    snapshot = vault.parse_snapshot(raw_snapshot)
    return RawBundle(
        path=path,
        meta=meta,
        unlock_method=unlock_method,
        snapshot=snapshot,
        blob_frames=blob_frames,
    )


def collection_from_raw(bundle: RawBundle) -> vault.BlobCollection:
    collection = vault.BlobCollection()
    for manifest in bundle.snapshot.ordered_manifests():
        manifest_id = str(manifest.get("manifestId", ""))
        hashes = bundle.snapshot.blob_hashes(manifest_id)
        collection.requested[manifest_id] = hashes
        frame = bundle.blob_frames.get(manifest_id)
        if not frame:
            collection.by_manifest[manifest_id] = {}
            continue
        header = parse_frame(frame)
        blobs = header.get("blobs")
        found: dict[str, dict[str, Any]] = {}
        if isinstance(blobs, list):
            for blob in blobs:
                if isinstance(blob, dict) and isinstance(blob.get("hash"), str):
                    found[blob["hash"]] = blob
        collection.by_manifest[manifest_id] = found
        collection.frames[manifest_id] = frame
    return collection


# ---------------------------------------------------------------------------
# Backup names and retention


def _timestamp() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def backup_paths(
    directory: Path, username: str, *, mode: str
) -> tuple[Path, Path | None]:
    ensure_private_dir(directory)
    prefix = f"aliasvault-{slugify(username or 'vault')}-{_timestamp()}"
    avex_path = directory / f"{prefix}.avex"
    counter = 1
    while avex_path.exists():
        avex_path = directory / f"{prefix}-{counter}.avex"
        counter += 1
    raw_path: Path | None = None
    if mode in ("raw", "both"):
        raw_path = avex_path.with_suffix(".avbak")
        counter = 1
        while raw_path.exists():
            raw_path = directory / f"{prefix}-{counter}.avbak"
            counter += 1
    return avex_path, raw_path


def prune_backups(directory: Path, keep: int, *, dry_run: bool = False) -> list[Path]:
    """Keep the newest ``keep`` files of each backup type.

    The two formats are counted separately so a short retention window on
    .avex files does not delete the only raw snapshot, or vice versa.
    """
    if keep < 1:
        return []
    removed: list[Path] = []
    for pattern in ("aliasvault-*.avex", "aliasvault-*.avbak"):
        files = [
            path
            for path in directory.glob(pattern)
            if path.is_file() and not path.is_symlink()
        ]
        files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
        for path in files[keep:]:
            removed.append(path)
            if not dry_run:
                path.unlink(missing_ok=True)
    return removed


# ---------------------------------------------------------------------------
# Verification


def verify_avex_file(path: Path, password: str) -> dict[str, Any]:
    data = path.read_bytes()
    avux_bytes = crypto.decrypt_avex(data, password)
    return verify_avux_bytes(avux_bytes, size=len(data))


def verify_avux_bytes(avux_bytes: bytes, *, size: int | None = None) -> dict[str, Any]:
    summary = avux.avux_summary(avux_bytes)
    manifest = avux.read_avux(avux_bytes)
    with zipfile.ZipFile(io.BytesIO(avux_bytes)) as archive:
        names = set(archive.namelist())
    missing_attachments: list[str] = []
    for item in manifest.get("items") or []:
        if not isinstance(item, dict):
            continue
        for attachment in item.get("attachments") or []:
            if isinstance(attachment, dict):
                relative = attachment.get("relativePath")
                if isinstance(relative, str) and relative not in names:
                    missing_attachments.append(relative)
    summary["missingAttachments"] = missing_attachments
    if missing_attachments:
        raise CryptoError(
            f"The .avex file is missing {len(missing_attachments)} attachment(s), "
            f"starting with {missing_attachments[0]}"
        )
    if size is not None:
        summary["size"] = size
    return summary


def verify_raw_file(path: Path, password: str | None = None) -> dict[str, Any]:
    bundle = read_raw_backup(path)
    collection = collection_from_raw(bundle)
    vault.missing_blob_error(collection)
    summary: dict[str, Any] = {
        "path": str(path),
        "format": bundle.meta.get("format"),
        "version": bundle.meta.get("version"),
        "createdAt": bundle.meta.get("createdAt"),
        "storageFormat": bundle.snapshot.storage_format,
        "manifests": len(bundle.snapshot.manifests),
        "blobFrames": len(bundle.blob_frames),
        "size": path.stat().st_size,
    }
    if bundle.snapshot.storage_format.lower() in ("sqlite-blob", "sqliteblob"):
        summary["legacy"] = True
        return summary
    if password:
        if not bundle.unlock_method:
            raise UnsupportedVaultError(
                "The raw snapshot has no unlock method to open with a password"
            )
        veks = vault.resolve_veks(
            bundle.snapshot,
            bundle.unlock_method,
            password=password,
            cached_veks=None,
        )
        manifests, _buckets = vault.decrypt_manifests(bundle.snapshot, veks)
        vault.missing_blob_error(collection)
        blobs = vault.decrypt_blobs(collection, manifests, veks)
        summary["items"] = sum(
            len(payload.value.get("tables", {}).get("Items", []))
            for payload in manifests.values()
            if isinstance(payload.value.get("tables"), dict)
        )
        summary["blobs"] = len(blobs)
        summary["verified"] = True
    return summary


# ---------------------------------------------------------------------------
# Orchestration


def _save_tokens(store: Any, secrets: Secrets, client: ApiClient) -> None:
    if client.tokens:
        secrets.tokens = dict(client.tokens)
        store.save(secrets)


def _login(
    client: ApiClient,
    config: AppConfig,
    *,
    password: str,
    totp_secret: str | None,
    totp_code: str | None,
    recovery_code: str | None,
) -> LoginResult:
    return client.login(
        config.username,
        password,
        remember_me=config.remember_me,
        totp_secret=totp_secret,
        totp_code=totp_code,
        recovery_code=recovery_code,
    )


def cache_veks(
    client: ApiClient,
    secrets: Secrets,
    *,
    password: str,
) -> dict[str, Any]:
    """Open the key chain and cache the VEK of every accessible manifest."""
    snapshot = vault.parse_snapshot(client.get_vault())
    if snapshot.storage_format.lower() in ("sqlite-blob", "sqliteblob"):
        return {
            "storageFormat": snapshot.storage_format,
            "legacy": True,
            "manifests": 0,
        }
    unlock_method = client.get_unlock_method()
    veks = vault.resolve_veks(
        snapshot, unlock_method, password=password, cached_veks=secrets.veks
    )
    manifests, _buckets = vault.decrypt_manifests(snapshot, veks)
    for manifest_id, vek in veks.by_manifest.items():
        secrets.veks[manifest_id] = vek
    item_count = 0
    for payload in manifests.values():
        tables = payload.value.get("tables")
        if isinstance(tables, dict):
            item_count += len(tables.get("Items", []))
    return {
        "storageFormat": snapshot.storage_format,
        "manifests": len(manifests),
        "items": item_count,
        "skippedShared": veks.skipped_shared,
    }


def run_backup(
    config: AppConfig,
    secrets: Secrets,
    store: Any,
    *,
    mode: str | None = None,
    output_dir: Path | None = None,
    keep: int | None = None,
    verify: bool = True,
    dry_run: bool = False,
    master_password: str | None = None,
    export_password: str | None = None,
    master_password_env: str = MASTER_PASSWORD_ENV,
    export_password_env: str = EXPORT_PASSWORD_ENV,
    totp_code: str | None = None,
    recovery_code: str | None = None,
    log: Any = None,
) -> dict[str, Any]:
    mode = mode or config.mode
    if mode not in ("avex", "raw", "both"):
        raise ConfigError("mode must be avex, raw, or both")
    if keep is not None and keep < 0:
        raise ConfigError("keep must be zero or positive")
    if mode in ("avex", "both") and not master_password:
        master_password = required_master_password(
            secrets, prompt=True, env_var=master_password_env
        )
    if mode in ("avex", "both"):
        if export_password is None:
            export_password, generated_export = export_password_for(
                config,
                secrets,
                master_password=master_password,
                prompt=True,
                generate_if_missing=True,
                env_var=export_password_env,
            )
        else:
            generated_export = False
        if generated_export:
            store.save(secrets)
            if log:
                log("Generated a new export password and saved it in the secrets file.")
    if mode == "raw":
        export_password = None

    client = ApiClient(config.api_url, tokens=secrets.tokens)
    try:
        if secrets.tokens:
            try:
                client.refresh()
                _save_tokens(store, secrets, client)
            except AuthError:
                if not master_password:
                    raise
                _login(
                    client,
                    config,
                    password=master_password,
                    totp_secret=secrets.totp_secret,
                    totp_code=totp_code,
                    recovery_code=recovery_code,
                )
                _save_tokens(store, secrets, client)
                if log:
                    log("Refreshed login with the master password.")
        else:
            if not master_password:
                raise ConfigError("No session is stored. Run `avb login` first.")
            _login(
                client,
                config,
                password=master_password,
                totp_secret=secrets.totp_secret,
                totp_code=totp_code,
                recovery_code=recovery_code,
            )
            _save_tokens(store, secrets, client)

        snapshot = vault.parse_snapshot(client.get_vault())
        unlock_method: dict[str, Any] | None = None
        try:
            unlock_method = client.get_unlock_method()
        except UnsupportedVaultError:
            # A legacy sqlite-blob account may have no password unlock method.
            unlock_method = None

        collection = vault.collect_blobs(client, snapshot)
        vault.missing_blob_error(collection)
        # A 401 retry may have rotated the refresh token while fetching the vault
        # or blobs. Persist the new pair before decryption, so a later failure
        # does not leave the stored refresh token unusable.
        _save_tokens(store, secrets, client)

        directory = output_dir or config.backup_dir
        avex_path, raw_path = backup_paths(directory, config.username, mode=mode)

        # Save the encrypted raw snapshot before touching the master-password
        # key chain. If decryption or .avex encryption fails later, the raw
        # snapshot is still written, and it can be exported offline.
        raw_written = False
        if not dry_run and mode in ("raw", "both") and raw_path is not None:
            write_raw_backup(
                raw_path,
                snapshot=snapshot,
                unlock_method=unlock_method,
                blob_collection=collection,
                config=config,
            )
            raw_written = True

        avex_bytes: bytes | None = None
        decrypted: vault.DecryptedSnapshot | None = None
        blobs: dict[str, bytes] = {}
        if snapshot.storage_format.lower() in ("sqlite-blob", "sqliteblob"):
            if mode in ("avex", "both"):
                raise UnsupportedVaultError(
                    "This account still uses the legacy sqlite-blob vault format. "
                    "Open the AliasVault app once to migrate it, then retry. "
                    "The encrypted raw snapshot has already been written; "
                    "use `avb backup --mode raw` for this legacy format."
                )
        else:
            can_decrypt = master_password is not None or bool(secrets.veks)
            if unlock_method is None:
                if mode in ("avex", "both"):
                    raise UnsupportedVaultError(
                        "The server returned no password unlock method for this "
                        "account, so an .avex export cannot be built"
                    )
                # The encrypted frames and key chain can still be preserved
                # even though they cannot be decrypted without an unlock
                # method; the raw snapshot remains restorable once the account
                # exposes one again.
                decrypted = None
            elif not can_decrypt and mode == "raw":
                # A raw snapshot is valuable without the master password: it
                # contains the encrypted frames and the key chain as served.
                decrypted = None
            else:
                veks = vault.resolve_veks(
                    snapshot,
                    unlock_method,
                    password=master_password,
                    cached_veks=secrets.veks,
                    skip_shared=master_password is None,
                )
                manifests, buckets = vault.decrypt_manifests(snapshot, veks)
                blobs = vault.decrypt_blobs(collection, manifests, veks)
                decrypted = vault.DecryptedSnapshot(
                    snapshot=snapshot,
                    veks=veks,
                    manifests=manifests,
                    buckets=buckets,
                    blobs=blobs,
                )
                for manifest_id, vek in veks.by_manifest.items():
                    secrets.veks[manifest_id] = vek
                if mode in ("avex", "both"):
                    avux_bytes = avux.build_avux(
                        decrypted.ordered_manifest_payloads(),
                        blobs,
                        exported_at=now_iso(),
                    )
                    assert export_password is not None
                    avex_bytes = crypto.encrypt_avex(
                        avux_bytes,
                        export_password,
                        app_version=f"aliasvault-backup/{__version__}",
                    )

        written: list[str] = []
        summary: dict[str, Any] = {
            "mode": mode,
            "storageFormat": snapshot.storage_format,
            "manifests": len(snapshot.manifests),
            "blobs": len(blobs)
            if decrypted is not None
            else sum(len(value) for value in collection.by_manifest.values()),
            "avex": None,
            "raw": None,
        }

        if dry_run:
            store.save(secrets)
            summary["wouldWrite"] = {
                "avex": str(avex_path) if mode in ("avex", "both") else None,
                "raw": str(raw_path) if raw_path else None,
            }
            return summary

        if raw_written and raw_path is not None:
            written.append(str(raw_path))
            summary["raw"] = str(raw_path)

        if mode in ("avex", "both") and avex_bytes is not None:
            atomic_write(avex_path, avex_bytes, mode=0o600)
            written.append(str(avex_path))
            summary["avex"] = str(avex_path)
            if verify:
                assert export_password is not None
                summary["avexVerification"] = verify_avex_file(
                    avex_path, export_password
                )

        if mode in ("raw", "both") and raw_path is not None and verify:
            summary["rawVerification"] = verify_raw_file(
                raw_path,
                master_password if unlock_method is not None else None,
            )

        # Persist the rotated refresh token and any new cached VEKs.
        store.save(secrets)

        if keep is None:
            keep = config.keep
        if keep and keep > 0:
            removed = prune_backups(directory, keep)
            if removed:
                summary["pruned"] = [str(path) for path in removed]
        summary["written"] = written
        return summary
    finally:
        client.close()


def export_raw_to_avex(
    raw_path: Path,
    output_path: Path,
    *,
    password: str,
    export_password: str,
    verify: bool = True,
) -> dict[str, Any]:
    bundle = read_raw_backup(raw_path)
    if not bundle.unlock_method:
        raise UnsupportedVaultError(
            "The raw snapshot has no unlock method; cannot open it offline"
        )
    if bundle.snapshot.storage_format.lower() in ("sqlite-blob", "sqliteblob"):
        raise UnsupportedVaultError(
            "This raw snapshot uses the legacy sqlite-blob format; offline .avex conversion is not implemented."
        )
    collection = collection_from_raw(bundle)
    vault.missing_blob_error(collection)
    veks = vault.resolve_veks(
        bundle.snapshot,
        bundle.unlock_method,
        password=password,
    )
    manifests, _buckets = vault.decrypt_manifests(bundle.snapshot, veks)
    blobs = vault.decrypt_blobs(collection, manifests, veks)
    avux_bytes = avux.build_avux(
        [
            manifests[manifest_id].value
            for manifest_id in [
                str(item.get("manifestId", ""))
                for item in bundle.snapshot.ordered_manifests()
            ]
            if manifest_id in manifests
        ],
        blobs,
        exported_at=now_iso(),
    )
    encrypted = crypto.encrypt_avex(
        avux_bytes,
        export_password,
        app_version=f"aliasvault-backup/{__version__}",
    )
    atomic_write(output_path, encrypted, mode=0o600)
    summary: dict[str, Any] = {
        "output": str(output_path),
        "items": len(avux.read_avux(avux_bytes).get("items", [])),
        "size": len(encrypted),
    }
    if verify:
        summary["verification"] = verify_avex_file(output_path, export_password)
    return summary


def decode_avex(
    path: Path, password: str, destination: Path, *, overwrite: bool = False
) -> dict[str, Any]:
    avux_bytes = crypto.decrypt_avex(path.read_bytes(), password)
    summary = avux.avux_summary(avux_bytes)
    written = avux.extract_avux(avux_bytes, destination, overwrite=overwrite)
    summary["extracted"] = len(written)
    summary["destination"] = str(destination)
    return summary
