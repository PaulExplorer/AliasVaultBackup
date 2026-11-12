"""Vault snapshot parsing, key resolution, and blob decryption."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import crypto, keys
from .errors import CryptoError, UnsupportedVaultError
from .util import parse_frame


@dataclass
class Snapshot:
    header: dict[str, Any]
    raw: bytes

    @property
    def storage_format(self) -> str:
        value = self.header.get("storageFormat") or "manifest"
        return str(value)

    @property
    def personal_manifest_id(self) -> str | None:
        value = self.header.get("personalManifestId")
        return value if isinstance(value, str) and value else None

    @property
    def manifests(self) -> list[dict[str, Any]]:
        value = self.header.get("manifests")
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @property
    def buckets(self) -> list[dict[str, Any]]:
        value = self.header.get("buckets")
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @property
    def legacy_vault_blob(self) -> str | None:
        value = self.header.get("legacyVaultBlob")
        return value if isinstance(value, str) and value else None

    def manifest(self, manifest_id: str) -> dict[str, Any] | None:
        for manifest in self.manifests:
            if str(manifest.get("manifestId", "")).lower() == manifest_id.lower():
                return manifest
        return None

    def ordered_manifests(self) -> list[dict[str, Any]]:
        personal = self.personal_manifest_id
        manifests = self.manifests
        if personal:
            manifests = sorted(
                manifests,
                key=lambda item: (
                    0
                    if str(item.get("manifestId", "")).lower() == personal.lower()
                    else 1
                ),
            )
        return manifests

    def blob_hashes(self, manifest_id: str) -> list[str]:
        manifest = self.manifest(manifest_id)
        if not manifest:
            return []
        references = manifest.get("blobReferences")
        if not isinstance(references, list):
            return []
        hashes: list[str] = []
        for reference in references:
            if isinstance(reference, dict):
                value = reference.get("hash")
                if isinstance(value, str) and value and value not in hashes:
                    hashes.append(value)
        return hashes


@dataclass
class Veks:
    chain: keys.KeyChain | None
    by_manifest: dict[str, str]
    skipped_shared: list[str] = field(default_factory=list)


@dataclass
class BlobCollection:
    by_manifest: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    frames: dict[str, bytes] = field(default_factory=dict)
    requested: dict[str, list[str]] = field(default_factory=dict)

    def missing(self) -> list[tuple[str, str]]:
        missing: list[tuple[str, str]] = []
        for manifest_id, hashes in self.requested.items():
            found = self.by_manifest.get(manifest_id, {})
            for blob_hash in hashes:
                if blob_hash not in found:
                    missing.append((manifest_id, blob_hash))
        return missing


@dataclass
class DecryptedSnapshot:
    snapshot: Snapshot
    veks: Veks
    manifests: dict[str, crypto.UnpackedPayload]
    buckets: dict[tuple[str, str], crypto.UnpackedPayload] = field(default_factory=dict)
    blobs: dict[str, bytes] = field(default_factory=dict)

    @property
    def personal_manifest_id(self) -> str | None:
        return self.snapshot.personal_manifest_id

    def ordered_manifest_payloads(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for manifest in self.snapshot.ordered_manifests():
            manifest_id = str(manifest.get("manifestId", ""))
            payload = self.manifests.get(manifest_id)
            if payload is not None:
                result.append(payload.value)
        return result


def parse_snapshot(raw: bytes) -> Snapshot:
    header = parse_frame(raw)
    storage_format = str(header.get("storageFormat") or "manifest")
    if storage_format.lower() not in ("manifest", "sqlite-blob", "sqliteblob"):
        raise UnsupportedVaultError(
            f"Unsupported vault storage format: {storage_format!r}"
        )
    snapshot = Snapshot(header=header, raw=raw)
    if snapshot.storage_format.lower() in ("sqlite-blob", "sqliteblob"):
        return snapshot
    if not snapshot.personal_manifest_id:
        raise CryptoError("The vault snapshot has no personal manifest id")
    for manifest in snapshot.manifests:
        if not isinstance(manifest.get("manifestId"), str):
            raise CryptoError("The vault snapshot contains a manifest without an id")
        if not isinstance(manifest.get("_data"), (bytes, bytearray)):
            raise CryptoError(
                "The vault snapshot contains a manifest without ciphertext"
            )
    return snapshot


def resolve_veks(
    snapshot: Snapshot,
    vault_key: dict[str, Any],
    *,
    password: str | None,
    cached_veks: dict[str, str] | None = None,
    skip_shared: bool = False,
) -> Veks:
    """Resolve every manifest's VEK.

    The personal VEK comes from the account key chain when a password is given,
    or from the cache for a token-only raw backup. Shared manifests use their
    RSA-OAEP grant for the account private key.
    """

    chain: keys.KeyChain | None = None
    by_manifest: dict[str, str] = {}
    if password is not None:
        chain = keys.open_key_chain_with_password(password, vault_key)
    personal_id = snapshot.personal_manifest_id
    if not personal_id:
        raise CryptoError("The vault snapshot has no personal manifest id")

    personal_vek: str | None = None
    if chain is not None:
        personal_vek = chain.vek_b64
    elif cached_veks:
        personal_vek = cached_veks.get(personal_id) or cached_veks.get(
            personal_id.lower()
        )
    if not personal_vek:
        raise CryptoError(
            "The personal vault key is not available. Provide the master password or run `avb login` again."
        )
    by_manifest[personal_id] = personal_vek

    skipped: list[str] = []
    for manifest in snapshot.ordered_manifests():
        manifest_id = str(manifest.get("manifestId", ""))
        if manifest_id == personal_id:
            continue
        key_type = manifest.get("keyType")
        encrypted_vek = manifest.get("encryptedVek")
        if not isinstance(encrypted_vek, str) or not encrypted_vek:
            # A manifest this account cannot open is not part of its vault.
            continue
        if key_type not in (None, "grant-key"):
            # Future key types are safer left closed than guessed at.
            if skip_shared:
                skipped.append(manifest_id)
                continue
            raise UnsupportedVaultError(
                f"Manifest {manifest_id} uses unsupported key type {key_type!r}"
            )
        if chain is None or not chain.account_private_key_jwk:
            if skip_shared:
                skipped.append(manifest_id)
                continue
            raise UnsupportedVaultError(
                f"Shared manifest {manifest_id} needs the account private key, "
                "which requires the master password."
            )
        try:
            by_manifest[manifest_id] = keys.open_shared_manifest_vek(
                manifest,
                chain.account_private_key_jwk,
                chain.signing_public_key_b64,
            )
        except (CryptoError, UnsupportedVaultError):
            if skip_shared:
                skipped.append(manifest_id)
                continue
            raise

    return Veks(chain=chain, by_manifest=by_manifest, skipped_shared=skipped)


def decrypt_manifests(
    snapshot: Snapshot, veks: Veks
) -> tuple[
    dict[str, crypto.UnpackedPayload], dict[tuple[str, str], crypto.UnpackedPayload]
]:
    manifests: dict[str, crypto.UnpackedPayload] = {}
    buckets: dict[tuple[str, str], crypto.UnpackedPayload] = {}
    for manifest in snapshot.ordered_manifests():
        manifest_id = str(manifest.get("manifestId", ""))
        vek = veks.by_manifest.get(manifest_id)
        if not vek:
            continue
        ciphertext = manifest.get("_data")
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            # An empty personal manifest is valid and simply has no tables.
            manifests[manifest_id] = crypto.UnpackedPayload(
                value={
                    "schemaVersion": 1,
                    "manifestId": manifest_id,
                    "manifestSalt": "",
                    "canonicalizedAt": "",
                    "tables": {},
                },
                json_text="{}",
                schema_version=1,
            )
            continue
        expected_hash = manifest.get("ciphertextHash")
        payload = keys.decrypt_manifest_payload(
            bytes(ciphertext),
            vek,
            manifest_id,
            expected_ciphertext_hash=expected_hash
            if isinstance(expected_hash, str)
            else None,
        )
        salt = payload.value.get("manifestSalt")
        if not isinstance(salt, str) or not salt:
            raise CryptoError(f"Manifest {manifest_id} has no manifest salt")
        manifests[manifest_id] = payload

    for bucket in snapshot.buckets:
        manifest_id = str(bucket.get("manifestId", ""))
        category = bucket.get("category")
        vek = veks.by_manifest.get(manifest_id)
        if not vek or not isinstance(category, str):
            continue
        ciphertext = bucket.get("_data")
        if not isinstance(ciphertext, (bytes, bytearray)) or not ciphertext:
            continue
        expected_hash = bucket.get("ciphertextHash")
        buckets[(manifest_id, category)] = keys.decrypt_bucket_payload(
            bytes(ciphertext),
            vek,
            manifest_id,
            category,
            expected_ciphertext_hash=expected_hash
            if isinstance(expected_hash, str)
            else None,
        )
    return manifests, buckets


def collect_blobs(client: Any, snapshot: Snapshot) -> BlobCollection:
    collection = BlobCollection()
    for manifest in snapshot.ordered_manifests():
        manifest_id = str(manifest.get("manifestId", ""))
        hashes = snapshot.blob_hashes(manifest_id)
        collection.requested[manifest_id] = hashes
        if not hashes:
            collection.by_manifest[manifest_id] = {}
            continue
        download = client.download_blobs(manifest_id, hashes)
        collection.by_manifest[manifest_id] = download.blobs
        if download.frame:
            collection.frames[manifest_id] = download.frame
    return collection


def decrypt_blobs(
    collection: BlobCollection,
    manifests: dict[str, crypto.UnpackedPayload],
    veks: Veks,
) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for manifest_id, blobs in collection.by_manifest.items():
        payload = manifests.get(manifest_id)
        vek = veks.by_manifest.get(manifest_id)
        if payload is None or vek is None:
            continue
        manifest_salt = payload.value.get("manifestSalt")
        if not isinstance(manifest_salt, str) or not manifest_salt:
            if blobs:
                raise CryptoError(
                    f"Manifest {manifest_id} references blobs but has no salt"
                )
            continue
        for blob_hash, blob in blobs.items():
            encrypted_data = blob.get("_data")
            encrypted_key = blob.get("encryptedBlobKey")
            if not isinstance(encrypted_data, (bytes, bytearray)) or not isinstance(
                encrypted_key, str
            ):
                raise CryptoError(f"Blob {blob_hash} is incomplete")
            plaintext = keys.decrypt_blob(
                bytes(encrypted_data),
                encrypted_key,
                vek,
                manifest_id,
                manifest_salt,
                blob_hash,
            )
            existing = result.get(blob_hash)
            if existing is not None and existing != plaintext:
                raise CryptoError(
                    f"Two different blobs share the hash {blob_hash}; refusing ambiguous data"
                )
            result[blob_hash] = plaintext
    return result


def missing_blob_error(collection: BlobCollection) -> None:
    missing = collection.missing()
    if not missing:
        return
    manifest_id, blob_hash = missing[0]
    raise CryptoError(
        f"The server did not return blob {blob_hash} for manifest {manifest_id} "
        f"({len(missing)} missing in total). The backup is incomplete."
    )
