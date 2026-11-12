from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from aliasvault_backup import backup, crypto, vault
from aliasvault_backup.api import BlobDownload
from aliasvault_backup.config import AppConfig
from aliasvault_backup.crypto import salted_blob_hash
from aliasvault_backup.secrets import Secrets, SecretStore
from aliasvault_backup.util import b64e, b64e_url, encode_frame, sha256_hex


def _rsa_jwks(private: rsa.RSAPrivateKey) -> tuple[str, str]:
    numbers = private.private_numbers()
    public = numbers.public_numbers
    private_jwk = json.dumps(
        {
            "kty": "RSA",
            "n": b64e_url(public.n.to_bytes(256, "big")),
            "e": b64e_url(public.e.to_bytes(3, "big")),
            "d": b64e_url(numbers.d.to_bytes(256, "big")),
            "p": b64e_url(numbers.p.to_bytes(128, "big")),
            "q": b64e_url(numbers.q.to_bytes(128, "big")),
        }
    )
    public_jwk = json.dumps(
        {
            "kty": "RSA",
            "n": b64e_url(public.n.to_bytes(256, "big")),
            "e": b64e_url(public.e.to_bytes(3, "big")),
        }
    )
    return private_jwk, public_jwk


def _row(**values):
    base = {
        "IsDeleted": 0,
        "CreatedAt": "2025-01-01 00:00:00",
        "UpdatedAt": "2025-01-01 00:00:00",
    }
    base.update(values)
    return base


def _make_vault():
    password = "test master password"
    account_key = os.urandom(32)
    vek = os.urandom(32)
    salt = "00112233445566778899aabbccddeeff"
    settings = json.dumps(
        {"MemorySize": 19456, "Iterations": 2, "DegreeOfParallelism": 1}
    )
    unlock = crypto.argon2id(
        password.encode(), salt.encode(), memory_kib=19456, iterations=2, parallelism=1
    )
    kek = crypto.derive_kek(unlock)
    vault_key = {
        "type": "password",
        "salt": salt,
        "encryptionType": "Argon2IdHkdf",
        "encryptionSettings": settings,
        "algorithm": "aes256-gcm",
        "encryptedAccountKey": crypto.encrypt_key(
            b64e(account_key), b64e(kek), crypto.AAD_ACCOUNT_KEY
        ),
        "encryptedVek": crypto.encrypt_key(
            b64e(vek), b64e(account_key), crypto.AAD_PERSONAL_VEK
        ),
    }
    private_jwk, public_jwk = _rsa_jwks(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    vault_key["encryptedAccountPrivateKey"] = crypto.encrypt_text(
        private_jwk, b64e(account_key), crypto.AAD_ACCOUNT_PRIVATE_KEY
    )
    vault_key["accountPublicKey"] = public_jwk
    signing_private = ed25519.Ed25519PrivateKey.generate()
    vault_key["encryptedSigningPrivateKey"] = crypto.encrypt_key(
        b64e(signing_private.private_bytes_raw()),
        b64e(account_key),
        crypto.AAD_ACCOUNT_SIGNING_PRIVATE_KEY,
    )
    vault_key["signingPublicKey"] = b64e(
        signing_private.public_key().public_bytes_raw()
    )

    manifest_id = "11111111-2222-3333-4444-555555555555"
    manifest_salt = "aabbccdd"
    attachment = b"attachment contents"
    logo = b"\x89PNG\r\n\x1a\nlogo"
    attachment_hash = salted_blob_hash(attachment, manifest_salt)
    logo_hash = salted_blob_hash(logo, manifest_salt)
    payload = {
        "schemaVersion": 1,
        "manifestId": manifest_id,
        "manifestSalt": manifest_salt,
        "canonicalizedAt": "2025-01-01T00:00:00.000Z",
        "tables": {
            "Items": [
                _row(
                    ManifestId=manifest_id,
                    Id="item-1",
                    Name="Example login",
                    ItemType="Login",
                    LogoId="logo-1",
                    FolderId="folder-1",
                    ArchivedAt=None,
                )
            ],
            "Folders": [
                _row(
                    ManifestId=manifest_id,
                    Id="folder-1",
                    Name="Personal",
                    ParentFolderId=None,
                    Weight=1,
                )
            ],
            "FieldValues": [
                _row(
                    ManifestId=manifest_id,
                    Id="fv-1",
                    ItemId="item-1",
                    FieldKey="login.username",
                    FieldDefinitionId=None,
                    Value="me@example.com",
                    Weight=1,
                    ValueIndex=0,
                ),
                _row(
                    ManifestId=manifest_id,
                    Id="fv-2",
                    ItemId="item-1",
                    FieldKey="login.password",
                    FieldDefinitionId=None,
                    Value="hunter2",
                    Weight=2,
                    ValueIndex=0,
                ),
            ],
            "Attachments": [
                _row(
                    ManifestId=manifest_id,
                    Id="att-1",
                    ItemId="item-1",
                    Filename="note.txt",
                    Blob={"__blobRef": attachment_hash, "__blobKind": "attachment"},
                    BlobHash=attachment_hash,
                )
            ],
            "Logos": [
                _row(
                    ManifestId=manifest_id,
                    Id="logo-1",
                    Kind="custom",
                    Source="example.com",
                    Name="Example",
                    MimeType="image/png",
                    FileData={"__blobRef": logo_hash, "__blobKind": "logo"},
                    FileDataHash=logo_hash,
                    FetchedAt="2025-01-01 00:00:00",
                )
            ],
        },
    }
    ciphertext = crypto.aes_gcm_encrypt(
        crypto.pack_payload(payload), vek, crypto.aad_manifest(manifest_id)
    )
    snapshot_raw = encode_frame(
        {
            "storageFormat": "manifest",
            "personalManifestId": manifest_id,
            "manifests": [
                {
                    "manifestId": manifest_id,
                    "ciphertextHash": sha256_hex(ciphertext),
                    "revision": 1,
                    "blobReferences": [
                        {
                            "hash": attachment_hash,
                            "category": "attachment",
                            "sizeBytes": len(attachment),
                        },
                        {"hash": logo_hash, "category": "logo", "sizeBytes": len(logo)},
                    ],
                    "keyType": "account-key",
                }
            ],
            "buckets": [],
        },
        [ciphertext],
    )

    blobs: dict[str, dict] = {}
    parts: list[bytes] = []
    entries: list[dict] = []
    for data, blob_hash, category in (
        (attachment, attachment_hash, "attachment"),
        (logo, logo_hash, "logo"),
    ):
        blob_key = os.urandom(32)
        encrypted_data = crypto.aes_gcm_encrypt(
            data, blob_key, crypto.aad_blob_data(manifest_id, blob_hash)
        )
        encrypted_key = crypto.encrypt_key(
            b64e(blob_key), b64e(vek), crypto.aad_blob_key(manifest_id, blob_hash)
        )
        entries.append(
            {"hash": blob_hash, "category": category, "encryptedBlobKey": encrypted_key}
        )
        parts.append(encrypted_data)
        blobs[blob_hash] = {
            "hash": blob_hash,
            "category": category,
            "encryptedBlobKey": encrypted_key,
            "_data": encrypted_data,
        }
    return (
        password,
        manifest_id,
        vault_key,
        snapshot_raw,
        blobs,
        encode_frame({"blobs": entries}, parts),
    )


def test_offline_raw_to_avex_round_trip(tmp_path: Path) -> None:
    password, manifest_id, vault_key, snapshot_raw, blobs, blob_frame = _make_vault()
    snapshot = vault.parse_snapshot(snapshot_raw)
    collection = vault.BlobCollection(
        by_manifest={manifest_id: blobs},
        frames={manifest_id: blob_frame},
        requested={manifest_id: list(blobs)},
    )
    config = AppConfig(
        username="test@example.com", api_url="https://app.aliasvault.com/api"
    )
    raw_path = tmp_path / "snapshot.avbak"
    backup.write_raw_backup(
        raw_path,
        snapshot=snapshot,
        unlock_method=vault_key,
        blob_collection=collection,
        config=config,
    )

    bundle = backup.read_raw_backup(raw_path)
    assert bundle.unlock_method == vault_key
    assert bundle.snapshot.personal_manifest_id == manifest_id
    assert set(bundle.blob_frames) == {manifest_id}

    veks = vault.resolve_veks(bundle.snapshot, vault_key, password=password)
    manifests, _buckets = vault.decrypt_manifests(bundle.snapshot, veks)
    loaded = backup.collection_from_raw(bundle)
    loaded_blobs = vault.decrypt_blobs(loaded, manifests, veks)
    attachment_ref = manifests[manifest_id].value["tables"]["Attachments"][0]["Blob"][
        "__blobRef"
    ]
    assert loaded_blobs[attachment_ref] == b"attachment contents"

    output = tmp_path / "recovered.avex"
    summary = backup.export_raw_to_avex(
        raw_path, output, password=password, export_password="export password"
    )
    assert summary["items"] == 1
    assert summary["verification"]["items"] == 1
    assert crypto.decrypt_avex(output.read_bytes(), "export password").startswith(b"PK")

    destination = tmp_path / "extracted"
    decoded = backup.decode_avex(output, "export password", destination)
    assert decoded["extracted"] >= 2
    extracted = json.loads((destination / "manifest.json").read_text())
    assert extracted["items"][0]["fieldValues"][0]["value"] == "me@example.com"
    assert (
        destination / "attachments" / "item-1_att-1_note.txt"
    ).read_bytes() == b"attachment contents"


def test_verify_raw_and_avex(tmp_path: Path) -> None:
    password, manifest_id, vault_key, snapshot_raw, blobs, blob_frame = _make_vault()
    snapshot = vault.parse_snapshot(snapshot_raw)
    collection = vault.BlobCollection(
        by_manifest={manifest_id: blobs},
        frames={manifest_id: blob_frame},
        requested={manifest_id: list(blobs)},
    )
    raw_path = tmp_path / "snapshot.avbak"
    backup.write_raw_backup(
        raw_path,
        snapshot=snapshot,
        unlock_method=vault_key,
        blob_collection=collection,
        config=AppConfig(username="test@example.com"),
    )
    summary = backup.verify_raw_file(raw_path, password)
    assert summary["verified"] is True
    assert summary["items"] == 1
    assert summary["blobs"] == 2


class _FakeClient:
    def __init__(self, snapshot_raw, vault_key, blobs, blob_frame, manifest_id):
        self.snapshot_raw = snapshot_raw
        self.vault_key = vault_key
        self.blobs = blobs
        self.blob_frame = blob_frame
        self.manifest_id = manifest_id
        self.tokens = {"token": "fake", "refreshToken": "fake-refresh"}
        self.closed = False

    def refresh(self):
        return dict(self.tokens)

    def get_vault(self):
        return self.snapshot_raw

    def get_unlock_method(self):
        return self.vault_key

    def download_blobs(self, manifest_id, hashes):
        assert manifest_id == self.manifest_id
        return BlobDownload(blobs=self.blobs, frame=self.blob_frame)

    def close(self):
        self.closed = True


def test_run_backup_with_fake_client(tmp_path: Path, monkeypatch) -> None:
    password, manifest_id, vault_key, snapshot_raw, blobs, blob_frame = _make_vault()
    fake = _FakeClient(snapshot_raw, vault_key, blobs, blob_frame, manifest_id)
    monkeypatch.setattr(backup, "ApiClient", lambda *args, **kwargs: fake)

    store = SecretStore(tmp_path / "secrets.json")
    secrets = Secrets(tokens={"token": "old", "refreshToken": "old-refresh"})
    store.save(secrets)
    config = AppConfig(
        username="test@example.com",
        backup_dir=tmp_path / "backups",
        mode="both",
        keep=1,
        config_path=tmp_path / "config.toml",
        secrets_path=tmp_path / "secrets.json",
    )
    summary = backup.run_backup(
        config,
        secrets,
        store,
        master_password=password,
        export_password="export password",
        verify=True,
    )
    assert Path(summary["avex"]).exists()
    assert Path(summary["raw"]).exists()
    assert summary["avexVerification"]["items"] == 1
    assert summary["rawVerification"]["verified"] is True
    assert fake.closed is True


def test_run_backup_raw_without_unlock_method(tmp_path: Path, monkeypatch) -> None:
    password, manifest_id, _vault_key, snapshot_raw, blobs, blob_frame = _make_vault()
    fake = _FakeClient(snapshot_raw, None, blobs, blob_frame, manifest_id)
    monkeypatch.setattr(backup, "ApiClient", lambda *args, **kwargs: fake)

    store = SecretStore(tmp_path / "secrets.json")
    secrets = Secrets(tokens={"token": "old", "refreshToken": "old-refresh"})
    store.save(secrets)
    config = AppConfig(
        username="test@example.com",
        backup_dir=tmp_path / "backups",
        mode="raw",
        keep=1,
        config_path=tmp_path / "config.toml",
        secrets_path=tmp_path / "secrets.json",
    )
    summary = backup.run_backup(
        config,
        secrets,
        store,
        master_password=password,
        verify=True,
    )
    assert summary["avex"] is None
    raw_path = Path(summary["raw"])
    assert raw_path.exists()
    # Without an unlock method the snapshot can only be verified structurally.
    assert "verified" not in summary["rawVerification"]
    assert backup.read_raw_backup(raw_path).unlock_method is None
