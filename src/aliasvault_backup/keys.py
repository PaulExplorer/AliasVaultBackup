"""The AliasVault account key chain and manifest/blob decryption."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from typing import Any

from . import crypto
from .errors import CryptoError, UnsupportedVaultError
from .util import b64d, b64e, sha256_hex


@dataclass(frozen=True)
class Argon2Params:
    memory_kib: int
    iterations: int
    parallelism: int


@dataclass
class KeyChain:
    unlock_key_b64: str
    account_key_b64: str
    vek_b64: str
    account_private_key_jwk: str | None = None
    signing_public_key_b64: str | None = None


def parse_encryption_settings(settings_json: str) -> Argon2Params:
    try:
        settings = json.loads(settings_json)
        return Argon2Params(
            memory_kib=int(settings["MemorySize"]),
            iterations=int(settings["Iterations"]),
            parallelism=int(settings["DegreeOfParallelism"]),
        )
    except Exception as exc:
        raise CryptoError("Invalid Argon2 encryption settings from the server") from exc


def derive_unlock_key(password: str, salt: str, settings_json: str) -> bytes:
    params = parse_encryption_settings(settings_json)
    if params.memory_kib < 19456 or params.iterations < 2 or params.parallelism < 1:
        raise CryptoError(
            "The server asked for weaker Argon2 parameters than AliasVault's minimum"
        )
    return crypto.argon2id(
        password.encode("utf-8"),
        salt.encode("utf-8"),
        memory_kib=params.memory_kib,
        iterations=params.iterations,
        parallelism=params.parallelism,
    )


def unlock_key_b64(password: str, salt: str, settings_json: str) -> str:
    return b64e(derive_unlock_key(password, salt, settings_json))


def srp_password_hash(unlock_key: bytes, encryption_type: str) -> str:
    return crypto.derive_srp_password_hash(unlock_key, encryption_type)


def _vault_key_field(vault_key: dict[str, Any], name: str) -> str | None:
    value = vault_key.get(name)
    return value if isinstance(value, str) and value else None


def _check_account_public_key(
    account_public_jwk: str | None, private_jwk: str | None
) -> None:
    if not account_public_jwk or not private_jwk:
        return
    try:
        public = crypto.rsa_public_key_from_jwk(account_public_jwk)
        private = crypto.rsa_private_key_from_jwk(private_jwk)
        if public.public_numbers() != private.public_key().public_numbers():
            raise CryptoError(
                "The account public key does not belong to the account private key"
            )
    except CryptoError:
        raise
    except Exception as exc:
        raise CryptoError("The account RSA key pair is invalid") from exc


def open_key_chain(unlock_key: bytes, vault_key: dict[str, Any]) -> KeyChain:
    """Open the Account Key, personal VEK, and optional account/signing keys."""

    encrypted_account_key = _vault_key_field(vault_key, "encryptedAccountKey")
    encrypted_vek = _vault_key_field(vault_key, "encryptedVek")
    if not encrypted_account_key:
        raise CryptoError("The server did not return an encrypted Account Key")
    if not encrypted_vek:
        raise UnsupportedVaultError(
            "This account has no vault encryption key yet (legacy sqlite-blob storage). "
            "Open the AliasVault app once to migrate it to the manifest storage format."
        )
    algorithm = _vault_key_field(vault_key, "algorithm") or "aes256-gcm"
    if algorithm != "aes256-gcm":
        raise UnsupportedVaultError(
            f"Unsupported Account Key encryption algorithm: {algorithm}"
        )

    unlock_key_b64 = b64e(unlock_key)
    kek_b64 = b64e(crypto.derive_kek(unlock_key))

    try:
        account_key_b64 = crypto.decrypt_key(
            encrypted_account_key, kek_b64, crypto.AAD_ACCOUNT_KEY
        )
    except CryptoError as exc:
        raise CryptoError(
            "The master password does not open this account (wrong password or changed key)"
        ) from exc

    try:
        vek_b64 = crypto.decrypt_key(
            encrypted_vek, account_key_b64, crypto.AAD_PERSONAL_VEK
        )
    except CryptoError as exc:
        raise CryptoError(
            "The Account Key does not open the personal vault key (damaged key chain)"
        ) from exc

    account_private_key_jwk: str | None = None
    encrypted_private = _vault_key_field(vault_key, "encryptedAccountPrivateKey")
    if encrypted_private:
        try:
            account_private_key_jwk = crypto.decrypt_text(
                encrypted_private, account_key_b64, crypto.AAD_ACCOUNT_PRIVATE_KEY
            )
        except CryptoError:
            # A missing/broken private key only blocks shared vaults; personal data still opens.
            account_private_key_jwk = None

    signing_public_key_b64: str | None = None
    encrypted_signing = _vault_key_field(vault_key, "encryptedSigningPrivateKey")
    if encrypted_signing:
        try:
            signing_seed_b64 = crypto.decrypt_key(
                encrypted_signing,
                account_key_b64,
                crypto.AAD_ACCOUNT_SIGNING_PRIVATE_KEY,
            )
            signing_public_key_b64 = crypto.ed25519_public_from_private(
                signing_seed_b64
            )
        except CryptoError:
            signing_public_key_b64 = None

    _check_account_public_key(
        _vault_key_field(vault_key, "accountPublicKey"), account_private_key_jwk
    )

    return KeyChain(
        unlock_key_b64=unlock_key_b64,
        account_key_b64=account_key_b64,
        vek_b64=vek_b64,
        account_private_key_jwk=account_private_key_jwk,
        signing_public_key_b64=signing_public_key_b64,
    )


def open_key_chain_with_password(password: str, vault_key: dict[str, Any]) -> KeyChain:
    salt = _vault_key_field(vault_key, "salt")
    settings = _vault_key_field(vault_key, "encryptionSettings")
    if not salt or not settings:
        raise CryptoError(
            "The server's key chain response has no salt or Argon2 settings"
        )
    unlock_key = derive_unlock_key(password, salt, settings)
    return open_key_chain(unlock_key, vault_key)


# ---------------------------------------------------------------------------
# Manifest / bucket / blob decryption


def verify_ciphertext_hash(ciphertext: bytes, expected: str | None, label: str) -> None:
    if not expected:
        return
    actual = sha256_hex(ciphertext)
    if not hmac.compare_digest(actual, expected.lower()):
        raise CryptoError(
            f"{label} ciphertext hash mismatch; refusing to use possibly corrupted data "
            f"(expected {expected}, got {actual})"
        )


def decrypt_manifest_payload(
    ciphertext: bytes,
    vek_b64: str,
    manifest_id: str,
    *,
    expected_ciphertext_hash: str | None = None,
) -> crypto.UnpackedPayload:
    verify_ciphertext_hash(
        ciphertext, expected_ciphertext_hash, f"manifest {manifest_id}"
    )
    plaintext = crypto.aes_gcm_decrypt(
        ciphertext, b64d(vek_b64), crypto.aad_manifest(manifest_id)
    )
    payload = crypto.unpack_payload(plaintext)
    declared = payload.value.get("manifestId")
    if not isinstance(declared, str) or declared.lower() != manifest_id.lower():
        raise CryptoError(
            f"Manifest {manifest_id} declares a different id inside its encrypted payload; refusing it"
        )
    return payload


def decrypt_bucket_payload(
    ciphertext: bytes,
    vek_b64: str,
    manifest_id: str,
    category: str,
    *,
    expected_ciphertext_hash: str | None = None,
) -> crypto.UnpackedPayload:
    label = f"{category} bucket of manifest {manifest_id}"
    verify_ciphertext_hash(ciphertext, expected_ciphertext_hash, label)
    plaintext = crypto.aes_gcm_decrypt(
        ciphertext, b64d(vek_b64), crypto.aad_bucket(manifest_id, category)
    )
    payload = crypto.unpack_payload(plaintext)
    declared_manifest = payload.value.get("manifestId")
    declared_category = payload.value.get("category")
    if (
        not isinstance(declared_manifest, str)
        or declared_manifest.lower() != manifest_id.lower()
    ):
        raise CryptoError(
            f"{label} declares a different manifest id inside its payload"
        )
    if declared_category != category:
        raise CryptoError(f"{label} declares a different category inside its payload")
    return payload


def decrypt_blob(
    encrypted_data: bytes,
    encrypted_blob_key_b64: str,
    vek_b64: str,
    manifest_id: str,
    manifest_salt: str,
    expected_hash: str,
) -> bytes:
    blob_key_b64 = crypto.decrypt_key(
        encrypted_blob_key_b64, vek_b64, crypto.aad_blob_key(manifest_id, expected_hash)
    )
    try:
        plaintext = crypto.aes_gcm_decrypt(
            encrypted_data,
            b64d(blob_key_b64),
            crypto.aad_blob_data(manifest_id, expected_hash),
        )
    except CryptoError as exc:
        raise CryptoError(
            f"Blob {expected_hash} did not decrypt with its manifest key"
        ) from exc
    actual = crypto.salted_blob_hash(plaintext, manifest_salt)
    if not hmac.compare_digest(actual, expected_hash.lower()):
        raise CryptoError(
            f"Blob {expected_hash} does not hash to its address; refusing corrupted data"
        )
    return plaintext


# ---------------------------------------------------------------------------
# Shared manifests


def open_shared_manifest_vek(
    manifest: dict[str, Any],
    private_key_jwk: str,
    signing_public_key_b64: str | None,
    *,
    require_signature: bool = True,
) -> str:
    """Decrypt a shared manifest's VEK and, when available, verify its grant signature."""

    manifest_id = str(manifest.get("manifestId", ""))
    algorithm = manifest.get("algorithm")
    encrypted_vek = manifest.get("encryptedVek")
    recipient_public_key = manifest.get("accountPublicKey")
    if algorithm != "rsa-oaep-sha256":
        raise UnsupportedVaultError(
            f"Shared manifest {manifest_id} uses an unsupported grant algorithm: {algorithm!r}"
        )
    if not isinstance(encrypted_vek, str) or not encrypted_vek:
        raise CryptoError(
            f"Shared manifest {manifest_id} carries no encrypted vault key"
        )
    if not isinstance(recipient_public_key, str) or not recipient_public_key:
        raise CryptoError(
            f"Shared manifest {manifest_id} does not say which key its grant is for"
        )

    signature = manifest.get("grantSignature")
    signer_user_id = manifest.get("grantSignerUserId")
    key_version = manifest.get("keyVersion")
    if require_signature:
        if not signing_public_key_b64:
            raise CryptoError(
                f"Shared manifest {manifest_id} has a grant, but this account's signing key is unavailable; "
                "cannot verify the grant"
            )
        if (
            not isinstance(signature, str)
            or not signature
            or not isinstance(signer_user_id, str)
        ):
            raise CryptoError(
                f"Shared manifest {manifest_id} carries an unsigned grant; refusing it"
            )
        if not isinstance(key_version, int):
            raise CryptoError(
                f"Shared manifest {manifest_id} has no key version for its grant"
            )
        message = crypto.grant_message(
            manifest_id,
            key_version,
            signer_user_id,
            recipient_public_key,
            algorithm,
            encrypted_vek,
        )
        if not crypto.ed25519_verify(signing_public_key_b64, message, signature):
            raise CryptoError(
                f"The grant on shared manifest {manifest_id} is not signed by this account; refusing it"
            )

    return crypto.decrypt_manifest_vek(encrypted_vek, manifest_id, private_key_jwk)
