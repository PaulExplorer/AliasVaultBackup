"""Cryptographic primitives used by AliasVault.

Everything here follows the formats in AliasVault's Rust core:

* AES-256-GCM with a 12-byte IV, stored as ``IV | ciphertext | tag``.
* Argon2id with the parameters from the account or .avex header.
* HKDF-SHA256 with no salt and a versioned label.
* The .avex container: JSON header, delimiter, encrypted .avux ZIP.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import CryptoError, UnsupportedVaultError
from .util import (
    b64d,
    b64d_url,
    b64e,
    content_hash,
    gzip_decompress_limited,
    now_iso,
    sha256_hex,
)

IV_LENGTH = 12
KEY_LENGTH = 32

AVEX_FORMAT = "avex"
AVEX_VERSION = "1.0.0"
AVEX_DELIMITER = b"\n-----BEGIN ENCRYPTED DATA-----\n"
AVEX_KDF_TYPE = "Argon2Id"
AVEX_ALGORITHM = "AES-256-GCM"
AVEX_DEFAULT_PARAMS = {"DegreeOfParallelism": 1, "MemorySize": 262144, "Iterations": 3}
AVEX_MIN_MEMORY_KIB = 19456
AVEX_MIN_ITERATIONS = 2
AVEX_MIN_PARALLELISM = 1

# Associated data labels. Changing any of these breaks compatibility.
AAD_ACCOUNT_KEY = b"aliasvault/v1/account-key"
AAD_PERSONAL_VEK = b"aliasvault/v1/vek"
AAD_ACCOUNT_PRIVATE_KEY = b"aliasvault/v1/account-private-key"
AAD_ACCOUNT_SIGNING_PRIVATE_KEY = b"aliasvault/v1/account-signing-private-key"

KEK_INFO = b"AliasVault KEK v1"
SRP_INFO = b"AliasVault SRP v1"

ENCRYPTION_TYPE_ARGON2ID = "Argon2Id"
ENCRYPTION_TYPE_ARGON2ID_HKDF = "Argon2IdHkdf"


# ---------------------------------------------------------------------------
# Symmetric primitives


def aes_gcm_encrypt(plaintext: bytes, key: bytes, aad: bytes = b"") -> bytes:
    if len(key) != KEY_LENGTH:
        raise CryptoError(f"AES-GCM keys must be {KEY_LENGTH} bytes")
    iv = os.urandom(IV_LENGTH)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


def aes_gcm_decrypt(payload: bytes, key: bytes, aad: bytes = b"") -> bytes:
    if len(key) != KEY_LENGTH:
        raise CryptoError(f"AES-GCM keys must be {KEY_LENGTH} bytes")
    if len(payload) < IV_LENGTH + 16:
        raise CryptoError("AES-GCM ciphertext is too short")
    try:
        return AESGCM(key).decrypt(payload[:IV_LENGTH], payload[IV_LENGTH:], aad)
    except InvalidTag as exc:
        raise CryptoError(
            "AES-GCM decryption failed (wrong password/key or corrupted data)"
        ) from exc


def argon2id(
    password: bytes,
    salt: bytes,
    *,
    memory_kib: int,
    iterations: int,
    parallelism: int,
    length: int = KEY_LENGTH,
) -> bytes:
    if memory_kib < 8 * parallelism:
        raise CryptoError("Invalid Argon2 memory cost")
    if iterations < 1 or parallelism < 1:
        raise CryptoError("Invalid Argon2 cost parameters")
    try:
        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=length,
            type=Argon2Type.ID,
            version=19,
        )
    except Exception as exc:
        raise CryptoError(f"Argon2id key derivation failed: {exc}") from exc


def hkdf_sha256(
    ikm: bytes, info: bytes, length: int = KEY_LENGTH, salt: bytes | None = None
) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(
        ikm
    )


def derive_kek(unlock_key: bytes) -> bytes:
    return hkdf_sha256(unlock_key, KEK_INFO)


def derive_srp_password_hash(unlock_key: bytes, encryption_type: str) -> str:
    if encryption_type == ENCRYPTION_TYPE_ARGON2ID:
        return unlock_key.hex().upper()
    if encryption_type == ENCRYPTION_TYPE_ARGON2ID_HKDF:
        return hkdf_sha256(unlock_key, SRP_INFO).hex().upper()
    raise UnsupportedVaultError(
        f"Unsupported account encryption type: {encryption_type}"
    )


def decrypt_key(encrypted_key_b64: str, with_key_b64: str, aad: bytes) -> str:
    plaintext = aes_gcm_decrypt(b64d(encrypted_key_b64), b64d(with_key_b64), aad)
    return b64e(plaintext)


def encrypt_key(key_b64: str, with_key_b64: str, aad: bytes) -> str:
    return b64e(aes_gcm_encrypt(b64d(key_b64), b64d(with_key_b64), aad))


def decrypt_text(encrypted_b64: str, with_key_b64: str, aad: bytes) -> str:
    plaintext = aes_gcm_decrypt(b64d(encrypted_b64), b64d(with_key_b64), aad)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError("AES-GCM plaintext is not valid UTF-8") from exc


def encrypt_text(text: str, with_key_b64: str, aad: bytes) -> str:
    return b64e(aes_gcm_encrypt(text.encode("utf-8"), b64d(with_key_b64), aad))


# ---------------------------------------------------------------------------
# AAD helpers


def _normalize_id(value: str) -> str:
    return value.lower()


def aad_manifest(manifest_id: str) -> bytes:
    return f"aliasvault/v1/manifest/{_normalize_id(manifest_id)}".encode()


def aad_bucket(manifest_id: str, category: str) -> bytes:
    return f"aliasvault/v1/bucket/{_normalize_id(manifest_id)}/{category}".encode()


def aad_manifest_name(manifest_id: str) -> bytes:
    return f"aliasvault/v1/manifest-name/{_normalize_id(manifest_id)}".encode()


def aad_blob_data(manifest_id: str, blob_hash: str) -> bytes:
    return f"aliasvault/v1/blob/{_normalize_id(manifest_id)}/{_normalize_id(blob_hash)}".encode()


def aad_blob_key(manifest_id: str, blob_hash: str) -> bytes:
    return f"aliasvault/v1/blob-key/{_normalize_id(manifest_id)}/{_normalize_id(blob_hash)}".encode()


def aad_grant(manifest_id: str) -> bytes:
    return f"aliasvault/v1/grant/{_normalize_id(manifest_id)}".encode()


# ---------------------------------------------------------------------------
# Payload envelope


@dataclass(frozen=True)
class UnpackedPayload:
    value: dict[str, Any]
    json_text: str
    schema_version: int


def pack_payload(payload: dict[str, Any]) -> bytes:
    """Wrap a payload in the integrity envelope and gzip it (for tests/tools)."""

    import gzip

    envelope = {
        "schemaVersion": 1,
        "contentHash": content_hash(payload),
        "payload": payload,
    }
    return gzip.compress(
        json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        mtime=0,
    )


def unpack_payload(plain_bytes: bytes) -> UnpackedPayload:
    decompressed = gzip_decompress_limited(plain_bytes)
    try:
        envelope = json.loads(decompressed.decode("utf-8"))
    except Exception as exc:
        raise CryptoError("The decrypted payload is not valid JSON") from exc
    if not isinstance(envelope, dict):
        raise CryptoError("The encrypted payload envelope is not an object")

    version = envelope.get("schemaVersion")
    if not isinstance(version, int) or isinstance(version, bool):
        raise CryptoError("The payload envelope is missing schemaVersion")
    if version > 1:
        raise UnsupportedVaultError(
            f"This vault payload uses format version {version}; this tool reads version 1. "
            "Update aliasvault-backup to read it."
        )
    if version < 1:
        raise CryptoError(f"The payload envelope has invalid format version {version}")

    expected = envelope.get("contentHash")
    if not isinstance(expected, str) or len(expected) != 64:
        raise CryptoError("The payload envelope is missing a valid contentHash")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise CryptoError("The payload envelope has no object payload")

    actual = content_hash(payload)
    if actual != expected:
        raise CryptoError(
            "The vault payload content hash does not match; the data is corrupted. "
            f"Expected {expected}, got {actual}."
        )
    json_text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return UnpackedPayload(value=payload, json_text=json_text, schema_version=version)


def salted_blob_hash(data: bytes, manifest_salt: str) -> str:
    try:
        key = bytes.fromhex(manifest_salt)
    except ValueError as exc:
        raise CryptoError("The manifest salt is not valid hex") from exc
    if not key:
        raise CryptoError("The manifest salt is empty")
    import hmac

    return hmac.new(key, data, "sha256").hexdigest()


# ---------------------------------------------------------------------------
# .avex container


def parse_avex(data: bytes) -> tuple[dict[str, Any], bytes]:
    index = data.find(AVEX_DELIMITER)
    if index < 0:
        raise CryptoError("Invalid .avex file: header delimiter not found")
    try:
        header = json.loads(data[:index].decode("utf-8"))
    except Exception as exc:
        raise CryptoError("Invalid .avex file: the header is not valid JSON") from exc
    if not isinstance(header, dict):
        raise CryptoError("Invalid .avex file: the header is not an object")
    if header.get("format") != AVEX_FORMAT:
        raise CryptoError(f"Invalid .avex file: expected format {AVEX_FORMAT!r}")
    if header.get("version") != AVEX_VERSION:
        raise CryptoError(
            f"Unsupported .avex version {header.get('version')!r}; this tool reads {AVEX_VERSION}."
        )
    kdf = header.get("kdf")
    if (
        not isinstance(kdf, dict)
        or str(kdf.get("type", "")).lower() != AVEX_KDF_TYPE.lower()
    ):
        raise CryptoError("Unsupported .avex KDF; only Argon2id is supported")
    if not isinstance(kdf.get("salt"), str) or not isinstance(kdf.get("params"), dict):
        raise CryptoError("Invalid .avex KDF header")
    encryption = header.get("encryption")
    if (
        not isinstance(encryption, dict)
        or encryption.get("algorithm") != AVEX_ALGORITHM
    ):
        raise CryptoError("Unsupported .avex encryption algorithm")
    return header, data[index + len(AVEX_DELIMITER) :]


def avex_params(header: dict[str, Any]) -> dict[str, int]:
    params = header["kdf"]["params"]
    try:
        result = {
            "memory_kib": int(params["MemorySize"]),
            "iterations": int(params["Iterations"]),
            "parallelism": int(params["DegreeOfParallelism"]),
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise CryptoError("Invalid Argon2 parameters in the .avex header") from exc
    if result["memory_kib"] < AVEX_MIN_MEMORY_KIB:
        raise CryptoError("The .avex Argon2 memory cost is below the minimum")
    if result["iterations"] < AVEX_MIN_ITERATIONS:
        raise CryptoError("The .avex Argon2 iteration count is below the minimum")
    if result["parallelism"] < AVEX_MIN_PARALLELISM:
        raise CryptoError("The .avex Argon2 parallelism is below the minimum")
    return result


def derive_avex_key(password: str, salt: str, params: dict[str, int]) -> bytes:
    return argon2id(
        password.encode("utf-8"),
        salt.encode("utf-8"),
        memory_kib=params["memory_kib"],
        iterations=params["iterations"],
        parallelism=params["parallelism"],
    )


def decrypt_avex(data: bytes, password: str) -> bytes:
    header, payload = parse_avex(data)
    params = avex_params(header)
    key = derive_avex_key(password, header["kdf"]["salt"], params)
    return aes_gcm_decrypt(payload, key, b"")


def decrypt_avex_with_key(data: bytes, key: bytes) -> bytes:
    _header, payload = parse_avex(data)
    return aes_gcm_decrypt(payload, key, b"")


def encrypt_avex(
    avux: bytes,
    password: str,
    *,
    exported_at: str | None = None,
    app_version: str = "aliasvault-backup",
) -> bytes:
    salt = b64e(os.urandom(32))
    params = dict(AVEX_DEFAULT_PARAMS)
    key = derive_avex_key(
        password,
        salt,
        {
            "memory_kib": params["MemorySize"],
            "iterations": params["Iterations"],
            "parallelism": params["DegreeOfParallelism"],
        },
    )
    payload = aes_gcm_encrypt(avux, key, b"")

    header: dict[str, Any] = {
        "format": AVEX_FORMAT,
        "version": AVEX_VERSION,
        "kdf": {
            "type": AVEX_KDF_TYPE,
            "salt": salt,
            "params": params,
        },
        "encryption": {
            "algorithm": AVEX_ALGORITHM,
            "encryptedDataOffset": 0,
        },
        "metadata": {
            "exportedAt": exported_at or now_iso(),
            "appVersion": app_version,
        },
    }

    header_json = json.dumps(header, indent=2, ensure_ascii=False).encode("utf-8")
    while True:
        offset = len(header_json) + len(AVEX_DELIMITER)
        if header["encryption"]["encryptedDataOffset"] == offset:
            break
        header["encryption"]["encryptedDataOffset"] = offset
        header_json = json.dumps(header, indent=2, ensure_ascii=False).encode("utf-8")

    return header_json + AVEX_DELIMITER + payload


def avex_metadata(data: bytes) -> dict[str, Any]:
    header, payload = parse_avex(data)
    metadata = header.get("metadata", {})
    return {
        "header": header,
        "ciphertext_size": len(payload),
        "exported_at": metadata.get("exportedAt"),
        "app_version": metadata.get("appVersion"),
        "kdf": header["kdf"],
    }


# ---------------------------------------------------------------------------
# RSA-OAEP and Ed25519 (shared manifests / account grants)


def _jwk_int(value: str) -> int:
    return int.from_bytes(b64d_url(value), "big")


def rsa_private_key_from_jwk(jwk_text: str) -> rsa.RSAPrivateKey:
    try:
        jwk = json.loads(jwk_text)
    except json.JSONDecodeError as exc:
        raise CryptoError("The account private key is not valid JSON") from exc
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise CryptoError("The account private key is not an RSA JWK")
    try:
        n = _jwk_int(jwk["n"])
        e = _jwk_int(jwk["e"])
        d = _jwk_int(jwk["d"])
        p = _jwk_int(jwk["p"])
        q = _jwk_int(jwk["q"])
    except KeyError as exc:
        raise CryptoError("The RSA JWK is missing a required member") from exc
    dmp1 = _jwk_int(jwk["dp"]) if "dp" in jwk else d % (p - 1)
    dmq1 = _jwk_int(jwk["dq"]) if "dq" in jwk else d % (q - 1)
    iqmp = _jwk_int(jwk["qi"]) if "qi" in jwk else pow(q, -1, p)
    public_numbers = rsa.RSAPublicNumbers(e, n)
    private_numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, public_numbers)
    try:
        key = private_numbers.private_key()
    except ValueError as exc:
        raise CryptoError("The RSA private key is invalid") from exc
    if key.key_size != 2048:
        raise CryptoError("Unsupported RSA key size; AliasVault uses 2048-bit keys")
    return key


def rsa_public_key_from_jwk(jwk_text: str) -> rsa.RSAPublicKey:
    try:
        jwk = json.loads(jwk_text)
    except json.JSONDecodeError as exc:
        raise CryptoError("The RSA public key is not valid JSON") from exc
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA":
        raise CryptoError("The RSA public key is not an RSA JWK")
    try:
        return rsa.RSAPublicNumbers(_jwk_int(jwk["e"]), _jwk_int(jwk["n"])).public_key()
    except (KeyError, ValueError) as exc:
        raise CryptoError("The RSA public key is invalid") from exc


def rsa_oaep_decrypt(ciphertext_b64: str, private_key_jwk: str, label: bytes) -> bytes:
    key = rsa_private_key_from_jwk(private_key_jwk)
    try:
        return key.decrypt(
            b64d(ciphertext_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=label,
            ),
        )
    except Exception as exc:
        raise CryptoError(
            "RSA-OAEP decryption failed (wrong key or corrupted grant)"
        ) from exc


def rsa_oaep_encrypt(plaintext: bytes, public_key_jwk: str, label: bytes) -> str:
    key = rsa_public_key_from_jwk(public_key_jwk)
    ciphertext = key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=label,
        ),
    )
    return b64e(ciphertext)


def decrypt_manifest_vek(
    encrypted_vek_b64: str, manifest_id: str, private_key_jwk: str
) -> str:
    plaintext = rsa_oaep_decrypt(
        encrypted_vek_b64, private_key_jwk, aad_grant(manifest_id)
    )
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CryptoError("The decrypted manifest key is not valid text") from exc


def ed25519_public_from_private(seed_b64: str) -> str:
    seed = b64d(seed_b64)
    if len(seed) != 32:
        raise CryptoError("The Ed25519 private key must be 32 bytes")
    key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)


def ed25519_verify(public_key_b64: str, message: bytes, signature_b64: str) -> bool:
    try:
        key = ed25519.Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))
        key.verify(b64d(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, CryptoError):
        return False


def signed_message(label: str, fields: list[bytes]) -> bytes:
    output = bytearray()
    for part in [label.encode("utf-8"), *fields]:
        output += len(part).to_bytes(4, "big")
        output += part
    return bytes(output)


def grant_message(
    manifest_id: str,
    key_version: int,
    signer_user_id: str,
    recipient_public_key: str,
    algorithm: str,
    encrypted_vek: str,
) -> bytes:
    return signed_message(
        "aliasvault/v1/sig/grant",
        [
            manifest_id.lower().encode("utf-8"),
            str(key_version).encode("ascii"),
            signer_user_id.encode("utf-8"),
            recipient_public_key.encode("utf-8"),
            algorithm.encode("utf-8"),
            encrypted_vek.encode("utf-8"),
        ],
    )


def sha256_ciphertext(ciphertext: bytes) -> str:
    return sha256_hex(ciphertext)
