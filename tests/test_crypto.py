from __future__ import annotations

import json

import pytest

from aliasvault_backup import crypto
from aliasvault_backup.errors import CryptoError
from aliasvault_backup.util import canonical_json, content_hash


def test_salted_blob_hash_matches_rust_vector() -> None:
    assert (
        crypto.salted_blob_hash(bytes([1, 2, 3]), "00ff")
        == "4307c7b0faa3e0b307fc467d8f3c3db3cd548860c7555955b2f3f00fe70cbea1"
    )


def test_canonical_json_sorts_keys_and_keeps_array_order() -> None:
    value = {"b": 2, "a": [3, {"z": 1, "y": 2}]}
    assert canonical_json(value) == '{"a":[3,{"y":2,"z":1}],"b":2}'


def test_content_fingerprint_ignores_canonicalized_at() -> None:
    a = json.dumps(
        {"schemaVersion": 1, "canonicalizedAt": "2025-01-01T00:00:00Z", "x": 1}
    )
    b = json.dumps(
        {"schemaVersion": 1, "canonicalizedAt": "2026-01-01T00:00:00Z", "x": 1}
    )
    assert content_hash(json.loads(a)) != content_hash(json.loads(b))
    from aliasvault_backup.util import content_fingerprint

    assert content_fingerprint(a) == content_fingerprint(b)


def test_aes_gcm_round_trip_and_aad() -> None:
    key = b"\x01" * 32
    ciphertext = crypto.aes_gcm_encrypt(b"hello", key, b"aad")
    assert crypto.aes_gcm_decrypt(ciphertext, key, b"aad") == b"hello"
    with pytest.raises(CryptoError):
        crypto.aes_gcm_decrypt(ciphertext, key, b"other aad")


def test_payload_envelope_round_trip() -> None:
    payload = {"schemaVersion": 1, "manifestId": "abc", "tables": {}}
    packed = crypto.pack_payload(payload)
    unpacked = crypto.unpack_payload(packed)
    assert unpacked.value == payload
    assert unpacked.schema_version == 1


def test_payload_envelope_rejects_tampering() -> None:
    payload = {"schemaVersion": 1, "manifestId": "abc", "tables": {}}
    packed = bytearray(crypto.pack_payload(payload))
    packed[-5] ^= 1
    with pytest.raises(CryptoError):
        crypto.unpack_payload(bytes(packed))


def test_hkdf_sha256_rfc5869_vector() -> None:
    # RFC 5869 test case 1.
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert crypto.hkdf_sha256(ikm, info, length=42, salt=salt) == expected
    assert len(crypto.derive_kek(bytes(range(32)))) == 32


def test_rsa_oaep_round_trip() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    from aliasvault_backup.util import b64e_url

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_jwk = json.dumps(
        {
            "kty": "RSA",
            "n": b64e_url(key.public_key().public_numbers().n.to_bytes(256, "big")),
            "e": b64e_url(key.public_key().public_numbers().e.to_bytes(3, "big")),
            "d": b64e_url(key.private_numbers().d.to_bytes(256, "big")),
            "p": b64e_url(key.private_numbers().p.to_bytes(128, "big")),
            "q": b64e_url(key.private_numbers().q.to_bytes(128, "big")),
        }
    )
    label = b"test-label"
    ciphertext = crypto.rsa_oaep_encrypt(b"secret", private_jwk, label)
    assert crypto.rsa_oaep_decrypt(ciphertext, private_jwk, label) == b"secret"
