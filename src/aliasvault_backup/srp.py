"""SRP-6a client, compatible with AliasVault's .NET server.

The group is RFC 5054's 2048-bit group (SHA-256). Values on the wire are
uppercase hex, left-padded to the 256-byte group size. This module deliberately
implements the older RFC 2945 proof layout used by the `SecureRemotePassword`
.NET package, which AliasVault follows.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from .errors import AuthError

N_HEX = (
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050"
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50"
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8"
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B"
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748"
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6"
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6"
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
)
N = int(N_HEX, 16)
G = 2
N_BYTES = 256
G_BYTES = b"\x02"

_H_N = hashlib.sha256(N.to_bytes(N_BYTES, "big")).digest()
_H_G = hashlib.sha256(G_BYTES).digest()
_H_N_XOR_H_G = bytes(left ^ right for left, right in zip(_H_N, _H_G))


@dataclass(frozen=True)
class SrpSession:
    client_public: str
    proof: str
    key: str


def _pad(value: int) -> bytes:
    return value.to_bytes(N_BYTES, "big")


def _hash_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big")


_K = _hash_int(_pad(N) + _pad(G))


def parse_hex(value: str) -> bytes:
    text = value.strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if not text or len(text) % 2:
        raise AuthError("Invalid SRP hex value")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise AuthError("Invalid SRP hex value") from exc


def derive_private_key(salt: str, identity: str, password_hash: str) -> str:
    """x = H(salt | H(identity | ':' | password_hash)), uppercase hex."""

    salt_bytes = parse_hex(salt)
    normalized_identity = identity.lower()
    identity_hash = hashlib.sha256(
        normalized_identity.encode("utf-8") + b":" + password_hash.encode("utf-8")
    ).digest()
    return hashlib.sha256(salt_bytes + identity_hash).hexdigest().upper()


def derive_verifier(private_key: str) -> str:
    return _pad(pow(G, int.from_bytes(parse_hex(private_key), "big"), N)).hex().upper()


def generate_ephemeral(secret: bytes | None = None) -> tuple[str, str]:
    """Return ``(secret_hex, public_hex)`` for a fresh 64-byte ``a``."""

    secret_bytes = secret if secret is not None else os.urandom(64)
    if len(secret_bytes) != 64:
        raise ValueError("SRP client secret must be 64 bytes")
    a = int.from_bytes(secret_bytes, "big")
    public = pow(G, a, N)
    return secret_bytes.hex().upper(), _pad(public).hex().upper()


def derive_session(
    client_secret: str,
    server_public: str,
    salt: str,
    identity: str,
    private_key: str,
) -> SrpSession:
    """Derive the client public value, proof M1 and session key K."""

    a = int.from_bytes(parse_hex(client_secret), "big")
    b_pub = int.from_bytes(parse_hex(server_public), "big")
    x = int.from_bytes(parse_hex(private_key), "big")
    salt_bytes = parse_hex(salt)
    normalized_identity = identity.lower()

    if b_pub % N == 0:
        raise AuthError("The server sent an invalid SRP public ephemeral")

    a_pub = pow(G, a, N)
    a_pub_bytes = _pad(a_pub)
    b_pub_bytes = _pad(b_pub)

    u = _hash_int(a_pub_bytes + b_pub_bytes)
    if u == 0:
        raise AuthError("The SRP scrambling parameter is zero")

    s = pow((b_pub - _K * pow(G, x, N)) % N, a + u * x, N)
    key = hashlib.sha256(_pad(s)).digest()

    identity_hash = hashlib.sha256(normalized_identity.encode("utf-8")).digest()
    m1 = hashlib.sha256(
        _H_N_XOR_H_G + identity_hash + salt_bytes + a_pub_bytes + b_pub_bytes + key
    ).digest()

    return SrpSession(
        client_public=a_pub_bytes.hex().upper(),
        proof=m1.hex().upper(),
        key=key.hex().upper(),
    )


def verify_server_proof(
    client_public: str, client_proof: str, session_key: str, server_proof: str
) -> bool:
    a_pub = parse_hex(client_public)
    m1 = parse_hex(client_proof)
    key = parse_hex(session_key)
    expected = hashlib.sha256(a_pub + m1 + key).digest()
    return hmac.compare_digest(expected, parse_hex(server_proof))
