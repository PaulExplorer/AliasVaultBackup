"""RFC 6238 TOTP generation without extra dependencies."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from .errors import ConfigError


def _normalize_secret(secret: str) -> bytes:
    compact = "".join(secret.split()).replace("-", "").upper()
    padding = "=" * (-len(compact) % 8)
    try:
        return base64.b32decode(compact + padding, casefold=True)
    except Exception as exc:
        raise ConfigError("The TOTP secret is not valid base32") from exc


def totp(
    secret: str,
    *,
    at: float | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1",
) -> str:
    if digits not in (6, 8):
        raise ConfigError("TOTP digits must be 6 or 8")
    if period < 1:
        raise ConfigError("TOTP period must be positive")
    digest_name = algorithm.lower().replace("-", "")
    if digest_name not in ("sha1", "sha256", "sha512"):
        raise ConfigError(f"Unsupported TOTP algorithm: {algorithm}")
    counter = int((time.time() if at is None else at) // period)
    message = struct.pack(">Q", counter)
    digest = hmac.new(
        _normalize_secret(secret), message, getattr(hashlib, digest_name)
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % (10**digits):0{digits}d}"
