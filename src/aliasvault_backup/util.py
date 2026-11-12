"""Small helpers shared by the crypto, vault and CLI modules."""

from __future__ import annotations

import base64
import datetime as _dt
import json
import math
import os
import re
import struct
import tempfile
import zlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .errors import CryptoError

# ---------------------------------------------------------------------------
# Encoding


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise CryptoError("A value is not valid base64") from exc


def b64e_url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64d_url(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    import hashlib
    import hmac

    return hmac.new(key, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Canonical JSON (matches AliasVault's Rust `vault_codec::hash::canonical_json`)


def _canonical_float(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        # serde_json refuses non-finite numbers; vault payloads never contain them.
        return "null"
    text = repr(value)
    # ryu (used by serde_json) writes exponents without a plus and without
    # leading zeroes: 1e+20 -> 1e20, 1e-07 -> 1e-7.
    match = re.match(r"^(.*?)[eE]([+-]?)(\d+)$", text)
    if match:
        mantissa, sign, exponent = match.groups()
        exponent = exponent.lstrip("0") or "0"
        text = f"{mantissa}e{'-' if sign == '-' else ''}{exponent}"
    return text


def _canonical_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_json(value: Any) -> str:
    """Render JSON the way Rust's canonical_json does.

    Object keys are sorted recursively, arrays keep their order, and primitives
    use the compact serde_json rendering. This exact string is hashed by the
    vault format, so it must not be replaced with a pretty-printed form.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _canonical_float(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            parts.append(_canonical_string(key) + ":" + canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"Unsupported JSON value: {type(value)!r}")


def content_hash(value: Any) -> str:
    return sha256_hex(canonical_json(value).encode("utf-8"))


def content_fingerprint(payload_json: str) -> str:
    """SHA-256 of the canonical payload without the volatile canonicalizedAt."""

    value = json.loads(payload_json)
    if isinstance(value, dict):
        value.pop("canonicalizedAt", None)
    return content_hash(value)


# ---------------------------------------------------------------------------
# Time


def now_iso() -> str:
    now = _dt.datetime.now(_dt.UTC)
    return _format_iso_z(now)


def _format_iso_z(value: _dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=_dt.UTC)
    value = value.astimezone(_dt.UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def to_iso_z(value: Any) -> str | None:
    """Normalize a database timestamp to the ISO form JavaScript emits.

    AliasVault's SQLite timestamps are ISO-like strings. The .avux exporter
    calls `Date.toISOString()`, which always uses UTC and milliseconds.
    """

    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return _format_iso_z(value)
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    if not text:
        return None
    candidate = text
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    # SQLite commonly uses a space between the date and the time.
    if len(candidate) > 10 and candidate[10] == " ":
        candidate = candidate[:10] + "T" + candidate[11:]
    try:
        parsed = _dt.datetime.fromisoformat(candidate)
    except ValueError:
        # A date-only value is still meaningful for a birthdate field.
        try:
            parsed_date = _dt.date.fromisoformat(candidate)
        except ValueError:
            return text
        parsed = _dt.datetime(parsed_date.year, parsed_date.month, parsed_date.day)
    return _format_iso_z(parsed)


def jwt_expiry(token: str | None) -> _dt.datetime | None:
    """Read the exp claim of a JWT without verifying it (display only)."""

    if not token:
        return None
    try:
        payload = token.split(".")[1]
        padding = "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload + padding))
        return _dt.datetime.fromtimestamp(int(data["exp"]), tz=_dt.UTC)
    except Exception:  # noqa: BLE001 - best effort only
        return None


# ---------------------------------------------------------------------------
# Bytes and files


def gzip_decompress_limited(data: bytes, limit: int = 512 * 1024 * 1024) -> bytes:
    """Decompress a gzip stream while refusing obvious decompression bombs."""

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = decompressor.decompress(data, limit + 1)
    except zlib.error as exc:
        raise CryptoError("The encrypted payload is not valid gzip data") from exc
    if len(output) > limit:
        raise CryptoError("The decrypted payload is larger than the supported limit")
    if not decompressor.eof:
        raise CryptoError("The encrypted payload is a truncated gzip stream")
    return output


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write a file atomically with restrictive permissions."""

    # The caller may be writing to a directory the user chose (for example
    # `.avex` output in the current directory). Create a missing directory with
    # private permissions, but never loosen or tighten an existing one; that is
    # the job of the dedicated config/backup-directory checks.
    if not path.parent.exists():
        ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    data = json.dumps(value, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    atomic_write(path, data, mode=mode)


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# Vault binary frames


def parse_frame(data: bytes) -> dict[str, Any]:
    """Parse a v2 vault frame and attach each part's ciphertext as ``_data``.

    Layout: 4-byte big-endian header length, JSON header, then the ciphertexts
    addressed by each part's ``offset`` and ``size``.
    """

    if len(data) < 4:
        raise CryptoError("Response is not a binary frame: no header length")
    (header_length,) = struct.unpack(">I", data[:4])
    if header_length > len(data) - 4:
        raise CryptoError("Response is not a binary frame: header exceeds the body")
    header_bytes = data[4 : 4 + header_length]
    body = data[4 + header_length :]
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise CryptoError(
            "Response is not a binary frame: invalid JSON header"
        ) from exc
    if not isinstance(header, dict):
        raise CryptoError("Response is not a binary frame: header is not an object")

    for group in ("manifests", "buckets", "blobs"):
        parts = header.get(group)
        if not isinstance(parts, list):
            continue
        for part in parts:
            if not isinstance(part, dict):
                continue
            offset = part.get("offset", 0)
            size = part.get("size", 0)
            if (
                not isinstance(offset, int)
                or isinstance(offset, bool)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or offset < 0
                or size < 0
            ):
                raise CryptoError("Response frame carries invalid offsets")
            end = offset + size
            if end > len(body):
                raise CryptoError("Response frame ciphertext exceeds the body")
            part["_data"] = body[offset:end]
    return header


def strip_frame_data(value: Any) -> Any:
    """Deep-copy a frame header without the private ``_data`` keys."""

    if isinstance(value, dict):
        return {
            key: strip_frame_data(item) for key, item in value.items() if key != "_data"
        }
    if isinstance(value, list):
        return [strip_frame_data(item) for item in value]
    return value


def encode_frame(header: dict[str, Any], parts: Iterable[bytes]) -> bytes:
    """Build a frame for tests or future write support."""

    part_list = list(parts)
    offset = 0
    # Caller puts the part metadata in the header already; walk the known groups
    # in serialization order and assign offsets.
    entries: list[dict[str, Any]] = []
    for group in ("manifests", "buckets", "blobs"):
        entries.extend(item for item in header.get(group, []) if isinstance(item, dict))
    if len(entries) != len(part_list):
        raise ValueError("header part count does not match data part count")
    for entry, payload in zip(entries, part_list):
        entry["offset"] = offset
        entry["size"] = len(payload)
        offset += len(payload)
    header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    return struct.pack(">I", len(header_bytes)) + header_bytes + b"".join(part_list)


# ---------------------------------------------------------------------------
# Misc


def truthy(value: Any) -> bool:
    """SQLite-tolerant truthiness, matching the Rust codec."""

    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value == "1" or value.lower() == "true"
    return False


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def slugify(value: str, *, default: str = "vault") -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return slug or default
