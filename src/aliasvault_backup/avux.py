"""Build and inspect the unencrypted .avux ZIP format.

The .avux format is AliasVault's portable export: a ``manifest.json`` plus
``attachments/...`` and ``logos/...`` files. Our builder mirrors the official
TypeScript exporter in ``AvuxExportService.ts``.
"""

from __future__ import annotations

import hashlib
import io
import json
import uuid
import zipfile
import zlib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from .errors import CryptoError
from .util import now_iso, to_iso_z, truthy

AVUX_FORMAT_VERSION = "1.0.0"

# The canonicalizer omits surrogate ids for these rows; the client derives them
# again on materialize. These values mirror AliasVault's
# vault_codec/normalize.rs and vault_model/generated.rs.
FIELD_VALUE_ID_NAMESPACE = "aliasvault:fieldvalue:v1"
FIELD_HISTORY_ID_NAMESPACE = "aliasvault:fieldhistory:v1"
SINGLE_VALUE_FIELD_KEYS = frozenset(
    {
        "login.email",
        "login.username",
        "login.password",
        "alias.first_name",
        "alias.last_name",
        "alias.gender",
        "alias.birthdate",
        "card.cardholder_name",
        "card.number",
        "card.expiry_month",
        "card.expiry_year",
        "card.cvv",
        "card.pin",
        "notes.content",
    }
)
MULTI_VALUE_FIELD_KEYS = frozenset({"login.url"})


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _as_int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _as_bool(value: Any) -> bool:
    return truthy(value)


def _cell_bytes_b64(value: Any) -> str | None:
    """Return a base64 string for a canonical byte cell.

    The canonicalizer writes inline bytes as ``{"__b64": "..."}`` and extracted
    blobs as ``{"__blobRef": "...", "__blobKind": "..."}``. Passkey columns are
    bytes and end up in the first form. A plain string is accepted because some
    older databases stored the credential id as text.
    """

    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, dict):
        encoded = value.get("__b64")
        if isinstance(encoded, str):
            return encoded or None
    return None


def _blob_ref(value: Any) -> str | None:
    if isinstance(value, dict):
        reference = value.get("__blobRef")
        if isinstance(reference, str) and reference:
            return reference
    if isinstance(value, str) and value.startswith("__"):
        return None
    return None


def _id_key(value: Any) -> str:
    return (_as_str(value) or "").strip().lower()


def _field_discriminator(row: dict[str, Any]) -> str:
    field_key = _as_str(row.get("FieldKey")) or ""
    if field_key:
        return "fk:" + field_key.lower()
    return "fd:" + _id_key(row.get("FieldDefinitionId"))


def _multi_value_definition_ids(
    manifests: list[dict[str, Any]],
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for manifest in manifests:
        manifest_id = _id_key(manifest.get("manifestId"))
        tables = manifest.get("tables")
        if not isinstance(tables, dict):
            continue
        rows = tables.get("FieldDefinitions")
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            definition_id = _id_key(row.get("Id"))
            if definition_id and truthy(row.get("IsMultiValue")):
                result.add(
                    (_id_key(row.get("ManifestId")) or manifest_id, definition_id)
                )
    return result


def _field_shape(
    row: dict[str, Any], manifest_id: str, multi_definition_ids: set[tuple[str, str]]
) -> str:
    field_key = (_as_str(row.get("FieldKey")) or "").lower()
    if field_key:
        if field_key in SINGLE_VALUE_FIELD_KEYS:
            return "single"
        if field_key in MULTI_VALUE_FIELD_KEYS:
            return "multi"
        return "unknown"
    definition_id = _id_key(row.get("FieldDefinitionId"))
    if definition_id:
        return (
            "multi"
            if (manifest_id, definition_id) in multi_definition_ids
            else "single"
        )
    return "unknown"


def _field_value_tail(row: dict[str, Any]) -> str:
    if "ValueIndex" in row:
        return str(_as_int(row.get("ValueIndex")))
    value = row.get("Value")
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _row_identity(
    table: str,
    row: dict[str, Any],
    manifest_id: str,
    multi_definition_ids: set[tuple[str, str]],
) -> str:
    row_id = _id_key(row.get("Id"))
    item_id = _id_key(row.get("ItemId"))
    field = _field_discriminator(row)
    if table == "FieldValues":
        row_manifest = _id_key(row.get("_manifestId")) or manifest_id
        shape = _field_shape(row, row_manifest, multi_definition_ids)
        if shape == "single":
            # Single-value rows travel without an id and are unique per item+field.
            return f"fv:{item_id}\x00{field}"
        if row_id:
            return f"id:{row_id}"
        return f"fv:{item_id}\x00{field}\x00{_field_value_tail(row)}"
    if table == "FieldHistories":
        changed_at = _as_str(row.get("ChangedAt")) or ""
        return f"fh:{item_id}\x00{field}\x00{changed_at}"
    if table == "ItemTags":
        return f"it:{item_id}\x00{_id_key(row.get('TagId'))}"
    if row_id:
        return f"id:{row_id}"
    material = json.dumps(
        {key: value for key, value in row.items() if key != "_manifestId"},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return f"row:{manifest_id}:{material}"


def _merge_rows(manifests: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Combine the manifest tables, keeping one row per logical identity.

    Manifests are normally disjoint, but shared manifests carry copies of tags
    and field definitions. Personal manifests are passed first, and updated
    rows win, which mirrors the client's last-write-wins materialization.

    Canonical rows for single-value fields, histories, and item-tag links have
    no surrogate ``Id`` on the wire, so their identity comes from the natural
    key instead. Treating every missing id as the same row would silently drop
    nearly all field values.
    """

    merged: dict[str, list[dict[str, Any]]] = {}
    seen: dict[str, dict[str, int]] = {}
    multi_definition_ids = _multi_value_definition_ids(manifests)

    for manifest in manifests:
        manifest_id = _id_key(manifest.get("manifestId"))
        tables = manifest.get("tables")
        if not isinstance(tables, dict):
            continue
        for table, rows in tables.items():
            if not isinstance(rows, list):
                continue
            destination = merged.setdefault(table, [])
            table_seen = seen.setdefault(table, {})
            for raw_row in rows:
                if not isinstance(raw_row, dict):
                    continue
                row = dict(raw_row)
                row["_manifestId"] = _id_key(row.get("ManifestId")) or manifest_id
                if table == "FieldValues":
                    row["_fieldShape"] = _field_shape(
                        row, row["_manifestId"], multi_definition_ids
                    )
                key = _row_identity(table, row, manifest_id, multi_definition_ids)
                if key in table_seen:
                    previous_index = table_seen[key]
                    previous = destination[previous_index]
                    previous_updated = to_iso_z(previous.get("UpdatedAt")) or ""
                    current_updated = to_iso_z(row.get("UpdatedAt")) or ""
                    if current_updated > previous_updated:
                        destination[previous_index] = row
                    continue
                table_seen[key] = len(destination)
                destination.append(row)
    return merged


def _live(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if not _as_bool(row.get("IsDeleted"))]


def _timestamp(value: Any, fallback: str) -> str:
    return to_iso_z(value) or fallback


def _derived_field_id(namespace: str, row: dict[str, Any], tail: str) -> str:
    manifest_id = _id_key(row.get("_manifestId") or row.get("ManifestId"))
    item_id = _id_key(row.get("ItemId"))
    field = _field_discriminator(row)
    material = f"{namespace}\n{manifest_id}\n{item_id}\n{field}\n{tail}"
    digest = hashlib.sha256(material.encode("utf-8")).digest()
    raw = bytearray(digest[:16])
    raw[6] = (raw[6] & 0x0F) | 0x80
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(raw)))


def _field_value_id(row: dict[str, Any]) -> str:
    return _derived_field_id(
        FIELD_VALUE_ID_NAMESPACE, row, str(_as_int(row.get("ValueIndex")))
    )


def _field_history_id(row: dict[str, Any]) -> str:
    changed_at = _as_str(row.get("ChangedAt")) or ""
    return _derived_field_id(FIELD_HISTORY_ID_NAMESPACE, row, changed_at)


def _field_value(row: dict[str, Any]) -> dict[str, Any]:
    # The canonical wire format omits the id of a single-value row, so derive
    # it even if a non-canonical snapshot still carries one. Multi-value and
    # unknown rows keep their own id when they have one.
    explicit_id = None if row.get("_fieldShape") == "single" else _as_str(row.get("Id"))
    return {
        "id": explicit_id or _field_value_id(row),
        "fieldKey": _as_str(row.get("FieldKey")),
        "fieldDefinitionId": _as_str(row.get("FieldDefinitionId")),
        "value": _as_str(row.get("Value")),
        "weight": _as_int(row.get("Weight")),
    }


def _field_history(row: dict[str, Any], fallback: str) -> dict[str, Any]:
    # Canonical field-history rows never carry a surrogate id.
    return {
        "id": _field_history_id(row),
        "fieldKey": _as_str(row.get("FieldKey")),
        "fieldDefinitionId": _as_str(row.get("FieldDefinitionId")),
        "valueSnapshot": _as_str(row.get("ValueSnapshot")) or "",
        "changedAt": _timestamp(row.get("ChangedAt"), fallback),
    }


def _archive_component(value: str, fallback: str) -> str:
    """Make a user-controlled database value safe as one ZIP path component.

    Attachment filenames and logo sources are user data. The official exporter
    interpolates them directly, but a slash or ``..`` would create a nested or
    traversing path. Keep the manifest's original filename, but sanitize the
    archive path.
    """

    cleaned = value.replace("\\", "_").replace("/", "_").replace("\x00", "_").strip()
    cleaned = cleaned.replace("..", "_")
    return cleaned or fallback


def attachment_path(item_id: str, attachment_id: str, filename: str) -> str:
    safe_filename = _archive_component(filename, "attachment")
    return f"attachments/{item_id}_{attachment_id}_{safe_filename}"


def logo_path(source: str, logo_id: str) -> str:
    safe_source = _archive_component(source, "logo")
    return f"logos/{safe_source}_{logo_id}.png"


def _attachment(row: dict[str, Any], item_id: str) -> dict[str, Any]:
    attachment_id = _as_str(row.get("Id")) or ""
    filename = _as_str(row.get("Filename")) or ""
    return {
        "id": attachment_id,
        "filename": filename,
        "relativePath": attachment_path(item_id, attachment_id, filename),
    }


def _totp(row: dict[str, Any]) -> dict[str, Any]:
    algorithm = _as_str(row.get("Algorithm")) or "SHA1"
    return {
        "id": _as_str(row.get("Id")) or "",
        "name": _as_str(row.get("Name")) or "",
        "secretKey": _as_str(row.get("SecretKey")) or "",
        "algorithm": algorithm,
        "digits": _as_int(row.get("Digits"), 6),
        "period": _as_int(row.get("Period"), 30),
    }


def _passkey(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _as_str(row.get("Id")) or "",
        "credentialId": _cell_bytes_b64(row.get("CredentialId")),
        "rpId": _as_str(row.get("RpId")) or "",
        "userHandle": _cell_bytes_b64(row.get("UserHandle")),
        "publicKey": _as_str(row.get("PublicKey")) or "",
        "privateKey": _as_str(row.get("PrivateKey")) or "",
        "prfKey": _cell_bytes_b64(row.get("PrfKey")),
        "displayName": _as_str(row.get("DisplayName")) or "",
        "additionalData": _cell_bytes_b64(row.get("AdditionalData")),
    }


def _folder(row: dict[str, Any], fallback: str) -> dict[str, Any]:
    return {
        "id": _as_str(row.get("Id")) or "",
        "name": _as_str(row.get("Name")) or "",
        "parentFolderId": _as_str(row.get("ParentFolderId")),
        "weight": _as_int(row.get("Weight")),
        "createdAt": _timestamp(row.get("CreatedAt"), fallback),
        "updatedAt": _timestamp(row.get("UpdatedAt"), fallback),
    }


def _tag(row: dict[str, Any], fallback: str) -> dict[str, Any]:
    return {
        "id": _as_str(row.get("Id")) or "",
        "name": _as_str(row.get("Name")) or "",
        "color": _as_str(row.get("Color")),
        "displayOrder": _as_int(row.get("DisplayOrder")),
        "createdAt": _timestamp(row.get("CreatedAt"), fallback),
        "updatedAt": _timestamp(row.get("UpdatedAt"), fallback),
    }


def _field_definition(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _as_str(row.get("Id")) or "",
        "fieldType": _as_str(row.get("FieldType")) or "",
        "label": _as_str(row.get("Label")) or "",
        "isMultiValue": _as_bool(row.get("IsMultiValue")),
        "isHidden": _as_bool(row.get("IsHidden")),
        "enableHistory": _as_bool(row.get("EnableHistory")),
        "weight": _as_int(row.get("Weight")),
        "applicableToTypes": _as_str(row.get("ApplicableToTypes")),
    }


def _logo(row: dict[str, Any], fallback: str) -> dict[str, Any]:
    source = _as_str(row.get("Source")) or ""
    logo_id = _as_str(row.get("Id")) or ""
    return {
        "id": logo_id,
        "kind": _as_str(row.get("Kind")) or "favicon",
        "source": source,
        "name": _as_str(row.get("Name")),
        "mimeType": _as_str(row.get("MimeType")),
        "fetchedAt": to_iso_z(row.get("FetchedAt")),
        "relativePath": logo_path(source, logo_id),
    }


def build_avux(
    manifests: list[dict[str, Any]],
    blobs: dict[str, bytes],
    *,
    exported_at: str | None = None,
) -> bytes:
    """Build a .avux ZIP from decrypted manifest payloads and blob plaintexts."""

    fallback = exported_at or now_iso()
    tables = _merge_rows(manifests)

    items = _live(tables.get("Items", []))
    folders = _live(tables.get("Folders", []))
    tags = _live(tables.get("Tags", []))
    item_tags = _live(tables.get("ItemTags", []))
    field_definitions = _live(tables.get("FieldDefinitions", []))
    field_values = _live(tables.get("FieldValues", []))
    field_histories = _live(tables.get("FieldHistories", []))
    attachments = _live(tables.get("Attachments", []))
    totp_codes = _live(tables.get("TotpCodes", []))
    passkeys = _live(tables.get("Passkeys", []))
    logos = _live(tables.get("Logos", []))

    logos_by_id = {
        _as_str(logo.get("Id")): logo for logo in logos if _as_str(logo.get("Id"))
    }

    def rows_by_item(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            item_id = _as_str(row.get("ItemId"))
            if item_id:
                result.setdefault(item_id, []).append(row)
        return result

    values_by_item = rows_by_item(field_values)
    histories_by_item = rows_by_item(field_histories)
    attachments_by_item = rows_by_item(attachments)
    totp_by_item = rows_by_item(totp_codes)
    passkeys_by_item = rows_by_item(passkeys)

    archive_files: dict[str, bytes] = {}
    avux_items: list[dict[str, Any]] = []
    used_logo_ids: set[str] = set()

    for item in sorted(
        items,
        key=lambda row: (
            (_as_str(row.get("Name")) or "").casefold(),
            _as_str(row.get("Id")) or "",
        ),
    ):
        item_id = _as_str(item.get("Id")) or ""
        logo_id = _as_str(item.get("LogoId"))
        logo = logos_by_id.get(logo_id) if logo_id else None
        if logo is not None and logo_id is not None:
            used_logo_ids.add(logo_id)

        item_values = sorted(
            values_by_item.get(item_id, []),
            key=lambda row: (
                _as_int(row.get("Weight")),
                _as_int(row.get("ValueIndex")),
                _as_str(row.get("Id")) or "",
            ),
        )
        item_histories = sorted(
            histories_by_item.get(item_id, []),
            key=lambda row: (
                to_iso_z(row.get("ChangedAt")) or "",
                _as_str(row.get("Id")) or "",
            ),
        )
        item_attachments = sorted(
            attachments_by_item.get(item_id, []),
            key=lambda row: (
                _as_str(row.get("Filename")) or "",
                _as_str(row.get("Id")) or "",
            ),
        )
        item_totps = sorted(
            totp_by_item.get(item_id, []),
            key=lambda row: (
                _as_str(row.get("Name")) or "",
                _as_str(row.get("Id")) or "",
            ),
        )
        item_passkeys = sorted(
            passkeys_by_item.get(item_id, []),
            key=lambda row: (
                _as_str(row.get("DisplayName")) or "",
                _as_str(row.get("Id")) or "",
            ),
        )

        avux_attachments = [_attachment(row, item_id) for row in item_attachments]
        for row, mapped in zip(item_attachments, avux_attachments):
            reference = _blob_ref(row.get("Blob")) or _as_str(row.get("BlobHash"))
            if reference and reference in blobs:
                archive_files[mapped["relativePath"]] = blobs[reference]

        avux_items.append(
            {
                "id": item_id,
                "name": _as_str(item.get("Name")),
                "itemType": _as_str(item.get("ItemType")) or "Login",
                "createdAt": _timestamp(item.get("CreatedAt"), fallback),
                "updatedAt": _timestamp(item.get("UpdatedAt"), fallback),
                "folderId": _as_str(item.get("FolderId")),
                "logoId": logo_id if logo is not None else None,
                "archivedAt": to_iso_z(item.get("ArchivedAt")),
                "fieldValues": [_field_value(row) for row in item_values],
                "fieldHistories": [
                    _field_history(row, fallback) for row in item_histories
                ],
                "attachments": avux_attachments,
                "totpCodes": [_totp(row) for row in item_totps],
                "passkeys": [_passkey(row) for row in item_passkeys],
            }
        )

    avux_logos: list[dict[str, Any]] = []
    for logo in sorted(
        logos,
        key=lambda row: (
            _as_str(row.get("Source")) or "",
            _as_str(row.get("Id")) or "",
        ),
    ):
        logo_id = _as_str(logo.get("Id")) or ""
        if logo_id not in used_logo_ids:
            continue
        mapped = _logo(logo, fallback)
        avux_logos.append(mapped)
        reference = _blob_ref(logo.get("FileData")) or _as_str(logo.get("FileDataHash"))
        if reference and reference in blobs:
            archive_files[mapped["relativePath"]] = blobs[reference]

    avux_folders = sorted(
        (_folder(row, fallback) for row in folders),
        key=lambda row: (row["weight"], row["name"].casefold(), row["id"]),
    )
    avux_tags = sorted(
        (_tag(row, fallback) for row in tags),
        key=lambda row: (row["displayOrder"], row["name"].casefold(), row["id"]),
    )
    avux_item_tags = sorted(
        (
            {
                "id": str(uuid.uuid4()),
                "itemId": _as_str(row.get("ItemId")) or "",
                "tagId": _as_str(row.get("TagId")) or "",
            }
            for row in item_tags
        ),
        key=lambda row: (row["itemId"], row["tagId"]),
    )
    avux_field_definitions = sorted(
        (_field_definition(row) for row in field_definitions),
        key=lambda row: (row["weight"], row["label"].casefold(), row["id"]),
    )

    manifest = {
        "version": AVUX_FORMAT_VERSION,
        "exportedAt": fallback,
        "items": avux_items,
        "folders": avux_folders,
        "tags": avux_tags,
        "itemTags": avux_item_tags,
        "fieldDefinitions": avux_field_definitions,
        "logos": avux_logos,
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "manifest.json",
            json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"),
        )
        for path, data in archive_files.items():
            archive.writestr(path, data)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Reading an .avux (for verify/decrypt)


def read_avux(avux: bytes) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(io.BytesIO(avux)) as archive:
            names = archive.namelist()
            for name in names:
                if not name.endswith("/"):
                    _safe_relative_path(name)
            if "manifest.json" not in names:
                raise CryptoError("The .avux archive has no manifest.json")
            manifest = json.loads(archive.read("manifest.json"))
    except (
        zipfile.BadZipFile,
        KeyError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        RuntimeError,
        zlib.error,
    ) as exc:
        raise CryptoError("The .avux archive is invalid or damaged") from exc
    if not isinstance(manifest, dict):
        raise CryptoError("The .avux manifest is not an object")
    if manifest.get("version") != AVUX_FORMAT_VERSION:
        raise CryptoError(f"Unsupported .avux version: {manifest.get('version')!r}")
    return manifest


def avux_summary(avux: bytes) -> dict[str, Any]:
    manifest = read_avux(avux)
    with zipfile.ZipFile(io.BytesIO(avux)) as archive:
        names = archive.namelist()
    raw_items = manifest.get("items")
    items = raw_items if isinstance(raw_items, list) else []

    def attachment_count(item: Any) -> int:
        if not isinstance(item, dict):
            return 0
        attachments = item.get("attachments")
        return len(attachments) if isinstance(attachments, list) else 0

    attachments = sum(attachment_count(item) for item in items)
    return {
        "version": manifest.get("version"),
        "exportedAt": manifest.get("exportedAt"),
        "items": len(items),
        "folders": len(manifest.get("folders") or []),
        "tags": len(manifest.get("tags") or []),
        "fieldDefinitions": len(manifest.get("fieldDefinitions") or []),
        "logos": len(manifest.get("logos") or []),
        "attachments": attachments,
        "files": len(names),
    }


def _safe_relative_path(name: str) -> PurePosixPath:
    if "\x00" in name or "\\" in name:
        raise CryptoError(f"Unsafe path in the .avux archive: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise CryptoError(f"Unsafe path in the .avux archive: {name!r}")
    return path


def extract_avux(
    avux: bytes, destination: Path, *, overwrite: bool = False
) -> list[Path]:
    """Extract an .avux safely into a directory."""

    if destination.exists() and not destination.is_dir():
        raise CryptoError(f"Extraction destination is not a directory: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    try:
        destination.chmod(0o700)
    except OSError:
        pass
    written: list[Path] = []
    with zipfile.ZipFile(io.BytesIO(avux)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            relative = _safe_relative_path(info.filename)
            target = destination.joinpath(*relative.parts)
            if target.exists() and not overwrite:
                raise CryptoError(f"Refusing to overwrite existing file: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.parent.chmod(0o700)
            except OSError:
                pass
            with archive.open(info) as source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
            try:
                target.chmod(0o600)
            except OSError:
                pass
            written.append(target)
    return written


def list_items(avux: bytes) -> list[dict[str, Any]]:
    manifest = read_avux(avux)
    result = []
    for item in manifest.get("items") or []:
        if not isinstance(item, dict):
            continue
        usernames = []
        passwords = 0
        for value in item.get("fieldValues") or []:
            if not isinstance(value, dict):
                continue
            key = value.get("fieldKey")
            content = value.get("value")
            if key == "login.username" and content:
                usernames.append(content)
            if key == "login.password" and content:
                passwords += 1
        result.append(
            {
                "name": item.get("name"),
                "type": item.get("itemType"),
                "usernames": usernames,
                "passwords": passwords,
                "attachments": len(item.get("attachments") or []),
                "totp": len(item.get("totpCodes") or []),
                "passkeys": len(item.get("passkeys") or []),
            }
        )
    return result
