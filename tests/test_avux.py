from __future__ import annotations

import io
import zipfile

import pytest

from aliasvault_backup.avux import (
    FIELD_VALUE_ID_NAMESPACE,
    _derived_field_id,
    avux_summary,
    build_avux,
    extract_avux,
    list_items,
    read_avux,
)
from aliasvault_backup.crypto import salted_blob_hash
from aliasvault_backup.errors import CryptoError


def _row(**values):
    base = {
        "IsDeleted": 0,
        "CreatedAt": "2025-01-02 03:04:05.678",
        "UpdatedAt": "2025-01-02 03:04:06.789",
    }
    base.update(values)
    return base


def test_derived_field_id_matches_the_rust_known_answer() -> None:
    row = {
        "_manifestId": "m-1",
        "ItemId": "item-1",
        "FieldKey": "login.username",
        "FieldDefinitionId": "",
    }
    assert (
        _derived_field_id(FIELD_VALUE_ID_NAMESPACE, row, "0")
        == "f36327d9-f225-86ab-a061-1ba3a668d89a"
    )


def test_build_avux_maps_items_fields_attachments_and_logos(tmp_path) -> None:
    attachment = b"secret attachment"
    logo = b"\x89PNG\r\n\x1a\nfake"
    attachment_hash = salted_blob_hash(attachment, "00ff")
    logo_hash = salted_blob_hash(logo, "00ff")

    manifest = {
        "schemaVersion": 1,
        "manifestId": "11111111-1111-1111-1111-111111111111",
        "manifestSalt": "00ff",
        "canonicalizedAt": "2025-01-02T03:04:07.000Z",
        "tables": {
            "Items": [
                _row(
                    Id="item-1",
                    Name="Example",
                    ItemType="Login",
                    FolderId="folder-1",
                    LogoId="logo-1",
                    ArchivedAt=None,
                ),
                _row(Id="item-deleted", Name="Deleted", ItemType="Login", IsDeleted=1),
            ],
            "Folders": [
                _row(Id="folder-1", Name="Personal", ParentFolderId=None, Weight=1)
            ],
            "Tags": [_row(Id="tag-1", Name="Work", Color="#ff0000", DisplayOrder=1)],
            "ItemTags": [_row(Id="it-1", ItemId="item-1", TagId="tag-1")],
            "FieldDefinitions": [],
            "FieldValues": [
                _row(
                    Id="fv-1",
                    ItemId="item-1",
                    FieldKey="login.username",
                    FieldDefinitionId=None,
                    Value="me@example.com",
                    Weight=1,
                    ValueIndex=0,
                ),
                _row(
                    Id="fv-2",
                    ItemId="item-1",
                    FieldKey="login.password",
                    FieldDefinitionId=None,
                    Value="hunter2",
                    Weight=2,
                    ValueIndex=0,
                ),
            ],
            "FieldHistories": [
                _row(
                    Id="fh-1",
                    ItemId="item-1",
                    FieldKey="login.password",
                    FieldDefinitionId=None,
                    ValueSnapshot="old",
                    ChangedAt="2025-01-01 00:00:00",
                )
            ],
            "Attachments": [
                _row(
                    Id="att-1",
                    ItemId="item-1",
                    Filename="note.txt",
                    Blob={"__blobRef": attachment_hash, "__blobKind": "attachment"},
                )
            ],
            "TotpCodes": [
                _row(
                    Id="totp-1",
                    ItemId="item-1",
                    Name="Example",
                    SecretKey="JBSWY3DPEHPK3PXP",
                    Algorithm="SHA1",
                    Digits=6,
                    Period=30,
                )
            ],
            "Passkeys": [],
            "Logos": [
                _row(
                    Id="logo-1",
                    Kind="custom",
                    Source="example.com",
                    Name="Example",
                    MimeType="image/png",
                    FetchedAt="2025-01-01 00:00:00",
                    FileData={"__blobRef": logo_hash, "__blobKind": "logo"},
                )
            ],
        },
    }

    avux = build_avux(
        [manifest],
        {attachment_hash: attachment, logo_hash: logo},
        exported_at="2025-01-02T03:04:07.000Z",
    )
    parsed = read_avux(avux)
    assert parsed["version"] == "1.0.0"
    assert len(parsed["items"]) == 1
    item = parsed["items"][0]
    assert item["name"] == "Example"
    assert item["logoId"] == "logo-1"
    assert item["createdAt"] == "2025-01-02T03:04:05.678Z"
    assert [value["fieldKey"] for value in item["fieldValues"]] == [
        "login.username",
        "login.password",
    ]
    assert item["attachments"][0]["relativePath"] == "attachments/item-1_att-1_note.txt"
    assert item["totpCodes"][0]["secretKey"] == "JBSWY3DPEHPK3PXP"
    assert parsed["logos"][0]["relativePath"] == "logos/example.com_logo-1.png"

    with zipfile.ZipFile(io.BytesIO(avux)) as archive:
        names = set(archive.namelist())
        assert "manifest.json" in names
        assert "attachments/item-1_att-1_note.txt" in names
        assert "logos/example.com_logo-1.png" in names
        assert archive.read("attachments/item-1_att-1_note.txt") == attachment
        assert archive.read("logos/example.com_logo-1.png") == logo

    summary = avux_summary(avux)
    assert summary["items"] == 1
    assert summary["attachments"] == 1
    assert summary["logos"] == 1

    items = list_items(avux)
    assert items[0]["usernames"] == ["me@example.com"]
    assert items[0]["passwords"] == 1

    written = extract_avux(avux, tmp_path)
    assert tmp_path.joinpath("manifest.json") in written


def test_build_avux_does_not_include_unused_logos() -> None:
    manifest = {
        "schemaVersion": 1,
        "manifestId": "m",
        "manifestSalt": "00",
        "canonicalizedAt": "2025-01-01T00:00:00Z",
        "tables": {
            "Items": [_row(Id="item-1", Name="No logo", ItemType="Note", LogoId=None)],
            "Logos": [
                _row(
                    Id="logo-unused",
                    Kind="favicon",
                    Source="unused.example",
                    FileData=None,
                )
            ],
        },
    }
    parsed = read_avux(build_avux([manifest], {}))
    assert parsed["items"][0]["logoId"] is None
    assert parsed["logos"] == []


def test_canonical_rows_without_surrogate_ids_are_not_collapsed() -> None:
    manifest = {
        "schemaVersion": 1,
        "manifestId": "11111111-1111-1111-1111-111111111111",
        "manifestSalt": "00ff",
        "canonicalizedAt": "2025-01-01T00:00:00Z",
        "tables": {
            "Items": [
                _row(Id="item-1", Name="One", ItemType="Login"),
                _row(Id="item-2", Name="Two", ItemType="Login"),
            ],
            "FieldDefinitions": [
                _row(Id="fd-single", FieldType="text", IsMultiValue=0),
                _row(Id="fd-multi", FieldType="text", IsMultiValue=1),
            ],
            # Single-value rows travel without Id; multi-value rows keep it.
            "FieldValues": [
                _row(
                    ItemId="item-1", FieldKey="login.username", Value="one@example.com"
                ),
                _row(ItemId="item-1", FieldKey="login.password", Value="secret-one"),
                _row(
                    ItemId="item-2", FieldKey="login.username", Value="two@example.com"
                ),
                _row(
                    ItemId="item-1", FieldKey="login.url", Id="url-1", Value="https://a"
                ),
                _row(
                    ItemId="item-2", FieldDefinitionId="fd-single", Value="custom-one"
                ),
                _row(
                    ItemId="item-2",
                    FieldDefinitionId="fd-multi",
                    Id="custom-multi-1",
                    Value="custom-multi",
                ),
            ],
            "FieldHistories": [
                _row(
                    ItemId="item-1",
                    FieldKey="login.password",
                    ValueSnapshot="old-one",
                    ChangedAt="2025-01-01 00:00:00.000",
                ),
                _row(
                    ItemId="item-1",
                    FieldKey="login.password",
                    ValueSnapshot="newer-one",
                    ChangedAt="2025-01-02 00:00:00.000",
                ),
                _row(
                    ItemId="item-2",
                    FieldKey="login.password",
                    ValueSnapshot="old-two",
                    ChangedAt="2025-01-01 00:00:00.000",
                ),
            ],
            "Tags": [_row(Id="tag-1", Name="Shared")],
            "ItemTags": [
                _row(ItemId="item-1", TagId="tag-1"),
                _row(ItemId="item-2", TagId="tag-1"),
            ],
        },
    }

    parsed = read_avux(build_avux([manifest], {}))
    by_name = {item["name"]: item for item in parsed["items"]}

    one_values = by_name["One"]["fieldValues"]
    assert {value["fieldKey"] for value in one_values if value["fieldKey"]} == {
        "login.username",
        "login.password",
        "login.url",
    }
    assert len(by_name["Two"]["fieldValues"]) == 3
    assert len(by_name["One"]["fieldHistories"]) == 2
    assert len(by_name["Two"]["fieldHistories"]) == 1
    assert len(parsed["itemTags"]) == 2

    ids = [value["id"] for item in parsed["items"] for value in item["fieldValues"]] + [
        history["id"] for item in parsed["items"] for history in item["fieldHistories"]
    ]
    assert all(ids)
    assert len(ids) == len(set(ids))


def test_build_avux_sanitizes_user_controlled_archive_paths(tmp_path) -> None:
    data = b"attachment"
    blob_hash = salted_blob_hash(data, "00ff")
    manifest = {
        "schemaVersion": 1,
        "manifestId": "m",
        "manifestSalt": "00ff",
        "canonicalizedAt": "2025-01-01T00:00:00Z",
        "tables": {
            "Items": [
                _row(Id="item-1", Name="Unsafe", ItemType="Login", LogoId="logo-1")
            ],
            "Attachments": [
                _row(
                    Id="att-1",
                    ItemId="item-1",
                    Filename="../outside/name.txt",
                    Blob={"__blobRef": blob_hash, "__blobKind": "attachment"},
                )
            ],
            "Logos": [
                _row(
                    Id="logo-1",
                    Kind="custom",
                    Source="../../logo",
                    FileData={"__blobRef": blob_hash, "__blobKind": "logo"},
                )
            ],
        },
    }
    avux = build_avux([manifest], {blob_hash: data})
    item = read_avux(avux)["items"][0]
    relative = item["attachments"][0]["relativePath"]
    assert ".." not in relative
    assert item["attachments"][0]["filename"] == "../outside/name.txt"
    with zipfile.ZipFile(io.BytesIO(avux)) as archive:
        assert relative in archive.namelist()
    extract_avux(avux, tmp_path)


def test_extract_avux_rejects_path_traversal(tmp_path) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("manifest.json", '{"version":"1.0.0"}')
        archive.writestr("../outside.txt", b"nope")
    with pytest.raises(CryptoError, match="Unsafe path"):
        extract_avux(buffer.getvalue(), tmp_path / "out")
