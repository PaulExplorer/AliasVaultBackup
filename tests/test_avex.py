from __future__ import annotations

from pathlib import Path

from aliasvault_backup import crypto

FIXTURE = Path(__file__).parent / "fixtures" / "official-0.28.0.avex"
PASSWORD = "testexportpass123"


def test_official_avex_fixture_decrypts() -> None:
    data = FIXTURE.read_bytes()
    metadata = crypto.avex_metadata(data)
    assert metadata["header"]["format"] == "avex"
    assert metadata["header"]["kdf"]["type"] == "Argon2Id"

    avux = crypto.decrypt_avex(data, PASSWORD)
    assert avux.startswith(b"PK\x03\x04")

    import io
    import json
    import zipfile

    with zipfile.ZipFile(io.BytesIO(avux)) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["version"] == "1.0.0"
    assert len(manifest["items"]) == 7
    assert any(name.startswith("attachments/") for name in names)
    assert any(name.startswith("logos/") for name in names)


def test_avex_round_trip() -> None:

    # Small synthetic .avux ZIP; the container does not care about its contents.
    avux = b"PK\x05\x06" + b"\x00" * 18
    encrypted = crypto.encrypt_avex(avux, "correct horse battery staple")
    assert crypto.decrypt_avex(encrypted, "correct horse battery staple") == avux

    import pytest

    from aliasvault_backup.errors import CryptoError

    with pytest.raises(CryptoError):
        crypto.decrypt_avex(encrypted, "wrong password")


def test_avex_encrypt_has_stable_offset() -> None:
    encrypted = crypto.encrypt_avex(b"payload", "password")
    header, payload = crypto.parse_avex(encrypted)
    assert header["encryption"]["encryptedDataOffset"] == len(encrypted) - len(payload)
