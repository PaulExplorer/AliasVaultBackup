from __future__ import annotations

import stat

import pytest

from aliasvault_backup.config import AppConfig, load_config, save_config
from aliasvault_backup.errors import ConfigError
from aliasvault_backup.util import atomic_write


def test_api_url_requires_https_except_for_localhost() -> None:
    AppConfig(
        api_url="https://app.aliasvault.com/api", username="a@example.com"
    ).validate()
    AppConfig(api_url="http://localhost:8080/api", username="a@example.com").validate()
    AppConfig(api_url="http://127.0.0.1:8080/api", username="a@example.com").validate()
    with pytest.raises(ConfigError, match="https"):
        AppConfig(
            api_url="http://localhost.evil.example/api", username="a@example.com"
        ).validate()
    with pytest.raises(ConfigError, match="https"):
        AppConfig(
            api_url="http://127.0.0.1.evil.example/api", username="a@example.com"
        ).validate()
    with pytest.raises(ConfigError, match="credentials"):
        AppConfig(
            api_url="https://user:pass@example.com/api", username="a@example.com"
        ).validate()


def test_config_round_trip(tmp_path) -> None:
    path = tmp_path / "config.toml"
    config = AppConfig(
        api_url="https://app.aliasvault.com/api",
        username="a@example.com",
        backup_dir=tmp_path / "backups",
        mode="raw",
        keep=7,
        remember_me=False,
        store_password=True,
        export_password_source="stored",
        config_path=path,
        secrets_path=tmp_path / "secrets.json",
    )
    save_config(config)
    loaded = load_config(path)
    assert loaded.api_url == config.api_url
    assert loaded.username == config.username
    assert loaded.backup_dir == config.backup_dir
    assert loaded.mode == "raw"
    assert loaded.keep == 7
    assert loaded.remember_me is False
    assert loaded.store_password is True
    assert loaded.export_password_source == "stored"


def test_atomic_write_does_not_chmod_an_existing_parent(tmp_path) -> None:
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o755)
    target = parent / "output.avex"

    atomic_write(target, b"data")

    assert target.read_bytes() == b"data"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_atomic_write_creates_a_private_missing_parent(tmp_path) -> None:
    parent = tmp_path / "new" / "private"
    target = parent / "output.avex"

    atomic_write(target, b"data")

    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
