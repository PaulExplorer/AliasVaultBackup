"""Configuration and private state paths."""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import ConfigError
from .util import atomic_write, ensure_private_dir

APP_NAME = "aliasvault-backup"
DEFAULT_API_URL = "https://app.aliasvault.com/api"
DEFAULT_BACKUP_DIR = Path.home() / "AliasVaultBackups"
VALID_MODES = ("avex", "raw", "both")
VALID_EXPORT_SOURCES = ("master", "stored", "env", "prompt")


def default_config_dir() -> Path:
    override = os.environ.get("AVB_CONFIG_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser() / APP_NAME
    return Path.home() / ".config" / APP_NAME


def default_config_path() -> Path:
    return default_config_dir() / "config.toml"


def default_secrets_path(config_path: Path) -> Path:
    override = os.environ.get("AVB_SECRETS_FILE")
    if override:
        return Path(override).expanduser()
    return config_path.parent / "secrets.json"


@dataclass
class AppConfig:
    api_url: str = DEFAULT_API_URL
    username: str = ""
    backup_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("AVB_BACKUP_DIR", str(DEFAULT_BACKUP_DIR))
        ).expanduser()
    )
    mode: str = "both"
    keep: int = 30
    remember_me: bool = True
    store_password: bool = False
    export_password_source: str = "master"
    config_path: Path = field(default_factory=default_config_path)
    secrets_path: Path = field(
        default_factory=lambda: default_secrets_path(default_config_path())
    )

    @property
    def config_dir(self) -> Path:
        return self.config_path.parent

    def validate(self) -> None:
        if self.mode not in VALID_MODES:
            raise ConfigError(f"mode must be one of {', '.join(VALID_MODES)}")
        if self.export_password_source not in VALID_EXPORT_SOURCES:
            raise ConfigError(
                f"export_password_source must be one of {', '.join(VALID_EXPORT_SOURCES)}"
            )
        if self.keep < 0:
            raise ConfigError("keep must be zero or positive")
        parsed = urlparse(str(self.api_url))
        local_http = parsed.scheme == "http" and parsed.hostname in (
            "localhost",
            "127.0.0.1",
            "::1",
        )
        if parsed.scheme != "https" and not local_http:
            raise ConfigError(
                "api_url must use https:// (except for a localhost test server)"
            )
        if not parsed.netloc:
            raise ConfigError("api_url must include a host name")
        if parsed.username or parsed.password:
            raise ConfigError("api_url must not contain credentials")
        if not self.username:
            raise ConfigError("No username is configured. Run `avb login` first.")


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, int):
        return value != 0
    return default


def load_config(path: Path | None = None) -> AppConfig:
    config_path = (path or default_config_path()).expanduser()
    config = AppConfig(
        config_path=config_path,
        secrets_path=default_secrets_path(config_path),
    )
    if not config_path.exists():
        return config
    try:
        with config_path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{config_path} is not a TOML table")

    if isinstance(data.get("api_url"), str):
        config.api_url = data["api_url"].rstrip("/")
    if isinstance(data.get("username"), str):
        config.username = data["username"].strip().lower()
    if isinstance(data.get("backup_dir"), str):
        config.backup_dir = Path(data["backup_dir"]).expanduser()
    if isinstance(data.get("mode"), str):
        config.mode = data["mode"]
    if isinstance(data.get("keep"), int) and not isinstance(data.get("keep"), bool):
        config.keep = data["keep"]
    elif isinstance(data.get("keep"), str) and data["keep"].isdigit():
        config.keep = int(data["keep"])
    config.remember_me = _coerce_bool(data.get("remember_me"), config.remember_me)
    config.store_password = _coerce_bool(
        data.get("store_password"), config.store_password
    )
    if isinstance(data.get("export_password_source"), str):
        config.export_password_source = data["export_password_source"]
    return config


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def save_config(config: AppConfig) -> None:
    config.validate()
    lines = [
        "# AliasVault backup configuration",
        f"api_url = {_toml_value(config.api_url)}",
        f"username = {_toml_value(config.username)}",
        f"backup_dir = {_toml_value(str(config.backup_dir))}",
        f"mode = {_toml_value(config.mode)}",
        f"keep = {_toml_value(config.keep)}",
        f"remember_me = {_toml_value(config.remember_me)}",
        f"store_password = {_toml_value(config.store_password)}",
        f"export_password_source = {_toml_value(config.export_password_source)}",
        "",
    ]
    ensure_private_dir(config.config_path.parent)
    atomic_write(config.config_path, "\n".join(lines).encode("utf-8"), mode=0o600)
