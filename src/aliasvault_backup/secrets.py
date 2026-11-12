"""Private state: tokens, optional passwords, and cached vault keys."""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .util import atomic_write, ensure_private_dir, read_json


@dataclass
class Secrets:
    tokens: dict[str, str] | None = None
    master_password: str | None = None
    export_password: str | None = None
    totp_secret: str | None = None
    veks: dict[str, str] = field(default_factory=dict)
    was_insecure: bool = False

    @property
    def has_tokens(self) -> bool:
        return bool(
            self.tokens
            and isinstance(self.tokens.get("token"), str)
            and isinstance(self.tokens.get("refreshToken"), str)
        )


class SecretStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser()

    def load(self) -> Secrets:
        if not self.path.exists():
            return Secrets()
        try:
            data = read_json(self.path)
        except Exception as exc:
            raise ConfigError(f"Cannot read secrets file {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"Secrets file {self.path} is not a JSON object")

        insecure = False
        try:
            mode = stat.S_IMODE(self.path.stat().st_mode)
            if mode & 0o077:
                insecure = True
                self.path.chmod(0o600)
        except OSError:
            pass

        tokens = data.get("tokens")
        if not isinstance(tokens, dict):
            tokens = None
        else:
            tokens = {
                "token": str(tokens.get("token", "")),
                "refreshToken": str(tokens.get("refreshToken", "")),
            }
            if not all(tokens.values()):
                tokens = None

        veks_raw = data.get("veks")
        veks: dict[str, str] = {}
        if isinstance(veks_raw, dict):
            for key, value in veks_raw.items():
                if isinstance(key, str) and isinstance(value, str):
                    veks[key] = value

        return Secrets(
            tokens=tokens,
            master_password=_optional_str(data.get("masterPassword")),
            export_password=_optional_str(data.get("exportPassword")),
            totp_secret=_optional_str(data.get("totpSecret")),
            veks=veks,
            was_insecure=insecure,
        )

    def save(self, secrets: Secrets) -> None:
        data: dict[str, Any] = {}
        if secrets.tokens:
            data["tokens"] = secrets.tokens
        if secrets.master_password:
            data["masterPassword"] = secrets.master_password
        if secrets.export_password:
            data["exportPassword"] = secrets.export_password
        if secrets.totp_secret:
            data["totpSecret"] = secrets.totp_secret
        if secrets.veks:
            data["veks"] = secrets.veks

        ensure_private_dir(self.path.parent)
        payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
        atomic_write(self.path, payload, mode=0o600)

    def delete(self) -> None:
        try:
            self.path.unlink()
        except FileNotFoundError:
            return


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
