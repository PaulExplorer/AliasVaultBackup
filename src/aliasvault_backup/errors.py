"""Errors with stable exit codes for the command line interface."""

from __future__ import annotations

from typing import Any


class AvbError(Exception):
    """Base class for expected failures.

    ``exit_code`` is used by the CLI. Messages are written without a stack trace
    unless ``--debug`` is given.
    """

    exit_code = 1

    def __init__(self, message: str, *, details: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class ConfigError(AvbError):
    """The configuration or state is missing or invalid."""

    exit_code = 2


class AuthError(AvbError):
    """Authentication failed or a session cannot be renewed."""

    exit_code = 3


class CryptoError(AvbError):
    """Decryption failed, usually a wrong password or damaged file."""

    exit_code = 4


class UnsupportedVaultError(AvbError):
    """The vault uses a format this tool cannot process yet."""

    exit_code = 5


class ApiError(AvbError):
    """The server returned an error response."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
        details: Any = None,
    ) -> None:
        super().__init__(message, details=details)
        self.status = status
        self.code = code


class NetworkError(AvbError):
    """The server could not be reached."""

    exit_code = 6
