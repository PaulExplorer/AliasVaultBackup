"""Minimal client for the AliasVault Cloud API v2.

Only the endpoints needed to log in, refresh a session, fetch the encrypted
vault snapshot, and download encrypted blobs are implemented.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Self

import httpx

from . import __version__, crypto, keys, srp
from .errors import (
    ApiError,
    AuthError,
    CryptoError,
    NetworkError,
    UnsupportedVaultError,
)
from .totp import totp
from .util import b64d, strip_frame_data

DEFAULT_API_URL = "https://app.aliasvault.com/api"
MAX_BLOBS_PER_REQUEST = 1000
CLIENT_HEADER = f"avb-{__version__}"


@dataclass
class LoginResult:
    tokens: dict[str, str]
    challenge: dict[str, Any]
    unlock_key_b64: str


@dataclass
class BlobDownload:
    blobs: dict[str, dict[str, Any]]
    frame: bytes | None


class ApiClient:
    def __init__(
        self,
        api_url: str = DEFAULT_API_URL,
        *,
        timeout: float = 60.0,
        tokens: dict[str, str] | None = None,
        client_header: str = CLIENT_HEADER,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.tokens: dict[str, str] | None = dict(tokens) if tokens else None
        self.client_header = client_header
        self.http = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=15.0),
            follow_redirects=True,
            headers={
                "Accept": "application/json",
                "User-Agent": f"aliasvault-backup/{__version__}",
                "X-AliasVault-Client": client_header,
            },
        )

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # HTTP plumbing

    def _url(self, path: str) -> str:
        return f"{self.api_url}/{path.lstrip('/')}"

    @staticmethod
    def _parse_error(response: httpx.Response) -> ApiError:
        message = f"HTTP {response.status_code} from {response.request.url}"
        code: str | None = None
        details: Any = None
        try:
            body = response.json()
            if isinstance(body, dict):
                message = str(body.get("message") or body.get("error") or message)
                code = body.get("code") or body.get("errorCode")
                details = body.get("details")
        except Exception:  # noqa: BLE001
            text = response.text.strip()
            if text:
                message = text[:500]
        if response.status_code == 429:
            retry_after = response.headers.get("retry-after")
            if retry_after:
                message += f" (retry after {retry_after}s)"
        return ApiError(
            message,
            status=response.status_code,
            code=str(code) if code else None,
            details=details,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        content: bytes | None = None,
        accept: str = "application/json",
        auth: bool = True,
        retry_auth: bool = True,
    ) -> httpx.Response:
        headers = {"Accept": accept}
        if auth and self.tokens and self.tokens.get("token"):
            headers["Authorization"] = f"Bearer {self.tokens['token']}"
        try:
            response = self.http.request(
                method,
                self._url(path),
                json=json_body,
                content=content,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise NetworkError(f"Could not reach {self.api_url}: {exc}") from exc

        if response.status_code == 401 and auth and retry_auth and self.tokens:
            try:
                self.refresh()
            except AuthError as exc:
                raise AuthError(
                    "The session expired and the refresh token is no longer valid. "
                    "Run `avb login` again."
                ) from exc
            return self._request(
                method,
                path,
                json_body=json_body,
                content=content,
                accept=accept,
                auth=auth,
                retry_auth=False,
            )

        if response.status_code >= 400:
            raise self._parse_error(response)
        return response

    def _json_request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        response = self._request(method, path, **kwargs)
        try:
            body = response.json()
        except Exception as exc:
            raise ApiError(
                "The server returned a non-JSON response", status=response.status_code
            ) from exc
        if not isinstance(body, dict):
            raise ApiError(
                "The server returned an unexpected JSON response",
                status=response.status_code,
            )
        return body

    # ------------------------------------------------------------------
    # Authentication

    def login(
        self,
        username: str,
        password: str,
        *,
        remember_me: bool = True,
        totp_secret: str | None = None,
        totp_code: str | None = None,
        recovery_code: str | None = None,
    ) -> LoginResult:
        normalized = username.strip().lower()
        if not normalized:
            raise AuthError("A username (email address) is required")

        challenge = self._json_request(
            "POST",
            "v2/Auth/login",
            json_body={"username": normalized},
            auth=False,
        )
        salt = challenge.get("salt")
        settings = challenge.get("encryptionSettings")
        encryption_type = challenge.get("encryptionType")
        server_ephemeral = challenge.get("serverEphemeral")
        if not all(
            isinstance(value, str) and value
            for value in (salt, settings, encryption_type, server_ephemeral)
        ):
            raise AuthError("The server's login challenge is incomplete")
        assert isinstance(salt, str)
        assert isinstance(settings, str)
        assert isinstance(encryption_type, str)
        assert isinstance(server_ephemeral, str)

        try:
            unlock_key_b64 = keys.unlock_key_b64(password, salt, settings)
            password_hash = crypto.derive_srp_password_hash(
                b64d(unlock_key_b64), encryption_type
            )
        except CryptoError as exc:
            raise AuthError(f"Could not derive the login key: {exc}") from exc

        identity = challenge.get("srpIdentity")
        if not isinstance(identity, str) or not identity:
            identity = normalized
        private_key = srp.derive_private_key(salt, identity, password_hash)
        client_secret, client_public = srp.generate_ephemeral()
        session = srp.derive_session(
            client_secret,
            server_ephemeral,
            salt,
            identity,
            private_key,
        )
        if session.client_public.upper() != client_public.upper():
            raise AuthError("Internal SRP public ephemeral mismatch")

        login_session_id = challenge.get("loginSessionId")
        validate_body: dict[str, Any] = {
            "username": normalized,
            "rememberMe": bool(remember_me),
            "clientPublicEphemeral": session.client_public,
            "clientSessionProof": session.proof,
        }
        if isinstance(login_session_id, str) and login_session_id:
            validate_body["loginSessionId"] = login_session_id

        try:
            response = self._json_request(
                "POST",
                "v2/Auth/validate",
                json_body=validate_body,
                auth=False,
            )
        except ApiError as exc:
            if exc.status in (400, 401):
                raise AuthError("Invalid username or master password") from exc
            raise

        if response.get("requiresTwoFactor"):
            if recovery_code:
                endpoint = "v2/Auth/validate-recovery-code"
                body = {**validate_body, "recoveryCode": recovery_code}
            else:
                code = totp_code
                if not code and totp_secret:
                    code = totp(totp_secret)
                if not code:
                    raise AuthError(
                        "This account requires two-factor authentication. "
                        "Provide --totp-secret or --totp-code, or use --recovery-code."
                    )
                if not str(code).isdigit():
                    raise AuthError("The two-factor code must be numeric")
                endpoint = "v2/Auth/validate-2fa"
                body = {**validate_body, "code2Fa": int(code)}
            try:
                response = self._json_request(
                    "POST", endpoint, json_body=body, auth=False
                )
            except ApiError as exc:
                if exc.status in (400, 401):
                    raise AuthError("Two-factor authentication failed") from exc
                raise

        server_proof = response.get("serverSessionProof")
        if (
            isinstance(server_proof, str)
            and server_proof
            and not srp.verify_server_proof(
                session.client_public,
                session.proof,
                session.key,
                server_proof,
            )
        ):
            raise AuthError(
                "The server failed the SRP proof check. This can mean a wrong password, "
                "a stale login challenge, or an incompatible server."
            )

        token = response.get("token")
        if not isinstance(token, dict):
            raise AuthError("The server did not return an access token")
        access = token.get("token")
        refresh = token.get("refreshToken")
        if (
            not isinstance(access, str)
            or not isinstance(refresh, str)
            or not access
            or not refresh
        ):
            raise AuthError("The server returned an incomplete token pair")
        self.tokens = {"token": access, "refreshToken": refresh}
        return LoginResult(
            tokens=dict(self.tokens), challenge=challenge, unlock_key_b64=unlock_key_b64
        )

    def set_tokens(self, tokens: dict[str, str]) -> None:
        self.tokens = {"token": tokens["token"], "refreshToken": tokens["refreshToken"]}

    def refresh(self) -> dict[str, str]:
        if not self.tokens or not self.tokens.get("refreshToken"):
            raise AuthError("No refresh token is stored; run `avb login` again")
        try:
            body = self._json_request(
                "POST",
                "v2/Auth/refresh",
                json_body={
                    "token": self.tokens.get("token", ""),
                    "refreshToken": self.tokens["refreshToken"],
                },
                auth=False,
                retry_auth=False,
            )
        except ApiError as exc:
            if exc.status in (400, 401, 403):
                raise AuthError(
                    "The stored refresh token is no longer valid; run `avb login` again"
                ) from exc
            raise
        access = body.get("token")
        refresh = body.get("refreshToken")
        if (
            not isinstance(access, str)
            or not isinstance(refresh, str)
            or not access
            or not refresh
        ):
            raise AuthError("The server returned an incomplete refreshed token pair")
        self.tokens = {"token": access, "refreshToken": refresh}
        return dict(self.tokens)

    # ------------------------------------------------------------------
    # Vault data

    def get_unlock_method(self) -> dict[str, Any]:
        body: dict[str, Any] | None = None
        last_error: ApiError | None = None
        for endpoint in ("v2/UnlockMethod/password", "v2/VaultKey/password"):
            try:
                body = self._json_request("GET", endpoint)
                break
            except ApiError as exc:
                if exc.status == 404:
                    last_error = exc
                    continue
                raise
        if body is None:
            raise UnsupportedVaultError(
                "This server does not expose the password unlock-method endpoint. "
                "Update AliasVault or use a supported server."
            ) from last_error

        candidate: Any = body
        for wrapper in ("vaultKey", "unlockMethod", "data"):
            if wrapper in body:
                candidate = body[wrapper]
                break
        if candidate is None:
            raise UnsupportedVaultError(
                "This account has no password unlock method (legacy or keyless account)."
            )
        if not isinstance(candidate, dict):
            raise UnsupportedVaultError(
                "The server returned an unexpected unlock-method response"
            )
        if not isinstance(candidate.get("encryptedAccountKey"), str):
            raise UnsupportedVaultError(
                "The unlock method has no encrypted Account Key"
            )
        return candidate

    def get_vault(self) -> bytes:
        response = self._request(
            "GET",
            "v2/Vault",
            accept="application/octet-stream",
        )
        content = response.content
        if content.startswith(b"{") and not content.startswith(b"PK"):
            # A successful HTTP status with a JSON body means an API problem.
            try:
                body = json.loads(content)
                message = body.get("message") if isinstance(body, dict) else None
            except Exception:  # noqa: BLE001
                message = None
            raise ApiError(
                message or "The server did not return a vault frame",
                status=response.status_code,
            )
        if len(content) < 4:
            raise CryptoError("The server returned an empty or truncated vault frame")
        return content

    def download_blobs(self, manifest_id: str, hashes: Iterable[str]) -> BlobDownload:
        wanted = list(dict.fromkeys(hash for hash in hashes if hash))
        if not wanted:
            return BlobDownload(blobs={}, frame=None)

        collected: dict[str, dict[str, Any]] = {}
        data_by_hash: dict[str, bytes] = {}
        first_frame_header: dict[str, Any] | None = None

        for offset in range(0, len(wanted), MAX_BLOBS_PER_REQUEST):
            batch = wanted[offset : offset + MAX_BLOBS_PER_REQUEST]
            response = self._request(
                "POST",
                "v2/Vault/blobs/download",
                json_body={"manifestId": manifest_id, "hashes": batch},
                accept="application/octet-stream",
            )
            from .util import parse_frame

            frame = parse_frame(response.content)
            blobs = frame.get("blobs")
            if not isinstance(blobs, list):
                raise CryptoError(
                    "The server returned a blob frame without a blobs list"
                )
            if first_frame_header is None:
                first_frame_header = frame
            for blob in blobs:
                if not isinstance(blob, dict):
                    continue
                blob_hash = blob.get("hash")
                data = blob.get("_data")
                if isinstance(blob_hash, str) and isinstance(data, bytes):
                    collected[blob_hash] = blob
                    data_by_hash[blob_hash] = data

        frame_bytes: bytes | None = None
        if first_frame_header is not None:
            # Re-lay the same ciphertexts out as one valid frame. Only the frame
            # offsets change; every encrypted blob is preserved byte-for-byte.
            combined = {"blobs": []}
            frame_parts: list[bytes] = []
            for blob_hash, blob in collected.items():
                combined["blobs"].append(strip_frame_data(blob))
                frame_parts.append(data_by_hash[blob_hash])
            from .util import encode_frame

            frame_bytes = encode_frame(combined, frame_parts)

        return BlobDownload(blobs=collected, frame=frame_bytes)
