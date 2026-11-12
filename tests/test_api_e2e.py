from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

import pytest
from test_offline_flow import _make_vault

from aliasvault_backup import crypto, keys, srp


class _Handler(BaseHTTPRequestHandler):
    vault_key: dict
    snapshot_raw: bytes
    manifest_id: str
    blobs: dict
    blob_frame: bytes
    password: str
    sessions: ClassVar[dict[str, dict]] = {}

    def log_message(self, _format, *_args):
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        return json.loads(raw) if raw else {}

    def _json(self, status: int, value: dict) -> None:
        data = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _binary(self, data: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path.endswith("/v2/UnlockMethod/password"):
            self._json(200, {"vaultKey": self.vault_key})
            return
        if path.endswith("/v2/Vault"):
            self._binary(self.snapshot_raw)
            return
        self._json(404, {"message": "not found"})

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        body = self._read_json()
        if path.endswith("/v2/Auth/login"):
            username = str(body.get("username", "")).lower()
            salt = self.vault_key["salt"]
            unlock = keys.derive_unlock_key(
                self.password, salt, self.vault_key["encryptionSettings"]
            )
            password_hash = crypto.derive_srp_password_hash(
                unlock, self.vault_key["encryptionType"]
            )
            verifier = int(
                srp.derive_verifier(
                    srp.derive_private_key(salt, username, password_hash)
                ),
                16,
            )
            b = int.from_bytes(os.urandom(64), "big")
            server_public = (srp._K * verifier + pow(srp.G, b, srp.N)) % srp.N
            session_id = os.urandom(16).hex()
            self.sessions[session_id] = {
                "b": b,
                "server_public": server_public,
                "verifier": verifier,
                "salt": salt,
                "identity": username,
            }
            self._json(
                200,
                {
                    "salt": salt,
                    "serverEphemeral": srp._pad(server_public).hex().upper(),
                    "encryptionType": self.vault_key["encryptionType"],
                    "encryptionSettings": self.vault_key["encryptionSettings"],
                    "srpIdentity": username,
                    "loginSessionId": session_id,
                },
            )
            return
        if path.endswith("/v2/Auth/validate"):
            session_id = str(body.get("loginSessionId", ""))
            session = self.sessions.pop(session_id, None)
            if session is None:
                self._json(400, {"message": "unknown login session"})
                return
            a_pub = int(str(body["clientPublicEphemeral"]), 16)
            u = srp._hash_int(srp._pad(a_pub) + srp._pad(session["server_public"]))
            shared = pow(
                (a_pub * pow(session["verifier"], u, srp.N)) % srp.N,
                session["b"],
                srp.N,
            )
            session_key = hashlib.sha256(srp._pad(shared)).digest()
            identity_hash = hashlib.sha256(session["identity"].encode()).digest()
            m1 = hashlib.sha256(
                srp._H_N_XOR_H_G
                + identity_hash
                + bytes.fromhex(session["salt"])
                + srp._pad(a_pub)
                + srp._pad(session["server_public"])
                + session_key
            ).digest()
            if not hmac.compare_digest(
                m1, bytes.fromhex(str(body["clientSessionProof"]))
            ):
                self._json(401, {"message": "bad proof"})
                return
            server_proof = (
                hashlib.sha256(srp._pad(a_pub) + m1 + session_key).hexdigest().upper()
            )
            self._json(
                200,
                {
                    "requiresTwoFactor": False,
                    "serverSessionProof": server_proof,
                    "token": {"token": "fake-token", "refreshToken": "fake-refresh"},
                },
            )
            return
        if path.endswith("/v2/Auth/refresh"):
            self._json(
                200,
                {"token": "fake-token-2", "refreshToken": "fake-refresh-2"},
            )
            return
        if path.endswith("/v2/Vault/blobs/download"):
            manifest_id = str(body.get("manifestId", ""))
            if manifest_id.lower() != self.manifest_id.lower():
                self._json(404, {"message": "manifest not found"})
                return
            self._binary(self.blob_frame)
            return
        self._json(404, {"message": "not found"})


@pytest.fixture()
def fake_server():
    password, manifest_id, vault_key, snapshot_raw, blobs, blob_frame = _make_vault()
    handler = type(
        "TestHandler",
        (_Handler,),
        {
            "vault_key": vault_key,
            "snapshot_raw": snapshot_raw,
            "manifest_id": manifest_id,
            "blobs": blobs,
            "blob_frame": blob_frame,
            "password": password,
            "sessions": {},
        },
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], password
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "aliasvault_backup", *args],
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_cli_login_backup_decrypt_against_fake_server(
    tmp_path: Path, fake_server
) -> None:
    port, password = fake_server
    config = tmp_path / "config.toml"
    backups = tmp_path / "backups"
    env = os.environ.copy()
    env["ALIASVAULT_PASSWORD"] = password
    env.pop("ALIASVAULT_EXPORT_PASSWORD", None)

    result = _run(
        [
            "--config",
            str(config),
            "login",
            "--url",
            f"http://127.0.0.1:{port}/api",
            "--username",
            "test@example.com",
            "--store-password",
            "--backup-dir",
            str(backups),
            "--mode",
            "both",
            "--export-password-source",
            "stored",
            "--generate-export-password",
        ],
        env,
    )
    assert result.returncode == 0, result.stderr
    assert "Logged in as test@example.com" in result.stdout
    assert config.exists()

    secrets = json.loads((tmp_path / "secrets.json").read_text())
    assert secrets["masterPassword"] == password
    export_password = secrets["exportPassword"]
    assert export_password

    result = _run(["--config", str(config), "backup", "--json"], env)
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    avex = Path(summary["avex"])
    raw = Path(summary["raw"])
    assert avex.exists() and raw.exists()
    assert summary["avexVerification"]["items"] == 1
    assert summary["rawVerification"]["verified"] is True

    destination = tmp_path / "decrypted"
    env["ALIASVAULT_EXPORT_PASSWORD"] = export_password
    result = _run(
        ["--config", str(config), "decrypt", str(avex), "-o", str(destination)],
        env,
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((destination / "manifest.json").read_text())
    assert manifest["items"][0]["name"] == "Example login"
    assert (
        destination / "attachments" / "item-1_att-1_note.txt"
    ).read_bytes() == b"attachment contents"

    result = _run(["--config", str(config), "verify", str(raw), "--with-password"], env)
    assert result.returncode == 0, result.stderr
    assert "Decrypted: 1 items" in result.stdout

    # Offline .avbak -> .avex conversion uses only the raw snapshot and the
    # master password; it must not contact the API.
    offline_avex = tmp_path / "offline.avex"
    result = _run(
        [
            "--config",
            str(config),
            "export",
            str(raw),
            "-o",
            str(offline_avex),
        ],
        env,
    )
    assert result.returncode == 0, result.stderr
    assert offline_avex.exists()
    result = _run(["--config", str(config), "verify", str(offline_avex)], env)
    assert result.returncode == 0, result.stderr

    # Without the export-password environment variable, verify falls back to
    # the password stored in the private secrets file.
    env.pop("ALIASVAULT_EXPORT_PASSWORD")
    result = _run(["--config", str(config), "verify", str(avex)], env)
    assert result.returncode == 0, result.stderr
    assert "valid .avex" in result.stdout

    # Inspection modes must not leave a plaintext extraction behind unless the
    # caller explicitly asked for one.
    result = _run(["--config", str(config), "decrypt", str(avex), "--list-items"], env)
    assert result.returncode == 0, result.stderr
    assert "Example login" in result.stdout
    assert not avex.with_suffix("").exists()
