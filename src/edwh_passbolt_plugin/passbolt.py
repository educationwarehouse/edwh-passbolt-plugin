from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import typing as t
import uuid
from pathlib import Path

import httpx


def _configure_logging() -> logging.Logger:
    logger = logging.getLogger("edwh.passbolt")

    level_raw = os.environ.get("EDWH_PASSBOLT_VERBOSE", "").strip().lower()
    if not level_raw:
        return logger

    if level_raw in {"1", "true", "info"}:
        level = logging.INFO
    elif level_raw in {"2", "debug", "verbose", "trace"}:
        level = logging.DEBUG
    else:
        level = logging.INFO
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    logger.setLevel(level)

    return logger


LOGGER = _configure_logging()


def _session_path() -> Path:
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_root / "edwh" / "passbolt" / "session.json"


def _load_session() -> dict[str, t.Any] | None:
    path = _session_path()
    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Session file is corrupted: {path}") from exc


def _save_session(data: dict[str, t.Any]) -> None:
    path = _session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError as exc:
        LOGGER.warning("Failed to set permissions on session file: %s", exc)


def _jwt_payload(token: str) -> dict[str, t.Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        return json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None


def _token_expiry(token: str) -> int | None:
    payload = _jwt_payload(token)
    if not payload:
        return None
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        return int(exp)
    return None


def _encrypt_tokens(
    tokens: dict[str, t.Any],
    gpg_home: str | None,
    recipient: str,
) -> str:
    raw = json.dumps(tokens, separators=(",", ":"))
    encrypted = _gpg_encrypt(raw, recipient, gpg_home)
    if not encrypted:
        raise RuntimeError("Failed to encrypt session tokens.")
    return encrypted


def _decrypt_tokens(
    encrypted: str,
    gpg_home: str | None,
    passphrase: str | None = None,
) -> dict[str, t.Any]:
    if not encrypted:
        raise RuntimeError("Encrypted token payload is empty.")
    if passphrase is None:
        raw = _gpg_decrypt_interactive(encrypted, gpg_home)
    else:
        raw = _gpg_decrypt(encrypted, gpg_home, passphrase=passphrase)
    return json.loads(raw)


def _save_secure_session(
    *,
    tokens: dict[str, t.Any],
    user_id: str,
    host: str,
    gpg_home: str | None,
    user_fingerprint: str,
) -> None:
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    if not access_token or not refresh_token:
        raise RuntimeError("Missing access_token or refresh_token.")
    encrypted = _encrypt_tokens(
        {"access_token": access_token, "refresh_token": refresh_token},
        gpg_home,
        user_fingerprint,
    )
    data = {
        "format": 4,
        "host": host,
        "user_id": user_id,
        "user_fingerprint": user_fingerprint,
        "access_token_exp": _token_expiry(access_token),
        "gpg_home": gpg_home,
        "encrypted_tokens": encrypted,
        "created_at": int(time.time()),
    }
    _save_session(data)


class Passbolt:
    def __init__(
        self, base_url: str, timeout: float = 30.0, gpg_home: str | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)
        self._gpg_home = gpg_home
        self._session_tokens: dict[str, t.Any] | None = None

    @classmethod
    def from_session(cls) -> "Passbolt":
        session = _load_session()
        if not session:
            raise RuntimeError(
                "Not logged in. Set PASSBOLT_ACCESS_TOKEN or run `edwh passbolt.login` first.",
            )

        if session.get("access_token") or session.get("refresh_token"):
            raise RuntimeError(
                "Session file contains plaintext tokens. Please delete it and re-login.",
            )

        encrypted = session.get("encrypted_tokens")
        if not encrypted or not encrypted.strip():
            raise RuntimeError(
                "Session file is missing encrypted tokens. Please re-login."
            )
        host = session.get("host")
        if not host:
            raise RuntimeError("Session is missing host. Please re-login.")
        client = cls(host, gpg_home=session.get("gpg_home"))
        client._session_tokens = _decrypt_tokens(encrypted, session.get("gpg_home"))
        return client

    @classmethod
    def from_login(
        cls,
        *,
        host: str,
        user_id: str,
        import_key: str,
        passphrase: str | None,
        verify_expiry: int,
        gpg_home: str | None = None,
    ) -> "Passbolt":
        client = cls(host, gpg_home=gpg_home)
        tokens = client.login_jwt(user_id, import_key, passphrase, verify_expiry)
        client.save_session(
            tokens=tokens,
            user_id=user_id,
            user_fingerprint=tokens["user_fingerprint"],
            warm_agent=True,
        )
        return client

    @classmethod
    def validate_session(cls) -> dict[str, t.Any]:
        client = cls.from_session()
        session = _load_session() or {}
        tokens = client._session_tokens or {}
        access_token = tokens.get("access_token")
        if not access_token:
            raise RuntimeError("Stored session is invalid. Please re-login.")

        exp = _token_expiry(access_token)
        if exp and time.time() >= exp:
            refresh_token = tokens.get("refresh_token")
            if not refresh_token:
                raise RuntimeError("Stored access token is expired. Please re-login.")
            user_id = session.get("user_id")
            if not user_id:
                raise RuntimeError("Session is missing user_id. Please re-login.")
            fingerprint = session.get("user_fingerprint")
            if not fingerprint:
                raise RuntimeError(
                    "Session is missing user_fingerprint. Please re-login."
                )
            refreshed = client.refresh_jwt(
                user_id, refresh_token, access_token=access_token
            )
            access_token = refreshed["access_token"]
            refresh_token = refreshed.get("refresh_token") or refresh_token
            tokens = {"access_token": access_token, "refresh_token": refresh_token}
            _save_secure_session(
                tokens=tokens,
                user_id=user_id,
                host=client.base_url,
                gpg_home=client._gpg_home,
                user_fingerprint=fingerprint,
            )

        if not client.is_authenticated(access_token):
            raise RuntimeError(
                "Stored access token is not authenticated. Please re-login."
            )

        return {"host": client.base_url, "access_token": access_token}

    @classmethod
    def clear_session(cls) -> None:
        _session_path().unlink(missing_ok=True)

    def save_session(
        self,
        *,
        tokens: dict[str, t.Any],
        user_id: str,
        user_fingerprint: str,
        warm_agent: bool = False,
    ) -> None:
        _save_secure_session(
            tokens=tokens,
            user_id=user_id,
            host=self.base_url,
            gpg_home=self._gpg_home,
            user_fingerprint=user_fingerprint,
        )
        if warm_agent:
            encrypted = (
                _load_session().get("encrypted_tokens") if _load_session() else None
            )
            if encrypted:
                try:
                    _gpg_decrypt_interactive(encrypted, self._gpg_home)
                except RuntimeError as exc:
                    LOGGER.warning("Failed to warm GPG agent cache: %s", exc)

    def close(self) -> None:
        self._client.close()

    def __del__(self) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, t.Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, t.Any]:
        url = f"{self.base_url}{path}"
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "edwh-passbolt-plugin",
        }
        if headers:
            request_headers.update(headers)
        if payload is not None:
            request_headers["Content-Type"] = "application/json"

        if csrf := self._client.cookies.get("csrfToken"):
            request_headers["X-CSRF-Token"] = csrf

        try:
            LOGGER.debug(
                "[request] method=%s url=%s payload=%s headers=%s",
                method,
                url,
                payload,
                request_headers,
            )

            resp = self._client.request(
                method, url, json=payload, headers=request_headers
            )

            resp.raise_for_status()
            data = resp.json()
            LOGGER.debug("[response] status=%s data=%s", resp.status_code, data)
            return data

        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"HTTP {exc.response.status_code} from {url}: {exc.response.text}"
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(f"Network error calling {url}: {exc}") from exc

    def verify(self) -> dict[str, t.Any]:
        return self.request("GET", "/auth/verify.json")

    def is_authenticated(self, access_token: str) -> bool:
        data = self.request(
            "GET",
            "/auth/is-authenticated.json",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        return data.get("header", {}).get("status") == "success"

    def refresh_jwt(
        self,
        user_id: str,
        refresh_token: str,
        access_token: str | None = None,
    ) -> dict[str, t.Any]:
        headers = {}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        data = self.request(
            "POST",
            "/auth/jwt/refresh.json",
            {"user_id": user_id, "refresh_token": refresh_token},
            headers=headers or None,
        )
        body = data.get("body") or {}
        access = body.get("access_token") or data.get("access_token")
        if not access:
            raise RuntimeError("Missing access_token in refresh response.")
        refreshed = {"access_token": access}
        if cookie_refresh := self._client.cookies.get("refresh_token"):
            refreshed["refresh_token"] = cookie_refresh
        return refreshed

    def jwt_login(self, user_id: str, challenge: str) -> dict[str, t.Any]:
        return self.request(
            "POST", "/auth/jwt/login.json", {"user_id": user_id, "challenge": challenge}
        )

    def login_jwt(
        self,
        user_id: str,
        import_key: str | None,
        passphrase: str | None,
        verify_expiry: int,
    ) -> dict[str, t.Any]:
        user_id = user_id.strip()
        if not user_id:
            raise RuntimeError("user_id is required for JWT login.")

        if not import_key:
            raise RuntimeError("import_key is required for JWT login.")

        keydata = _read_key_material(import_key)
        user_key = _gpg_fingerprint_from_key(keydata, self._gpg_home)
        _gpg_import(keydata, self._gpg_home, passphrase=passphrase)

        verify = self.verify()
        body = verify.get("body") or {}
        server_fingerprint = body.get("fingerprint")
        server_keydata = body.get("keydata")
        if not server_fingerprint or not server_keydata:
            raise RuntimeError("Server verify response missing fingerprint/keydata.")

        _gpg_import(server_keydata, self._gpg_home, passphrase=passphrase)

        verify_token = str(uuid.uuid4())
        payload = {
            "version": "1.0.0",
            "domain": self.base_url,
            "verify_token": verify_token,
            "verify_token_expiry": int(time.time()) + int(verify_expiry),
        }
        challenge = _gpg_sign_encrypt(
            payload, user_key, server_fingerprint, self._gpg_home, passphrase=passphrase
        )

        data = self.jwt_login(user_id, challenge)
        encrypted = (data.get("body") or {}).get("challenge")
        if not encrypted:
            raise RuntimeError("No challenge in login response.")

        decrypted = _gpg_decrypt(encrypted, self._gpg_home, passphrase=passphrase)
        response = json.loads(decrypted)
        if response.get("verify_token") != verify_token:
            raise RuntimeError("Server verify_token mismatch.")

        mfa_providers = response.get("mfa_providers")
        if mfa_providers:
            raise RuntimeError(
                f"MFA required: {mfa_providers}. MFA flow is not implemented yet."
            )

        access = response.get("access_token")
        refresh = response.get("refresh_token")
        if not access or not refresh:
            raise RuntimeError(
                "Missing access_token or refresh_token in login response."
            )

        return {
            "access_token": access,
            "refresh_token": refresh,
            "user_fingerprint": user_key,
        }


def _read_key_material(value: str) -> str:
    if "BEGIN PGP" in value:
        return value
    path = Path(value).expanduser()
    if path.exists():
        return path.read_text(encoding="utf-8")
    raise RuntimeError("Key material must be a path or a PGP key block.")


def _default_gpg_home() -> str:
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return str(config_root / "edwh" / "passbolt" / "gnupg")


def _gpg_env(gpg_home: str | None) -> dict[str, str]:
    env = os.environ.copy()
    gpg_home = gpg_home or _default_gpg_home()
    gpg_path = Path(gpg_home)
    gpg_path.mkdir(parents=True, exist_ok=True)

    try:
        gpg_path.chmod(0o700)
    except OSError as exc:
        LOGGER.warning("Failed to set permissions on GNUPGHOME: %s", exc)

    env["GNUPGHOME"] = gpg_home
    return env


def _run_gpg(
    args: list[str],
    input_data: str,
    gpg_home: str | None,
    passphrase: str | None = None,
) -> str:
    if not shutil.which("gpg"):
        raise RuntimeError("gpg is required but was not found in PATH.")
    if passphrase:
        args = ["--pinentry-mode", "loopback", "--passphrase", passphrase, *args]
    proc = subprocess.run(
        ["gpg", "--batch", "--yes", *args],
        input=input_data.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_gpg_env(gpg_home),
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8").strip())
    return proc.stdout.decode("utf-8").strip()


def _gpg_import(
    keydata: str, gpg_home: str | None, passphrase: str | None = None
) -> None:
    _run_gpg(["--import"], keydata, gpg_home, passphrase=passphrase)


def _gpg_fingerprint_from_key(keydata: str, gpg_home: str | None) -> str:
    output = _run_gpg(
        ["--with-colons", "--import-options", "show-only", "--dry-run", "--import"],
        keydata,
        gpg_home,
    )
    want_fpr = False
    for line in output.splitlines():
        if line.startswith(("sec:", "sec#")):
            want_fpr = True
            continue
        if line.startswith("fpr:") and want_fpr:
            parts = line.split(":")
            if len(parts) > 9 and parts[9]:
                return parts[9]
            want_fpr = False
    raise RuntimeError("Could not determine fingerprint from key material.")


def _gpg_sign_encrypt(
    payload: dict[str, t.Any],
    user_key: str,
    server_key: str,
    gpg_home: str | None,
    passphrase: str | None = None,
) -> str:
    raw = json.dumps(payload, separators=(",", ":"))
    return _run_gpg(
        [
            "--armor",
            "--trust-model",
            "always",
            "--local-user",
            user_key,
            "--recipient",
            server_key,
            "--sign",
            "--encrypt",
        ],
        raw,
        gpg_home,
        passphrase=passphrase,
    )


def _gpg_decrypt(
    message: str, gpg_home: str | None, passphrase: str | None = None
) -> str:
    return _run_gpg(["--decrypt"], message, gpg_home, passphrase=passphrase)


def _gpg_encrypt(message: str, recipient: str, gpg_home: str | None) -> str:
    return _run_gpg(
        [
            "--armor",
            "--trust-model",
            "always",
            "--recipient",
            recipient,
            "--encrypt",
        ],
        message,
        gpg_home,
    )


def _run_gpg_interactive(
    args: list[str],
    input_data: str,
    gpg_home: str | None,
    *,
    passphrase: str | None = None,
    use_batch: bool = False,
) -> str:
    if not shutil.which("gpg"):
        raise RuntimeError("gpg is required but was not found in PATH.")
    if passphrase or use_batch:
        with tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8", delete=True
        ) as temp:
            temp.write(input_data)
            temp.flush()
            cmd = ["gpg", "--yes"]
            if use_batch:
                cmd += ["--batch", "--no-tty"]
            if passphrase:
                cmd += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]
            cmd += [*args, temp.name]
            proc = subprocess.run(
                cmd,
                input=(passphrase or "").encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_gpg_env(gpg_home),
                check=False,
            )
    else:
        proc = subprocess.run(
            ["gpg", "--yes", *args],
            input=input_data.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_gpg_env(gpg_home),
            check=False,
        )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8").strip())
    return proc.stdout.decode("utf-8").strip()


def _gpg_decrypt_interactive(message: str, gpg_home: str | None) -> str:
    return _run_gpg_interactive(["--decrypt"], message, gpg_home)
