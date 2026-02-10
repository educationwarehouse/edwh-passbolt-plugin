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
from functools import cached_property
from getpass import getpass
from pathlib import Path

import httpx
from rapidfuzz import fuzz, process

from .types import (
    FolderEntry,
    FolderRecord,
    GpgKeyRecord,
    JwtPayload,
    LoginTokens,
    MetadataKeyRecord,
    PassboltApiResponse,
    PasswordEntry,
    RefreshTokens,
    ResourceRecord,
    ResourceTypeRecord,
    SearchResultEntry,
    SecretRecord,
    SessionData,
    SessionValidation,
    Tokens,
)


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


def _load_session() -> SessionData | None:
    path = _session_path()
    if not path.exists():
        return None

    try:
        return t.cast(SessionData, json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Session file is corrupted: {path}") from exc


def _save_session(data: SessionData) -> None:
    path = _session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError as exc:
        LOGGER.warning(f"Failed to set permissions on session file: {exc}")


def _jwt_payload(token: str) -> JwtPayload | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload_b64 + padding)
        return t.cast(JwtPayload, json.loads(raw.decode("utf-8")))
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
    tokens: Tokens,
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
) -> Tokens:
    if not encrypted:
        raise RuntimeError("Encrypted token payload is empty.")
    if passphrase is None:
        raw = _gpg_decrypt_interactive(encrypted, gpg_home)
    else:
        raw = _gpg_decrypt(encrypted, gpg_home, passphrase=passphrase)
    return t.cast(Tokens, json.loads(raw))


def _save_secure_session(
    *,
    tokens: Tokens,
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

    data: SessionData = {
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
        self,
        base_url: str,
        timeout: float = 30.0,
        gpg_home: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)
        self._gpg_home = gpg_home
        self._session_tokens: Tokens | None = None

    @classmethod
    def from_session(cls) -> "Passbolt":
        session = _load_session()
        if not session:
            raise RuntimeError(
                "Not logged in. Set PASSBOLT_ACCESS_TOKEN or run `edwh passbolt.login` first.",
            )

        encrypted = session.get("encrypted_tokens")
        if not encrypted or not encrypted.strip():
            raise RuntimeError(
                "Session file is missing encrypted tokens. Please re-login.",
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
    def validate_session(cls, verify_remote: bool = True) -> SessionValidation:
        client = cls.from_session()
        session = _load_session()
        tokens = client._session_tokens
        if not session or not tokens:
            raise RuntimeError("Stored session is invalid. Please re-login.")
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
                    "Session is missing user_fingerprint. Please re-login.",
                )
            refreshed = client.refresh_jwt(
                user_id,
                refresh_token,
                access_token=access_token,
            )
            access_token = refreshed["access_token"]
            refresh_token = refreshed.get("refresh_token") or refresh_token
            tokens: Tokens = {
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
            _save_secure_session(
                tokens=tokens,
                user_id=user_id,
                host=client.base_url,
                gpg_home=client._gpg_home,
                user_fingerprint=fingerprint,
            )

        if verify_remote and not client.is_authenticated(access_token):
            raise RuntimeError(
                "Stored access token is not authenticated. Please re-login.",
            )

        return {"host": client.base_url, "access_token": access_token}

    @classmethod
    def clear_session(cls) -> None:
        _session_path().unlink(missing_ok=True)

    def save_session(
        self,
        *,
        tokens: Tokens,
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
                    LOGGER.warning(f"Failed to warm GPG agent cache: {exc}")

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
    ) -> PassboltApiResponse:
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
                f"[request] method={method} url={url} payload={payload} headers={request_headers}",
            )

            resp = self._client.request(
                method,
                url,
                json=payload,
                headers=request_headers,
            )

            resp.raise_for_status()
            data = t.cast(PassboltApiResponse, resp.json())
            LOGGER.debug(f"[response] status={resp.status_code} data={data}")
            return data

        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"HTTP {exc.response.status_code} from {url}: {exc.response.text}",
            ) from exc
        except httpx.RequestError as exc:
            raise RuntimeError(f"Network error calling {url}: {exc}") from exc

    def session_info(self) -> SessionData:
        session = _load_session()
        if not session:
            raise RuntimeError("Not logged in. Run `edwh passbolt.login` first.")
        return session

    def access_token(self) -> str:
        return self.validate_session(verify_remote=False)["access_token"]

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token()}"}

    def _api_request(
        self,
        method: str,
        path: str,
        payload: dict[str, t.Any] | None = None,
        params: dict[str, t.Any] | None = None,
    ) -> PassboltApiResponse:
        if params:
            from urllib.parse import urlencode

            query = urlencode(params, doseq=True, safe="[]")
            sep = "&" if "?" in path else "?"
            path = f"{path}{sep}{query}"
        return self.request(method, path, payload=payload, headers=self._auth_headers())

    def api_get(
        self,
        path: str,
        params: dict[str, t.Any] | None = None,
    ) -> PassboltApiResponse:
        return self._api_request("GET", path, params=params)

    def api_post(
        self,
        path: str,
        payload: dict[str, t.Any],
        params: dict[str, t.Any] | None = None,
    ) -> PassboltApiResponse:
        return self._api_request("POST", path, payload=payload, params=params)

    def api_put(
        self,
        path: str,
        payload: dict[str, t.Any],
        params: dict[str, t.Any] | None = None,
    ) -> PassboltApiResponse:
        return self._api_request("PUT", path, payload=payload, params=params)

    def api_delete(
        self,
        path: str,
        params: dict[str, t.Any] | None = None,
    ) -> PassboltApiResponse:
        return self._api_request("DELETE", path, params=params)

    def gpg_home(self) -> str:
        return self._gpg_home or _default_gpg_home()

    def load_metadata_keys(self) -> dict[str, MetadataKeyRecord]:
        params = {
            "contain[metadata_private_keys]": 1,
            "filter[deleted]": 0,
            "filter[expired]": 0,
        }
        data = self.api_get("/metadata/keys.json", params=params)
        keys = data.get("body") or []
        LOGGER.debug(
            f"Loaded metadata keys from API. count={len(keys)} "
            f"filter_deleted=0 filter_expired=0",
        )
        if not keys:
            data = self.api_get(
                "/metadata/keys.json",
                params={"contain[metadata_private_keys]": 1},
            )
            keys = data.get("body") or []
            LOGGER.debug(
                f"Loaded metadata keys from API without filters. count={len(keys)}",
            )
        session = self.session_info()
        user_id = session.get("user_id")
        gpg_home = self.gpg_home()

        by_id: dict[str, MetadataKeyRecord] = {}
        for key in keys:
            key_id = key.get("id")
            if not key_id:
                continue
            by_id[key_id] = key
            LOGGER.debug(f"Metadata key loaded: {key_id}")

            armored_key = key.get("armored_key")
            if armored_key:
                try:
                    _gpg_import(armored_key, gpg_home)
                except RuntimeError as exc:
                    LOGGER.warning(f"Failed to import metadata public key: {exc}")

            privates = key.get("metadata_private_keys") or []
            private = next(
                (item for item in privates if item.get("user_id") == user_id),
                None,
            )
            if private and private.get("data"):
                try:
                    decrypted_private = _gpg_decrypt_interactive(
                        private["data"],
                        gpg_home,
                    )
                except RuntimeError as exc:
                    LOGGER.warning(f"Failed to decrypt metadata private key: {exc}")
                    continue
                armored_private = decrypted_private
                try:
                    private_payload = json.loads(decrypted_private)
                except json.JSONDecodeError:
                    private_payload = None
                if isinstance(private_payload, dict) and private_payload.get(
                    "armored_key",
                ):
                    armored_private = str(private_payload.get("armored_key") or "")
                if "BEGIN PGP" not in armored_private:
                    first_line = (
                        armored_private.splitlines()[0] if armored_private else ""
                    )
                    LOGGER.warning(
                        "Skipping invalid decrypted private key for "
                        f"metadata_key_id={key_id} first_line={first_line}",
                    )
                    continue
                try:
                    _gpg_import(armored_private, gpg_home)
                except RuntimeError as exc:
                    LOGGER.warning(f"Failed to import metadata private key: {exc}")
        return by_id

    def decrypt_metadata(
        self,
        encrypted: str,
        metadata_key_id: str,
        metadata_key_type: str | None,
        metadata_keys: dict[str, MetadataKeyRecord],
    ) -> dict[str, t.Any]:
        if metadata_key_type != "user_key":
            if metadata_key_id not in metadata_keys:
                LOGGER.debug(
                    "Metadata key missing. "
                    f"requested={metadata_key_id} "
                    f"type={metadata_key_type} "
                    f"available={list(metadata_keys.keys())}",
                )
                raise RuntimeError(f"Metadata key {metadata_key_id} not available.")
        raw = _gpg_decrypt_interactive(encrypted, self.gpg_home())
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"name": raw}

    def encrypt_metadata(
        self,
        metadata: dict[str, t.Any],
        metadata_key_id: str | None,
        metadata_key_type: str | None,
        metadata_keys: dict[str, MetadataKeyRecord],
    ) -> str:
        session = self.session_info()
        user_fingerprint = session.get("user_fingerprint")
        if not user_fingerprint:
            raise RuntimeError("Session missing user_fingerprint. Please re-login.")
        if metadata_key_type == "user_key":
            fingerprint = user_fingerprint
            raw = json.dumps(metadata, separators=(",", ":"))
            return _gpg_encrypt(raw, fingerprint, self.gpg_home())

        if not metadata_key_id:
            raise RuntimeError("Metadata key id required for shared_key metadata.")
        key = metadata_keys.get(metadata_key_id)
        if not key:
            raise RuntimeError(f"Metadata key {metadata_key_id} not found.")
        fingerprint = key.get("fingerprint")
        if not fingerprint:
            raise RuntimeError(f"Metadata key {metadata_key_id} missing fingerprint.")
        raw = json.dumps(metadata, separators=(",", ":"))
        return _gpg_encrypt_signed(raw, fingerprint, user_fingerprint, self.gpg_home())

    def decrypt_secret(self, secret_data: str) -> t.Any:
        raw = _gpg_decrypt_interactive(secret_data, self.gpg_home())
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    def encrypt_secret(self, secret_value: t.Any) -> str:
        session = self.session_info()
        user_fingerprint = session.get("user_fingerprint")
        if not user_fingerprint:
            raise RuntimeError("Session missing user_fingerprint. Please re-login.")
        if isinstance(secret_value, (dict, list)):
            raw = json.dumps(secret_value, separators=(",", ":"))
        else:
            raw = str(secret_value)
        return _gpg_encrypt(raw, user_fingerprint, self.gpg_home())

    def list_resources(self) -> list[ResourceRecord]:
        data = self.api_get("/resources.json")
        return data.get("body") or []

    def list_folders(self) -> list[FolderRecord]:
        data = self.api_get("/folders.json")
        folders = data.get("body") or []
        LOGGER.debug(f"Loaded folders from API. count={len(folders)}")
        return folders

    def get_resource(self, resource_id: str) -> ResourceRecord:
        data = self.api_get(f"/resources/{resource_id}.json")
        return data.get("body") or {}

    def get_folder(self, folder_id: str) -> FolderRecord:
        data = self.api_get(f"/folders/{folder_id}.json")
        return data.get("body") or {}

    def list_gpg_keys(self) -> list[GpgKeyRecord]:
        data = self.api_get("/gpgkeys.json")
        return data.get("body") or []

    def user_gpg_key_id(self) -> str | None:
        session = self.session_info()
        user_id = session.get("user_id")
        if not user_id:
            return None
        for key in self.list_gpg_keys():
            if key.get("user_id") == user_id:
                return key.get("id")
        return None

    def get_secret(self, resource_id: str) -> SecretRecord:
        data = self.api_get(f"/secrets/resource/{resource_id}.json")
        return data.get("body") or {}

    @cached_property
    def resource_types(self) -> dict[str, ResourceTypeRecord]:
        data = self.api_get("/resource-types.json")
        body = data.get("body") or []
        return {item.get("id"): item for item in body if item.get("id")}

    @cached_property
    def default_resource_type(self) -> ResourceTypeRecord:
        resource_types = self.resource_types
        for item in resource_types.values():
            if item.get("default"):
                return item
        if resource_types:
            return next(iter(resource_types.values()))
        raise RuntimeError("No resource types available.")

    def resolve_resource(self, name_or_id: str) -> ResourceRecord | None:
        resources = self.list_resources()
        metadata_keys = self.load_metadata_keys()
        for resource in resources:
            LOGGER.debug(
                "Resolving resource "
                f"id={resource.get('id')} "
                f"metadata_key_id={resource.get('metadata_key_id')}",
            )
            if resource.get("id") == name_or_id:
                return resource
            metadata = resource.get("metadata")
            metadata_key_id = resource.get("metadata_key_id")
            metadata_key_type = resource.get("metadata_key_type")
            if metadata and metadata_key_id:
                try:
                    meta = self.decrypt_metadata(
                        metadata,
                        metadata_key_id,
                        metadata_key_type,
                        metadata_keys,
                    )
                except RuntimeError:
                    continue
                if meta.get("name") == name_or_id:
                    return resource
        return None

    def resolve_folder(self, name_or_id: str) -> FolderRecord | None:
        folders = self.list_folders()
        metadata_keys = self.load_metadata_keys()
        for folder in folders:
            if folder.get("id") == name_or_id:
                return folder
            if folder.get("name") == name_or_id:
                return folder

            metadata = folder.get("metadata")
            metadata_key_id = folder.get("metadata_key_id")
            metadata_key_type = folder.get("metadata_key_type")
            if metadata and metadata_key_id:
                try:
                    meta = self.decrypt_metadata(
                        metadata,
                        metadata_key_id,
                        metadata_key_type,
                        metadata_keys,
                    )
                except RuntimeError:
                    continue
                if meta.get("name") == name_or_id:
                    return folder
        return None

    def list_folder_entries(self) -> list[FolderEntry]:
        folders = self.list_folders()
        metadata_keys = self.load_metadata_keys()
        entries: list[FolderEntry] = []
        for folder in folders:
            if folder.get("name"):
                entries.append({"id": folder["id"], "name": folder.get("name")})
                continue

            metadata = folder.get("metadata")
            metadata_key_id = folder.get("metadata_key_id")
            metadata_key_type = folder.get("metadata_key_type")
            if not metadata or not metadata_key_id:
                continue
            try:
                meta = self.decrypt_metadata(
                    metadata,
                    metadata_key_id,
                    metadata_key_type,
                    metadata_keys,
                )
            except RuntimeError as exc:
                LOGGER.warning(
                    f"Failed to decrypt folder metadata for id={folder.get('id')}: {exc}",
                )
                continue
            entries.append({"id": folder["id"], "name": meta.get("name")})

        return entries

    def _resource_type_supports_uris(self, resource_type: ResourceTypeRecord) -> bool:
        definition = resource_type.get("definition") or {}
        resource_def = definition.get("resource") or {}
        properties = resource_def.get("properties") or {}
        return "uris" in properties

    def _apply_uri_field(
        self,
        metadata: dict[str, t.Any],
        uri: str | None,
        resource_type: ResourceTypeRecord,
    ) -> dict[str, t.Any]:
        if uri is None:
            return metadata
        if self._resource_type_supports_uris(resource_type):
            metadata["uris"] = [uri]
            metadata.pop("uri", None)
        else:
            metadata["uri"] = uri
            metadata.pop("uris", None)
        return metadata

    def _build_v5_metadata(
        self,
        *,
        name: str,
        username: str | None,
        uri: str | None,
        description: str | None,
        resource_type_id: str,
    ) -> dict[str, t.Any]:
        metadata: dict[str, t.Any] = {
            "object_type": "PASSBOLT_RESOURCE_METADATA",
            "name": name,
            "username": username,
            "uris": [uri] if uri else [],
            "description": description,
            "resource_type_id": resource_type_id,
            "custom_fields": [],
        }
        return metadata

    def list_password_entries(self, include_folder: bool = True) -> list[PasswordEntry]:
        resources = self.list_resources()
        metadata_keys = self.load_metadata_keys()
        folders: dict[str, str | None] = {}
        if include_folder:
            folders = {
                entry["id"]: entry.get("name") for entry in self.list_folder_entries()
            }
        entries: list[PasswordEntry] = []
        for resource in resources:
            metadata = resource.get("metadata")
            metadata_key_id = resource.get("metadata_key_id")
            metadata_key_type = resource.get("metadata_key_type")
            if not metadata or not metadata_key_id:
                continue
            try:
                meta = self.decrypt_metadata(
                    metadata,
                    metadata_key_id,
                    metadata_key_type,
                    metadata_keys,
                )
            except RuntimeError as exc:
                LOGGER.warning(
                    f"Failed to decrypt metadata for id={resource.get('id')}: {exc}",
                )
                continue

            entries.append(
                {
                    "id": resource["id"],
                    "name": meta.get("name"),
                    "username": meta.get("username"),
                    "uri": (meta.get("uri") or (meta.get("uris") or [None])[0]),
                    "folder": (
                        folders.get(resource.get("folder_parent_id") or "")
                        if include_folder
                        else None
                    ),
                }
            )
        return entries

    def search_password_entries(
        self,
        term: str,
        *,
        limit: int = 10,
        threshold: int = 70,
        include_passwords: bool = False,
    ) -> list[SearchResultEntry]:
        entries = self.list_password_entries(include_folder=False)
        choices: dict[str, PasswordEntry] = {}
        for entry in entries:
            label = " | ".join(
                (
                    part
                    for part in (
                        str(entry.get("name") or "").strip(),
                        str(entry.get("username") or "").strip(),
                        str(entry.get("uri") or "").strip(),
                    )
                    if part
                )
            ).strip()
            if not label:
                continue
            choices[label] = entry

        # noinspection PyTypeChecker
        results = process.extract(
            term,
            choices.keys(),
            scorer=fuzz.WRatio,
            score_cutoff=threshold,
            limit=limit,
        )

        output: list[SearchResultEntry] = []
        for label, score, _ in results:
            entry = choices.get(label) or {}
            resource_id = str(entry.get("id") or "")
            password: str | None = None
            if include_passwords and resource_id:
                try:
                    password = self.get_password_field(resource_id, "password")
                except RuntimeError as exc:
                    password = f"Error: {exc}"

            output.append(
                {
                    "score": int(score),
                    "id": resource_id,
                    "name": entry.get("name"),
                    "username": entry.get("username"),
                    "uri": entry.get("uri"),
                    "password": password,
                },
            )
        return output

    def get_password_field(self, name_or_id: str, field: str) -> str:
        field = field.lower()
        if field not in {"password", "user", "uri"}:
            raise RuntimeError("field must be one of: password, user, uri")

        resource = self.resolve_resource(name_or_id)
        if not resource:
            raise RuntimeError(f"Resource not found: {name_or_id}")

        metadata_keys = self.load_metadata_keys()
        metadata = {}
        if resource.get("metadata") and resource.get("metadata_key_id"):
            metadata = self.decrypt_metadata(
                resource["metadata"],
                resource["metadata_key_id"],
                resource.get("metadata_key_type"),
                metadata_keys,
            )

        if field == "user":
            return str(metadata.get("username") or "")
        if field == "uri":
            uri_value = metadata.get("uri")
            if not uri_value and isinstance(metadata.get("uris"), list):
                uri_value = metadata.get("uris")[0] if metadata.get("uris") else ""
            return str(uri_value or "")

        secret = self.get_secret(resource["id"])
        secret_data = secret.get("data")
        if not secret_data:
            raise RuntimeError("No secret data available for this resource.")
        decrypted = self.decrypt_secret(secret_data)
        if isinstance(decrypted, dict) and "password" in decrypted:
            return str(decrypted.get("password") or "")
        return str(decrypted)

    def set_password(
        self,
        name: str,
        password: str,
        username: str | None = None,
        uri: str | None = None,
        folder: str | None = None,
    ) -> str:
        resource = self.resolve_resource(name)
        if resource:
            return self.update_password(
                resource["id"],
                password,
                username=username,
                uri=uri,
            )
        return self.create_password(
            name,
            password,
            username=username,
            uri=uri,
            folder=folder,
        )

    def create_password(
        self,
        name: str,
        password: str,
        username: str | None = None,
        uri: str | None = None,
        folder: str | None = None,
    ) -> str:
        metadata_keys = self.load_metadata_keys()
        LOGGER.debug(
            f"create_password metadata_keys_count={len(metadata_keys)} "
            f"metadata_key_ids={list(metadata_keys.keys())}",
        )
        resource_types = self.resource_types
        resource_type = self.default_resource_type
        if resource_type.get("slug") and not str(resource_type.get("slug")).startswith(
            "v5-",
        ):
            v5_default = next(
                (
                    rt
                    for rt in resource_types.values()
                    if rt.get("slug") == "v5-default"
                ),
                None,
            )
            if v5_default:
                resource_type = v5_default

        if not metadata_keys:
            raise RuntimeError("No metadata keys available for creation.")

        metadata_key_id = next(iter(metadata_keys.keys()))
        metadata_key_type = "shared_key"

        preferred_folder_parent_id: str | None = None
        if folder:
            resolved_folder = self.resolve_folder(folder)
            if not resolved_folder or not resolved_folder.get("id"):
                raise RuntimeError(f"Folder not found: {folder}")
            preferred_folder_parent_id = resolved_folder.get("id")

        description = None
        metadata = self._build_v5_metadata(
            name=name,
            username=username,
            uri=uri,
            description=description,
            resource_type_id=resource_type["id"],
        )
        encrypted_metadata = self.encrypt_metadata(
            metadata,
            metadata_key_id,
            metadata_key_type,
            metadata_keys,
        )

        session = self.session_info()
        user_id = session.get("user_id")
        if not user_id:
            raise RuntimeError("Session missing user_id. Please re-login.")
        secret_data = {
            "object_type": "PASSBOLT_SECRET_DATA",
            "password": password,
            "description": description,
            "custom_fields": [],
        }
        encrypted_secret = self.encrypt_secret(secret_data)

        payload: dict[str, t.Any] = {
            "metadata": encrypted_metadata,
            "metadata_key_id": metadata_key_id,
            "metadata_key_type": metadata_key_type,
            "resource_type_id": resource_type["id"],
            "secrets": [{"data": encrypted_secret, "user_id": user_id}],
        }
        if preferred_folder_parent_id:
            payload["folder_parent_id"] = preferred_folder_parent_id
        created = self.api_post("/resources.json", payload=payload)
        body = created.get("body") or {}
        return str(body.get("id") or "")

    def update_password(
        self,
        name_or_id: str,
        password: str,
        username: str | None = None,
        uri: str | None = None,
    ) -> str:
        resource = self.resolve_resource(name_or_id)
        if not resource:
            raise RuntimeError(f"Resource not found: {name_or_id}")

        metadata_keys = self.load_metadata_keys()
        metadata = self.decrypt_metadata(
            resource["metadata"],
            resource["metadata_key_id"],
            resource.get("metadata_key_type"),
            metadata_keys,
        )
        if username is not None:
            metadata["username"] = username
        resource_types = self.resource_types
        resource_type = resource_types.get(resource["resource_type_id"]) or {}

        metadata = self._apply_uri_field(metadata, uri, resource_type)
        encrypted_metadata = self.encrypt_metadata(
            metadata,
            resource["metadata_key_id"],
            resource.get("metadata_key_type"),
            metadata_keys,
        )

        secret = self.get_secret(resource["id"])
        secret_id = secret.get("id")
        if not secret_id:
            raise RuntimeError("Unable to determine secret id for update.")

        existing_secret = None
        if secret.get("data"):
            existing_secret = self.decrypt_secret(secret["data"])

        if isinstance(existing_secret, dict):
            existing_secret["password"] = password
            secret_payload = existing_secret
        else:
            secret_payload = password

        encrypted_secret = self.encrypt_secret(secret_payload)
        session = self.session_info()
        user_id = session.get("user_id")
        if not user_id:
            raise RuntimeError("Session missing user_id. Please re-login.")
        payload = {
            "metadata": encrypted_metadata,
            "metadata_key_id": resource["metadata_key_id"],
            "metadata_key_type": resource["metadata_key_type"],
            "resource_type_id": resource["resource_type_id"],
            "secrets": [
                {"id": secret_id, "data": encrypted_secret, "user_id": user_id}
            ],
        }
        self.api_put(f"/resources/{resource['id']}.json", payload=payload)
        return str(resource["id"])

    def delete_password(self, name_or_id: str) -> str:
        resource = self.resolve_resource(name_or_id)
        if not resource:
            raise RuntimeError(f"Resource not found: {name_or_id}")
        self.api_delete(f"/resources/{resource['id']}.json")
        return str(resource["id"])

    def verify(self) -> PassboltApiResponse:
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
    ) -> RefreshTokens:
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
        refreshed: RefreshTokens = {"access_token": access}
        if cookie_refresh := self._client.cookies.get("refresh_token"):
            refreshed["refresh_token"] = cookie_refresh
        return refreshed

    def jwt_login(self, user_id: str, challenge: str) -> PassboltApiResponse:
        return self.request(
            "POST",
            "/auth/jwt/login.json",
            {"user_id": user_id, "challenge": challenge},
        )

    def login_jwt(
        self,
        user_id: str,
        import_key: str | None,
        passphrase: str | None,
        verify_expiry: int,
    ) -> LoginTokens:
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
            payload,
            user_key,
            server_fingerprint,
            self._gpg_home,
            passphrase=passphrase,
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
                f"MFA required: {mfa_providers}. MFA flow is not implemented yet.",
            )

        access = response.get("access_token")
        refresh = response.get("refresh_token")
        if not access or not refresh:
            raise RuntimeError(
                "Missing access_token or refresh_token in login response.",
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
        LOGGER.warning(f"Failed to set permissions on GNUPGHOME: {exc}")

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
    keydata: str,
    gpg_home: str | None,
    passphrase: str | None = None,
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
    message: str,
    gpg_home: str | None,
    passphrase: str | None = None,
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


def _gpg_encrypt_signed(
    message: str,
    recipient: str,
    signer: str,
    gpg_home: str | None,
) -> str:
    return _run_gpg(
        [
            "--armor",
            "--trust-model",
            "always",
            "--local-user",
            signer,
            "--recipient",
            recipient,
            "--sign",
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
            mode="w+",
            encoding="utf-8",
            delete=True,
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
    try:
        # First try a silent decrypt: no pinentry, no prompt.
        return _run_gpg_interactive(
            ["--pinentry-mode", "error", "--decrypt"],
            message,
            gpg_home,
            use_batch=True,
        )
    except RuntimeError as exc:
        if _is_non_passphrase_error(str(exc)):
            raise

    passphrase = getpass("GPG passphrase: ").strip()
    if not passphrase:
        raise RuntimeError("GPG passphrase is required to decrypt.")

    try:
        # Try loopback pinentry in the terminal to avoid GUI popups.
        return _run_gpg_interactive(
            ["--decrypt"],
            message,
            gpg_home,
            passphrase=passphrase,
            use_batch=True,
        )
    except RuntimeError as exc:
        if _is_loopback_blocked(str(exc)):
            # Fall back to interactive pinentry if loopback is disallowed.
            return _run_gpg_interactive(["--decrypt"], message, gpg_home)
        raise


def _is_non_passphrase_error(error: str) -> bool:
    error = error.lower()
    return any(
        marker in error
        for marker in (
            "no secret key",
            "no public key",
            "no data",
            "invalid packet",
            "not a valid openpgp",
            "decrypt_message failed",
        )
    )


def _is_loopback_blocked(error: str) -> bool:
    error = error.lower()
    return any(
        marker in error
        for marker in (
            "pinentry",
            "loopback",
            "inappropriate ioctl",
            "no tty",
            "cannot get input",
        )
    )
