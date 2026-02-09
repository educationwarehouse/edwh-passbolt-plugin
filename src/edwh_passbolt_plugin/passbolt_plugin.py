from __future__ import annotations

from getpass import getpass
from pathlib import Path

from edwh import task
from invoke import Context

from .passbolt import Passbolt


def _normalize_base_url(host: str) -> str:
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


def _prompt(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def _read_key_block(first_line: str | None = None) -> str:
    if first_line is None:
        print("Paste the PGP private key block. End with a single line: EOF")
    lines: list[str] = []
    if first_line:
        lines.append(first_line)
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "EOF":
            break
        lines.append(line)
    return "\n".join(lines).strip()


@task()
def ensure_logged_in(c: Context) -> None:
    Passbolt.validate_session()


def _prompt_login_inputs() -> tuple[str, str, str | None, str | None]:
    host = _prompt(f"Passbolt host (e.g. {DEFAULT_HOST})") or DEFAULT_HOST
    host = _normalize_base_url(host)
    user_id = _prompt(
        f"Passbolt user UUID (find it via {host}/app/users, click your user, copy UUID from URL)"
    )
    import_mode_raw = _prompt("Import key? (path/paste/skip)", "skip")
    import_mode = import_mode_raw.lower()
    import_key: str | None = None
    if import_mode_raw.startswith("-----BEGIN PGP"):
        import_key = _read_key_block(first_line=import_mode_raw)
    elif Path(import_mode_raw).expanduser().exists():
        import_key = import_mode_raw
    elif import_mode == "path":
        import_key = _prompt("Path to private key (recovery kit)")
    elif import_mode == "paste":
        import_key = _read_key_block()
    passphrase = (
        getpass("GPG passphrase (leave empty if key has none): ").strip() or None
    )
    return host, user_id, import_key, passphrase


DEFAULT_HOST = "https://passbolt.edwh.nl"


@task(
    help={
        "host": "Passbolt server URL (e.g. https://passbolt.example)",
        "user_id": "Passbolt user UUID",
        "gpg_home": "Override GNUPGHOME for gpg operations (default: ~/.config/edwh/passbolt/gnupg)",
        "import_key": "Path to a private key (e.g. passbolt-recovery-kit.asc) to import",
        "passphrase": "GPG key passphrase (uses loopback pinentry; avoid unless necessary)",
        "verify_expiry": "Challenge expiry in seconds (default: 300)",
        "force": "Force re-login even if a valid session exists",
    }
)
def login(
    c: Context,
    host: str | None = None,
    user_id: str | None = None,
    gpg_home: str | None = None,
    import_key: str | None = None,
    passphrase: str | None = None,
    verify_expiry: int = 300,
    force: bool = False,
) -> None:
    """Authenticate against Passbolt and cache a session/token locally."""
    if not force:
        try:
            Passbolt.validate_session()
            answer = _prompt("A valid session exists. Re-login? (y/N)", "N").lower()
            if answer not in {"y", "yes"}:
                return
        except Exception:  # noqa: BLE001
            pass
    if not any([host, user_id, import_key, passphrase]):
        host, user_id, import_key, passphrase = _prompt_login_inputs()
    if passphrase is None:
        passphrase = (
            getpass("GPG passphrase (leave empty if key has none): ").strip() or None
        )

    if not host or not user_id:
        raise RuntimeError("Host and user_id are required.")

    host = _normalize_base_url(host)
    Passbolt.from_login(
        host=host,
        user_id=user_id,
        import_key=import_key,
        passphrase=passphrase,
        verify_expiry=verify_expiry,
        gpg_home=gpg_home,
    )
    return


@task()
def logout(c: Context) -> None:
    """Clear local Passbolt session/token."""
    Passbolt.clear_session()
    return


@task(
    help={"search": "Filter on name/username/uri"},
    pre=[ensure_logged_in],
    name="list",
    aliases=["list-passwords", "list-password"],
)
def list_passwords(c: Context, search: str | None = None) -> None:
    """List available passwords (optionally filtered)."""
    raise NotImplementedError("Implement listing secrets.")


@task(
    help={
        "name": "Entry name or ID",
        "field": "Which field to return (password/user/uri)",
    },
    pre=[ensure_logged_in],
)
def get_password(c: Context, name: str, field: str = "password") -> None:
    """Retrieve a password (or specific field) for an entry."""
    raise NotImplementedError("Implement fetching a secret field.")


@task(
    help={"name": "Entry name or ID", "username": "Username", "uri": "Resource URI"},
    pre=[ensure_logged_in],
)
def set_password(
    c: Context,
    name: str,
    password: str,
    username: str | None = None,
    uri: str | None = None,
) -> None:
    """Create or update a password entry."""
    raise NotImplementedError("Implement creating/updating a secret.")


@task(help={"name": "Entry name or ID"}, pre=[ensure_logged_in])
def delete_password(c: Context, name: str) -> None:
    """Delete a password entry."""
    raise NotImplementedError("Implement deletion of a secret.")


@task(help={"name": "Entry name or ID"}, pre=[ensure_logged_in])
def rotate_password(c: Context, name: str) -> None:
    """Generate and set a new password for an entry."""
    raise NotImplementedError("Implement rotation logic.")
