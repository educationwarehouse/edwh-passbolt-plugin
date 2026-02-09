from __future__ import annotations

import secrets
import typing as t
from getpass import getpass
from pathlib import Path

from edwh import task
from invoke import Context
from rapidfuzz import fuzz, process
from rich import print as rprint
from rich.table import Table
from threadful import animate, thread

from .passbolt import Passbolt

T = t.TypeVar("T")


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


def with_spinner(func: t.Callable[[], T], text: str) -> T:
    @thread
    def _task() -> T:
        return func()

    return animate(_task(), text=text)


@task()
def ensure_logged_in(c: Context) -> None:
    Passbolt.validate_session()


def _prompt_login_inputs() -> tuple[str, str, str | None, str | None]:
    host = _prompt(f"Passbolt host (e.g. {DEFAULT_HOST})") or DEFAULT_HOST
    host = _normalize_base_url(host)
    user_id = _prompt(
        f"Passbolt user UUID (find it via {host}/app/users, click your user, copy UUID from URL)",
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
    },
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
    help={"search": "Filter on name/username/uri", "folder": "Filter on folder name"},
    pre=[ensure_logged_in],
    name="list",
    aliases=("list-passwords", "list-password"),
)
def list_passwords(
    c: Context, search: str | None = None, folder: str | None = None
) -> None:
    """List available passwords (optionally filtered)."""
    client = Passbolt.from_session()
    entries = with_spinner(client.list_password_entries, text="Loading passwords...")
    if search:
        search_lower = search.lower()
        entries = [
            entry
            for entry in entries
            if search_lower
            in " ".join(
                (
                    str(entry.get(field) or "").lower()
                    for field in ("name", "username", "uri")
                )
            )
        ]
    if folder:
        folder_lower = folder.lower()
        entries = [
            entry
            for entry in entries
            if folder_lower in str(entry.get("folder") or "").lower()
        ]

    table = Table(title="Passbolt Passwords")
    table.add_column("ID", overflow="fold")
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("URI")
    table.add_column("Folder")
    for entry in entries:
        table.add_row(
            str(entry.get("id") or ""),
            str(entry.get("name") or ""),
            str(entry.get("username") or ""),
            str(entry.get("uri") or ""),
            str(entry.get("folder") or ""),
        )
    rprint(table)


@task(
    pre=[ensure_logged_in],
    name="list-folders",
    aliases=("folders",),
)
def list_folders(c: Context) -> None:
    """List available folders."""
    client = Passbolt.from_session()
    entries = with_spinner(client.list_folder_entries, text="Loading folders...")
    table = Table(title="Passbolt Folders")
    table.add_column("ID", overflow="fold")
    table.add_column("Name")
    for entry in entries:
        table.add_row(
            str(entry.get("id") or ""),
            str(entry.get("name") or ""),
        )
    rprint(table)


@task(
    help={
        "name": "Entry name or ID",
        "field": "Which field to return (password/user/uri)",
    },
    name="get",
    aliases=("get-password",),
    pre=[ensure_logged_in],
)
def get_password(c: Context, name: str, field: str = "password") -> None:
    """Retrieve a password (or specific field) for an entry."""
    client = Passbolt.from_session()
    value = with_spinner(
        lambda: client.get_password_field(name, field),
        text="Fetching password...",
    )
    print(value)


@task(
    help={
        "term": "Search term",
        "limit": "Max number of results (default: 10)",
        "threshold": "Minimum fuzzy score (0-100, default: 70)",
    },
    pre=[ensure_logged_in],
    name="search",
)
def search_passwords(
    c: Context, term: str, limit: int = 10, threshold: int = 70
) -> None:
    """Fuzzy search passwords and show matching entries (including passwords)."""
    client = Passbolt.from_session()
    results = with_spinner(
        lambda: client.search_password_entries(
            term, limit=limit, threshold=threshold, include_passwords=True
        ),
        text="Searching passwords...",
    )

    table = Table(title=f"Search Results for: {term}")
    table.add_column("Name")
    table.add_column("Username")
    table.add_column("URI")
    table.add_column("Password")

    for entry in results:
        table.add_row(
            str(entry.get("name") or ""),
            str(entry.get("username") or ""),
            str(entry.get("uri") or ""),
            str(entry.get("password") or ""),
        )

    rprint(table)


@task(
    help={
        "name": "Entry name or ID",
        "username": "Username",
        "uri": "Resource URI",
        "folder": "Folder name or ID (optional)",
    },
    pre=[ensure_logged_in],
    name="set",
    aliases=("set-password",),
)
def set_password(
    c: Context,
    name: str | None = None,
    password: str | None = None,
    username: str | None = None,
    uri: str | None = None,
    folder: str | None = None,
) -> None:
    """Create or update a password entry."""
    client = Passbolt.from_session()

    if not name:
        name = _prompt("Entry name or ID")

    if username is None:
        username = _prompt("Username (optional)", "") or None

    if password is None:
        password = getpass("Password: ").strip()
    if not password:
        raise RuntimeError("Password is required.")

    if uri is None:
        uri = _prompt("URI (optional)", "") or None

    resource_id = with_spinner(
        lambda: client.set_password(
            str(name), password, username=username, uri=uri, folder=folder
        ),
        text="Saving password...",
    )
    print(resource_id)


@task(
    help={"name": "Entry name or ID"},
    pre=[ensure_logged_in],
    name="delete",
    aliases=("delete-password",),
)
def delete_password(c: Context, name: str) -> None:
    """Delete a password entry."""
    client = Passbolt.from_session()
    resource_id = with_spinner(
        lambda: client.delete_password(name),
        text="Deleting password...",
    )
    print(resource_id)


# @task(help={"name": "Entry name or ID"}, pre=[ensure_logged_in])
# def rotate_password(c: Context, name: str) -> None:
#     """Generate and set a new password for an entry."""
#     new_password = secrets.token_urlsafe(24)
#     client = Passbolt.from_session()
#     with_spinner(
#         lambda: client.set_password(name, new_password),
#         text="Rotating password...",
#     )
#     print(new_password)
