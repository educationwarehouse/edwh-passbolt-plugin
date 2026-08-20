from __future__ import annotations

import contextlib
import sys
import typing as t
from getpass import getpass
from pathlib import Path

from edwh import task
from invoke import Context
from rich import print as rprint
from rich.table import Table
from termcolor import cprint
from threadful import animate, thread

from .passbolt import Passbolt, PassboltError

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
def ensure_logged_in(_: Context) -> None:
    try:
        Passbolt.validate_session()
    except PassboltError as exc:
        cprint(exc, "red")
        sys.exit(1)


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
    passphrase = getpass("Passbolt/GPG passphrase: ").strip() or None
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
        with contextlib.suppress(Exception):
            Passbolt.validate_session()
            answer = _prompt("A valid session exists. Re-login? (y/N)", "N").lower()
            if answer not in {"y", "yes"}:
                return

    if not any([host, user_id, import_key, passphrase]):
        host, user_id, import_key, passphrase = _prompt_login_inputs()
    if passphrase is None:
        passphrase = getpass("Passbolt/GPG passphrase: ").strip() or None

    if not host or not user_id:
        raise RuntimeError("Host and user_id are required.")
    if not import_key:
        raise RuntimeError("import_key is required for login.")

    host = _normalize_base_url(host)
    Passbolt.from_login(
        host=host,
        user_id=user_id,
        import_key=import_key,
        passphrase=passphrase,
        verify_expiry=verify_expiry,
        gpg_home=gpg_home,
    )


@task()
def logout(c: Context) -> None:
    """Clear local Passbolt session/token."""
    Passbolt.clear_session()


@task(
    help={"search": "Filter on name/username/uri", "folder": "Filter on folder name"},
    pre=[ensure_logged_in],
    name="list",
    aliases=("list-passwords", "list-password"),
)
def list_passwords(_: Context, folder: str | None = None) -> None:
    """List available passwords (optionally filtered)."""
    client = Passbolt.from_session()
    entries = with_spinner(
        lambda: client.list_password_entries(include_shares=True),
        text="Loading passwords...",
    )

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
    table.add_column("Shared")
    for entry in entries:
        shared_users = int(entry.get("shared_users") or 0)
        shared_groups = int(entry.get("shared_groups") or 0)
        shared_label = f"U:{shared_users} G:{shared_groups}"
        table.add_row(
            str(entry.get("id") or ""),
            str(entry.get("name") or ""),
            str(entry.get("username") or ""),
            str(entry.get("uri") or ""),
            str(entry.get("folder") or ""),
            shared_label,
        )
    rprint(table)


@task(
    pre=[ensure_logged_in],
    name="list-folders",
    aliases=("folders",),
)
def list_folders(_: Context) -> None:
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
def get_password(_: Context, name: str) -> None:
    """Retrieve a password (or specific field) for an entry."""
    client = Passbolt.from_session()
    value = with_spinner(
        lambda: client.get_password_field(name),
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
    _: Context, term: str, limit: int = 10, threshold: int = 60
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
    _: Context,
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
    help={
        "title": "Note title or ID",
        "content": "Note content (reads stdin when piped)",
        "folder": "Folder name or ID (optional)",
    },
    pre=[ensure_logged_in],
    name="set-note",
    aliases=("add-note", "update-note"),
)
def set_note(
    _: Context,
    title: str | None = None,
    content: str | None = None,
    folder: str | None = None,
) -> None:
    """Create or update a standalone note entry."""
    if not title:
        title = _prompt("Note title or ID")

    if content is None and not sys.stdin.isatty():
        content = sys.stdin.read()
    if content is None:
        content = _prompt("Note content")
    if not content:
        raise RuntimeError("Note content is required.")

    client = Passbolt.from_session()
    resource_id = with_spinner(
        lambda: client.set_note(str(title), content, folder=folder),
        text="Saving note...",
    )
    print(resource_id)


@task(
    help={"name": "Entry name or ID"},
    pre=[ensure_logged_in],
    name="delete",
    aliases=("delete-password",),
)
def delete_password(_: Context, name: str) -> None:
    """Delete a password entry."""
    client = Passbolt.from_session()
    resource_id = with_spinner(
        lambda: client.delete_password(name),
        text="Deleting password...",
    )
    print(resource_id)


def _parse_labels(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _permission_level(value: str) -> int:
    raw = value.strip().lower()
    if raw in {"1", "read", "reader"}:
        return 1
    if raw in {"7", "update", "write", "editor"}:
        return 7
    if raw in {"15", "owner", "admin"}:
        return 15
    raise RuntimeError("permission must be one of: read, update, owner (or 1/7/15)")


def _join_with_and(values: list[str]) -> str:
    items = [item.strip() for item in values if item and item.strip()]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"


@task(
    help={
        "name": "Entry name or ID",
        "user": "User name or username/email (comma-separated for multiple)",
        "group": "Group name (comma-separated for multiple)",
        "permission": "Permission level: read|update|owner (default: read)",
    },
    pre=[ensure_logged_in],
    name="share",
    aliases=("share-password",),
)
def share_password(
    _: Context,
    name: str,
    user: str | None = None,
    group: str | None = None,
    permission: str = "read",
) -> None:
    """Share a password with users or groups by friendly name."""
    users = _parse_labels(user)
    groups = _parse_labels(group)
    if not users and not groups:
        raise RuntimeError("Provide at least one --user or --group.")
    level = _permission_level(permission)
    client = Passbolt.from_session()
    result = with_spinner(
        lambda: client.share_resource(
            name,
            users=users,
            groups=groups,
            permission=level,
        ),
        text="Sharing password...",
    )
    if result and isinstance(result, dict) and result.get("status") == "noop":
        print(result.get("message") or "No new users or groups to share.")
        return
    shared_labels = []
    if isinstance(result, dict):
        shared_labels = t.cast(list[str], result.get("shared_labels") or [])
    label = _join_with_and(shared_labels or [*users, *groups])
    if label:
        print(f"Shared with {label}")
    else:
        print("Shared.")


@task(
    help={
        "name": "Entry name or ID",
        "user": "User name or username/email (comma-separated for multiple)",
        "group": "Group name (comma-separated for multiple)",
    },
    pre=[ensure_logged_in],
    name="unshare",
    aliases=("unshare-password",),
)
def unshare_password(
    _: Context,
    name: str,
    user: str | None = None,
    group: str | None = None,
) -> None:
    """Unshare a password with users or groups by friendly name."""
    users = _parse_labels(user)
    groups = _parse_labels(group)
    client = Passbolt.from_session()
    result = with_spinner(
        lambda: client.unshare_resource(
            name,
            users=users,
            groups=groups,
        ),
        text="Unsharing password...",
    )
    if result and isinstance(result, dict) and result.get("status") == "noop":
        print(result.get("message") or "No matching shares to remove.")
        return
    if not users and not groups:
        print("Unshared with everyone.")
        return
    removed_labels = []
    if isinstance(result, dict):
        removed_labels = t.cast(list[str], result.get("removed_labels") or [])
    label = _join_with_and(removed_labels or [*users, *groups])
    if label:
        print(f"Unshared with {label}")
    else:
        print("Unshared.")


# @task(help={"name": "Entry name or ID"}, pre=[ensure_logged_in])
# def rotate_password(_: Context, name: str) -> None:
#     """Generate and set a new password for an entry."""
#     new_password = secrets.token_urlsafe(24)
#     client = Passbolt.from_session()
#     with_spinner(
#         lambda: client.set_password(name, new_password),
#         text="Rotating password...",
#     )
#     print(new_password)
