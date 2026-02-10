from __future__ import annotations

import typing as t


class PasswordEntry(t.TypedDict):
    id: str
    name: str | None
    username: str | None
    uri: str | None
    folder: str | None
    shared_users: int | None
    shared_groups: int | None


class SearchResultEntry(t.TypedDict):
    score: int
    id: str
    name: str | None
    username: str | None
    uri: str | None
    password: str | None


class FolderEntry(t.TypedDict):
    id: str
    name: str | None


class ResourceRecord(t.TypedDict, total=False):
    id: str
    metadata: str
    metadata_key_id: str
    metadata_key_type: str
    resource_type_id: str
    deleted: bool
    expired: str | None
    folder_parent_id: str | None
    personal: bool
    permissions: list["PermissionRecord"]


class PermissionRecord(t.TypedDict, total=False):
    id: str
    aro: str
    aro_foreign_key: str
    type: int
    user: "UserRecord"
    group: "GroupRecord"


class UserProfileRecord(t.TypedDict, total=False):
    first_name: str
    last_name: str


class UserRecord(t.TypedDict, total=False):
    id: str
    username: str
    active: bool
    deleted: bool
    profile: UserProfileRecord
    gpgkey: "GpgKeyRecord"


class FolderRecord(t.TypedDict, total=False):
    id: str
    name: str
    metadata: str
    metadata_key_id: str
    metadata_key_type: str
    folder_parent_id: str | None
    personal: bool
    created: str
    modified: str
    created_by: str
    modified_by: str


class SecretRecord(t.TypedDict, total=False):
    id: str
    user_id: str
    resource_id: str
    data: str
    created: str
    modified: str


class GpgKeyRecord(t.TypedDict, total=False):
    id: str
    user_id: str
    armored_key: str
    fingerprint: str


class GroupUserRecord(t.TypedDict, total=False):
    user_id: str
    user: UserRecord


class GroupRecord(t.TypedDict, total=False):
    id: str
    name: str
    groups_users: list[GroupUserRecord]


class Tokens(t.TypedDict):
    access_token: str
    refresh_token: str


class LoginTokens(Tokens):
    user_fingerprint: str


class RefreshTokens(t.TypedDict):
    access_token: str
    refresh_token: t.NotRequired[str]


class SessionData(t.TypedDict):
    format: int
    host: str
    user_id: str
    user_fingerprint: str
    access_token_exp: int | None
    gpg_home: str | None
    encrypted_tokens: str
    created_at: int


class JwtPayload(t.TypedDict, total=False):
    exp: int
    iat: int
    iss: str
    sub: str


class SessionValidation(t.TypedDict):
    host: str
    access_token: str


class PassboltApiResponse(t.TypedDict, total=False):
    header: dict[str, t.Any]
    body: t.Any
    access_token: str


class MetadataPrivateKeyRecord(t.TypedDict, total=False):
    user_id: str
    data: str


class MetadataKeyRecord(t.TypedDict, total=False):
    id: str
    armored_key: str
    fingerprint: str
    metadata_private_keys: list[MetadataPrivateKeyRecord]


class ResourceTypeDefinition(t.TypedDict, total=False):
    resource: dict[str, t.Any]


class ResourceTypeRecord(t.TypedDict, total=False):
    id: str
    slug: str
    default: bool
    definition: ResourceTypeDefinition
