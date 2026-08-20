# edwh-passbolt-plugin

[![PyPI - Version](https://img.shields.io/pypi/v/edwh-passbolt-plugin.svg)](https://pypi.org/project/edwh-passbolt-plugin)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/edwh-passbolt-plugin.svg)](https://pypi.org/project/edwh-passbolt-plugin)

-----

**Table of Contents**

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Installation

```console
edwh plugin.add passbolt
```

If you don't have `edwh` yet:

```console
uvenv install edwh[passbolt]
# or pipx, pip, ...
```

## Usage

Typical flow starts with a login:

```console
edwh passbolt.login
```

You will be prompted for:
- Passbolt host URL (e.g. `https://passbolt.edwh.nl`).
- Your Passbolt user UUID (find it in the Passbolt UI under users; it is in the URL).
- How to import a private key: provide a path to a recovery kit, paste a PGP private key block, or skip.
- Your GPG key passphrase.

After login, your OS may occasionally show a passphrase prompt popup (via `gpg-agent`/`pinentry`). 
This depends on your system and the GPG Agent cache/expiry time.

For unattended commands, first create the local session with `edwh passbolt.login`,
then set `PASSBOLT_GPG_PASSPHRASE` to the passphrase for that session's GPG key.
The plugin uses it to unlock the encrypted session and perform required GPG operations.

Main commands:

```console
edwh passbolt.list [--folder ...]
edwh passbolt.get <name-or-id> [--field password|user|uri]
edwh passbolt.set [--name ...] [--password ...] [--username ...] [--uri ...] [--folder ...]
edwh passbolt.search <term> [--limit 10] [--threshold 70]
edwh passbolt.list-folders
edwh passbolt.delete <name-or-id>
edwh passbolt.share <name-or-id> [--user "Alice, Bob"] [--group "Admins"] [--permission read|update|owner]
edwh passbolt.unshare <name-or-id> [--user "Alice, Bob"] [--group "Admins"]
```

For full command listings and help text:

```console
edwh help passbolt
edwh help passbolt.<command>
```

## License

`edwh-passbolt-plugin` is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
