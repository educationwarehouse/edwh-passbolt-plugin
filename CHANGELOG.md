# Changelog

<!--next-version-placeholder-->

## v0.3.0 (2026-08-20)

### Feature
* **passbolt:** support unattended sessions and folder resolution

### Fix
* **httpx:** replaced httpx with requests (#3)

## v0.2.0 (2026-05-12)

### Feature

* **totp:** Added totp support to passbolt.search ([#1](https://github.com/educationwarehouse/edwh-passbolt-plugin/issues/1)) ([`74bdd76`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/74bdd76af4285fc99eb6071f4eda99ae18bbef94))

## v0.1.1 (2026-02-13)

### Fix

* Lower search threshold so 'docker' finds 'docker hub' ([`8c73286`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/8c73286232da963e6da2e8e1f148c0a4656712fa))

## v0.1.0 (2026-02-10)

### Feature

* Support sharing/unsharing passwords ([`a879c81`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/a879c817eb0ba1bb29702a17e6534f860fab31e1))
* Improved typing and docs ([`37d8a9c`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/37d8a9cbe64a2a9cb7e580b691af997798102124))
* `search` subcommand, disabled untested 'rotate' ([`2211cdb`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/2211cdbdb65c6d260c664aa854796f5a8c6d720c))
* List, add, set ([`852535f`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/852535ff125df52f41825138a5d8d21b54d2bcc6))
* Implemented authentication ([`6bc5573`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/6bc5573e4f904a6b6e5dec443533a14a0d9ed955))

### Fix

* **passphrase:** Use cli prompt instead of OS popup ([`201cd62`](https://github.com/educationwarehouse/edwh-passbolt-plugin/commit/201cd62925bac7986ee59be9f6b852a1c0dc112e))