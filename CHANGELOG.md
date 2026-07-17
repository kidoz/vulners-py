# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-17

### Added

- Stable, strictly typed synchronous and asynchronous API namespaces.
- Discriminated subscription query and delivery models, typed polling results, STIX objects,
  audit advisories, and CVE-affected package/CPE models.
- Python 3.10 compatibility checks and a statically checked public-client contract.

### Changed

- Promoted legacy polling subscriptions to the documented `client.webhooks` namespace.
- Centralized package and HTTP user-agent version metadata at `1.0.0`.

### Removed

- Deprecated VScanner support remains intentionally excluded from the stable API.

## [0.1.0] - 2026-07-17

### Added

- Initial `vulners-py` 0.1.0 release.
- Typed synchronous and asynchronous clients for search, documents, audit, archives, reports,
  subscriptions, polling webhooks, STIX, and miscellaneous API helpers.
- Smart Audit and multipart SPDX/CycloneDX audit support.
- ZIP, gzip, JSON, and NDJSON archive decoding plus stream-to-disk downloads.
- Retry, rate-limit, typed-error, strict typing, and mocked API-contract test coverage.

### Removed

- Deprecated VScanner and legacy top-level compatibility aliases are intentionally not included.
