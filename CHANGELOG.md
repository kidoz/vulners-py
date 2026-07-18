# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The 1.x series is a public-API stabilization period: patch releases preserve compatibility, while
minor releases may contain clearly documented breaking API refinements. Starting with 2.0.0, the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) strictly.

## [1.1.0] - 2026-07-18

This release intentionally refines the early public API while adoption is limited. Correcting the
namespace and method names now avoids carrying compatibility aliases and naming debt into future
feature development.

### Changed

- Rename the `client.documents` namespace to `client.bulletins`.
- Replace `client.documents.get(id)` and `client.documents.get_many(ids)` with
  `client.bulletins.by_id(id)` and `client.bulletins.by_ids(ids)`.
- Rename the auto-paginating search methods to `all_bulletins(...)` and `all_exploits(...)`.

### Removed

- Remove the former `client.documents` namespace, `client.search.by_id`,
  `search.bulletins_iter`, and `search.exploits_iter` names.

## [1.0.1] - 2026-07-17

### Added

- Typed WAF rule models matching the live `/api/v3/burp/rules/` response.
- Regression tests for credential redaction, cookie rejection, retry timing, search-window
  pagination, sync/async error parity, and disabled rate limiting.
- Python 3.14 CI coverage, PyPI classifiers, and project metadata links.

### Changed

- Use the canonical GET contract for bulletin history and clamp search pages to the 10,000-record
  API window.
- Honor HTTP-date `Retry-After` values and add async archive overload narrowing.

### Security

- Prevent legacy authenticated GET calls from placing API keys in query strings and HTTP logs.
- Reject and clear HTTP cookies so API responses cannot create replayed client state.

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

[1.1.0]: https://github.com/kidoz/vulners-py/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/kidoz/vulners-py/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/kidoz/vulners-py/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/kidoz/vulners-py/releases/tag/v0.1.0
