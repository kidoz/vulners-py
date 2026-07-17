# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
