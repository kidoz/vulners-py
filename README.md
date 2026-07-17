# vulners-py

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)](CHANGELOG.md)

A modern, strictly typed Python SDK for the [Vulners API](https://docs.vulners.com/docs/api/).
It provides matching synchronous and asynchronous clients, immutable Pydantic v2 models, resilient
HTTP handling, and no deprecated top-level compatibility aliases.

## Features

- Search, document retrieval, software/host/package/SBOM audits, and Smart Audit.
- ZIP, gzip, JSON, and NDJSON archive decoding with a stream-to-disk option.
- Reports, v4 subscriptions, legacy email/polling subscriptions, STIX, CPE, and search helpers.
- API-key loading from `VULNERS_API_KEY`, including `.env`-based development workflows.
- Retry/backoff, `Retry-After`, per-endpoint rate limiting, HTTP/2 support, and typed exceptions.
- Strict mypy, Ruff, and pytest checks with sync/async contract tests.

VScanner is intentionally excluded because it is deprecated.

## Requirements

- Python 3.10 or newer
- A [Vulners API key](https://vulners.com)

## Installation

```bash
uv add vulners-py
```

or:

```bash
pip install vulners-py
```

Optional performance extras:

```bash
uv add "vulners-py[http2,orjson]"
```

## Authentication

Create a local `.env` file that is not committed:

```dotenv
VULNERS_API_KEY=your-api-key
```

Load it into the environment before running an application:

```bash
set -a
source .env
set +a
```

The key can also be passed explicitly as `Vulners(api_key="...")`. Client representations never
contain the key.

Before wiring the SDK into your app, confirm the key in your `.env` is accepted with the bundled
preflight (one cheap, read-only call; exits `0` on success, `2` when no key is set):

```bash
uv run python examples/check_connection.py        # synchronous
uv run python examples/async_check_connection.py  # asynchronous
```

See [`examples/`](examples/) for runnable snippets that load `VULNERS_API_KEY` from `.env`.

## Quick start

### Synchronous

```python
from vulners import Vulners

with Vulners() as client:
    page = client.search.bulletins("wordpress 4.7", limit=10)
    document = client.documents.get("CVE-2024-23622")

for bulletin in page.documents:
    print(bulletin.id, bulletin.title)
print(document)
```

### Asynchronous

```python
import asyncio

from vulners import AsyncVulners


async def main() -> None:
    async with AsyncVulners() as client:
        async for bulletin in client.search.exploits_iter("CVE-2021-44228"):
            print(bulletin.id)


asyncio.run(main())
```

## Namespaces

| Namespace | Capabilities |
| --- | --- |
| `search` | Bulletins, exploits, iterators, history, and web vulnerability matching |
| `documents` | Get one/many documents, references, KB seeds, and KB updates |
| `audit` | Software, host, Linux, library, classic OS, Windows, CVE, SBOM, and Smart Audit |
| `archive` | v3/v4 collections, incremental updates, distributives, and Getsploit downloads |
| `reports` | Vulnerability, IP, scan, and host reports |
| `subscriptions` | v4 lifecycle plus legacy email subscriptions under `.email` |
| `webhooks` | Legacy polling/webhook subscriptions |
| `stix` | STIX bundle generation by bulletin ID |
| `misc` | Suggestions, autocomplete, CPE lookup, and WAF rules |

### Audit examples

```python
from pathlib import Path

from vulners import Vulners
from vulners.types import AuditSoftware

with Vulners() as client:
    matches = client.audit.software(
        (AuditSoftware(product="curl", vendor="haxx", version="8.0"),)
    )
    packages = client.audit.library(("pkg:pypi/requests@2.20.0",))
    sbom = client.audit.sbom(Path("bom.json"))
```

[Smart Audit](https://docs.vulners.com/docs/api/smart-audit/) is a preview endpoint billed per
submitted software string. Calling `client.audit.smart(...)` may incur account charges.

### Archive examples

```python
from pathlib import Path

from vulners import Vulners

with Vulners() as client:
    records = client.archive.collection_update("exploitdb", "2026-07-17T00:00:00")
    client.archive.collection_v4(
        "exploitdb",
        raw=True,
        destination=Path("exploitdb.ndjson.gz"),
    )
```

Decoded archive calls return immutable `ArchiveRecord` objects. `raw=True` requires a destination
and streams the response without loading the archive into memory.

### Subscriptions

```python
from vulners import Vulners
from vulners.types import LuceneSubscriptionQuery, WebhookSubscriptionDelivery

query = LuceneSubscriptionQuery(query="cvss:[9 TO *] AND family:cve")
delivery = WebhookSubscriptionDelivery(
    address="https://example.com/vulners",
    crontab="0 * * * *",
)

with Vulners() as client:
    created = client.subscriptions.create("Critical CVEs", query, delivery)
    print(created.id)
```

Create, update, and delete calls mutate remote account state. Legacy email subscriptions are under
`client.subscriptions.email`; legacy polling subscriptions are under `client.webhooks`.

## Error handling

```python
from vulners import AuthenticationError, RateLimitError, Vulners, VulnersAPIError

try:
    with Vulners() as client:
        client.search.bulletins("wordpress")
except AuthenticationError:
    print("Check VULNERS_API_KEY")
except RateLimitError as error:
    print(f"Retry after {error.retry_after!r} seconds")
except VulnersAPIError as error:
    print(f"Vulners API error {error.status_code}: {error.message}")
```

## Migration from the legacy wrapper

| Legacy wrapper | `vulners-py` |
| --- | --- |
| `find(query)` / `search_bulletins(query)` | `client.search.bulletins(query)` |
| `find_all(query)` | `client.search.bulletins_iter(query)` |
| `find_exploit(query)` | `client.search.exploits(query)` |
| `get_bulletin(id)` | `client.documents.get(id)` |
| `audit_software(...)` | `client.audit.software(...)` |
| `winaudit(...)` | `client.audit.winaudit(...)` |
| `vulnssummary_report(...)` | `client.reports.vulns_summary(...)` |

No deprecated top-level aliases or `DeprecationWarning` shims are included.

## Development

```bash
uv sync --all-extras
just check
```

Available recipes:

```bash
just fmt
just lint
just typecheck
just test
just check
```

Tests use mocked HTTP contracts by default. Run the bounded, read-only integration suite with a key
loaded from `.env`:

```bash
set -a
source .env
set +a
VULNERS_LIVE=1 uv run pytest tests/test_integration.py
```

The integration suite deliberately excludes billed Smart Audit/SBOM requests, archive bulk
downloads, and subscription mutations.

## License

Distributed under the [MIT License](LICENSE). Copyright © 2026 Aleksandr Pavlov
<ckidoz@gmail.com>.
