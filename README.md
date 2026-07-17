# vulners-py

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#project-status)

A modern, strictly typed Python SDK for the [Vulners API](https://vulners.com).
It provides synchronous and asynchronous clients, typed Pydantic v2 response models,
and resilient HTTP handling without the legacy wrapper's compatibility aliases.

> **Alpha:** version 0.1.0 implements the search namespace. Additional Vulners API
> namespaces will be added incrementally.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Search](#search)
- [Configuration](#configuration)
- [Error handling](#error-handling)
- [Migration from the legacy wrapper](#migration-from-the-legacy-wrapper)
- [Development](#development)
- [Project status](#project-status)
- [License](#license)

## Features

- Synchronous `Vulners` and asynchronous `AsyncVulners` clients.
- Typed, immutable search pages and documents powered by Pydantic v2.
- Bulletin and exploit search with transparent sync and async pagination.
- API-key authentication from the constructor or `VULNERS_API_KEY` environment variable.
- Retries with exponential backoff, `Retry-After` support, and optional server-advertised
  rate limiting.
- Typed exceptions for authentication, rate-limit, not-found, server, and API-envelope
  errors.

## Requirements

- Python 3.10 or newer
- A [Vulners API key](https://vulners.com)

## Installation

Install with your preferred package manager:

```bash
uv add vulners-py
```

```bash
pip install vulners-py
```

Install the optional HTTP/2 or JSON acceleration extras when needed:

```bash
uv add "vulners-py[http2,orjson]"
```

## Quick start

Set your API key once in the environment:

```bash
export VULNERS_API_KEY="your-api-key"
```

### Synchronous client

```python
from vulners import Vulners

with Vulners() as client:
    page = client.search.bulletins("wordpress 4.7", limit=10)

for bulletin in page.documents:
    print(bulletin.id, bulletin.title)
```

### Asynchronous client

```python
import asyncio

from vulners import AsyncVulners


async def main() -> None:
    async with AsyncVulners() as client:
        page = await client.search.bulletins("wordpress 4.7", limit=10)

    for bulletin in page.documents:
        print(bulletin.id, bulletin.title)


asyncio.run(main())
```

You can also pass the key explicitly: `Vulners(api_key="your-api-key")`.

## Search

`client.search` currently provides the following methods:

```python
from vulners import Vulners

with Vulners() as client:
    # A typed SearchPage, containing immutable SearchDocument instances.
    page = client.search.bulletins("type:cve AND wordpress", limit=20, offset=0)

    # Iterate all bulletin documents across pages.
    for bulletin in client.search.bulletins_iter("wordpress"):
        print(bulletin.id)

    # Search public exploits, optionally matching particular fields.
    exploits = client.search.exploits("CVE-2024-1234", lookup_fields=("title",))
```

For asynchronous iteration, use `async for` with the corresponding iterator:

```python
async for bulletin in client.search.bulletins_iter("wordpress"):
    print(bulletin.id)
```

Use `await client.search.bulletins(...)` and `await client.search.exploits(...)` for
single-page asynchronous searches.

## Configuration

Both clients accept the same settings, except that the asynchronous client accepts an
`httpx.AsyncClient` escape hatch.

| Setting | Default | Purpose |
| --- | --- | --- |
| `api_key` | `VULNERS_API_KEY` | Vulners API key. |
| `base_url` | `"https://vulners.com"` | API base URL, useful for testing. |
| `timeout` | `60.0` | Per-request HTTP timeout in seconds or an `httpx.Timeout`. |
| `proxy` | `None` | Optional proxy URL. |
| `retries` | `3` | Maximum total attempts for retryable requests. |
| `rate_limit` | `True` | Honor rate-limit headers returned by the API. |
| `http_client` | `None` | Caller-owned configured HTTPX client. |

## Error handling

All SDK exceptions inherit from `VulnersError`. Handle the typed API errors when a
specific recovery action is useful:

```python
from vulners import AuthenticationError, RateLimitError, Vulners, VulnersAPIError

try:
    with Vulners() as client:
        client.search.bulletins("wordpress")
except AuthenticationError:
    print("Check VULNERS_API_KEY.")
except RateLimitError as error:
    print(f"Try again after {error.retry_after!r} seconds.")
except VulnersAPIError as error:
    print(f"Vulners API error {error.status_code}: {error.message}")
```

## Migration from the legacy wrapper

The rewrite uses namespaced methods and does not include deprecated top-level aliases.

| Legacy wrapper | `vulners-py` |
| --- | --- |
| `search.search_bulletins(query)` | `client.search.bulletins(query)` |
| `search.search_bulletins_all(query)` | `client.search.bulletins_iter(query)` |
| `search.search_exploits(query)` | `client.search.exploits(query)` |
| `search.search_exploits_all(query)` | `client.search.exploits_iter(query)` |

## Development

This project uses [uv](https://docs.astral.sh/uv/) and [just](https://just.systems/).

```bash
uv sync
just check
```

Available recipes:

```bash
just fmt       # format code
just lint      # verify formatting and linting
just typecheck # run strict mypy
just test      # run the test suite with coverage
just check     # run all verification steps
```

## Project status

`vulners-py` is in alpha. The public API is intentionally small while the typed rewrite
is built and verified namespace by namespace. The current release supports search only.

## License

Distributed under the [MIT License](LICENSE). Copyright © 2026 Aleksandr Pavlov.
