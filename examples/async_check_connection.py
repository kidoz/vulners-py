"""Verify that the API key in your .env works (asynchronous).

    uv run python examples/async_check_connection.py

Same credential/connectivity probe as ``check_connection.py``, using the
``AsyncVulners`` client so you can confirm the async path and event-loop wiring
before integrating. Exit codes match the sync version (0 ok, 1 error, 2 no key).
"""

from __future__ import annotations

import asyncio
import os
import sys

from _env import load_dotenv

from vulners import (
    AsyncVulners,
    AuthenticationError,
    RateLimitError,
    VulnersAPIError,
    VulnersError,
)


async def _probe() -> int:
    """Open an async client and issue one read-only call."""
    async with AsyncVulners(timeout=30, retries=2, rate_limit=False) as client:
        suggestions = await client.misc.autocomplete("type:cv")
    print(f"OK: the API key works and the Vulners API is reachable ({len(suggestions)} hits).")
    return 0


def main() -> int:
    """Load the key, run the async probe, and translate failures to exit codes."""
    env_file = load_dotenv()
    if env_file is not None:
        print(f"Loaded environment from {env_file}")

    if not os.getenv("VULNERS_API_KEY"):
        print("VULNERS_API_KEY is not set. Create a .env file next to this repo:", file=sys.stderr)
        print("    VULNERS_API_KEY=your-api-key", file=sys.stderr)
        return 2

    try:
        return asyncio.run(_probe())
    except AuthenticationError:
        print("FAILED: the API key was rejected (check VULNERS_API_KEY).", file=sys.stderr)
        return 1
    except RateLimitError as error:
        print(f"RATE LIMITED: retry after {error.retry_after!r} seconds.", file=sys.stderr)
        return 1
    except VulnersAPIError as error:
        print(f"API ERROR {error.status_code}: {error.message}", file=sys.stderr)
        return 1
    except VulnersError as error:
        print(f"CLIENT ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
