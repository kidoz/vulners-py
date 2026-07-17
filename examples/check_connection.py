"""Verify that the API key in your .env works (synchronous).

Run it as your first integration step:

    uv run python examples/check_connection.py

It loads ``VULNERS_API_KEY`` from a local ``.env`` file, makes a single cheap,
read-only call, and reports whether the credentials are accepted. The process
exits ``0`` on success, ``1`` on an API/credential failure, and ``2`` when no key
is configured -- so it also works as a CI preflight or shell ``&&`` guard.
"""

from __future__ import annotations

import os
import sys

from _env import load_dotenv

from vulners import (
    AuthenticationError,
    RateLimitError,
    Vulners,
    VulnersAPIError,
    VulnersError,
)


def main() -> int:
    """Load the key, probe the API once, and report the outcome."""
    env_file = load_dotenv()
    if env_file is not None:
        print(f"Loaded environment from {env_file}")

    if not os.getenv("VULNERS_API_KEY"):
        print("VULNERS_API_KEY is not set. Create a .env file next to this repo:", file=sys.stderr)
        print("    VULNERS_API_KEY=your-api-key", file=sys.stderr)
        return 2

    try:
        with Vulners(timeout=30, retries=2, rate_limit=False) as client:
            # Autocomplete is a cheap, read-only endpoint that still requires a
            # valid key, which makes it a good credential/connectivity probe.
            suggestions = client.misc.autocomplete("type:cv")
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

    print(f"OK: the API key works and the Vulners API is reachable ({len(suggestions)} hits).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
