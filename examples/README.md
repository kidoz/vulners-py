# Examples

Runnable snippets for integrating the `vulners-py` SDK. Every example reads your
API key from a local `.env` file, so you never hard-code or `export` it.

## 1. Configure your key

Create a `.env` file in the repository root (it is git-ignored):

```dotenv
VULNERS_API_KEY=your-api-key
```

The examples load it automatically via the dependency-free helper in `_env.py`
(`os.environ.setdefault`, so an already-exported `VULNERS_API_KEY` still wins).
In real applications, prefer [`python-dotenv`](https://pypi.org/project/python-dotenv/)
or your framework's settings loader.

## 2. Check that the key works

Run this first — it makes one cheap, read-only call and tells you whether the
key is accepted, without spending a search or incurring billed endpoints:

```bash
uv run python examples/check_connection.py        # synchronous
uv run python examples/async_check_connection.py  # asynchronous
```

Exit codes make it usable as a CI preflight or shell guard:

| Code | Meaning |
| --- | --- |
| `0` | Key works, API reachable |
| `1` | Auth rejected / rate limited / API error |
| `2` | No `VULNERS_API_KEY` configured |

```bash
uv run python examples/check_connection.py && uv run python examples/search.py
```

## 3. Explore

| File | Shows |
| --- | --- |
| `check_connection.py` | Verify the `.env` key works (sync preflight) |
| `async_check_connection.py` | Same probe on the async client |
| `search.py` | Iterate bulletin search results |
| `exploits.py` | Find public exploits for a CVE |
| `software_audit.py` | Audit structured software metadata |
| `linux_audit.py` | Audit an installed distro package |

All of these are read-only. Smart Audit, SBOM, archive bulk downloads, and
subscription mutations can be billed or mutate account state — see the top-level
`README.md` before calling them.
