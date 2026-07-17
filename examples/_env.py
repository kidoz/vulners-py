"""Tiny, dependency-free ``.env`` loader shared by the examples.

The SDK deliberately depends only on ``httpx`` and ``pydantic``, so the examples
avoid pulling in ``python-dotenv``. This helper reads a local ``.env`` file into
``os.environ`` so ``Vulners()`` can pick up ``VULNERS_API_KEY`` automatically.

In real applications prefer ``python-dotenv`` or your framework's settings loader.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(filename: str = ".env") -> Path | None:
    """Load ``KEY=VALUE`` lines from the nearest ``.env`` into ``os.environ``.

    Searches the current working directory and its parents, so the examples work
    whether they are run from the repository root or the ``examples`` folder.
    Already-set environment variables win (``os.environ.setdefault``), so an
    exported ``VULNERS_API_KEY`` is never overwritten by the file.

    Returns the path that was loaded, or ``None`` when no ``.env`` was found.
    """
    for directory in (Path.cwd(), *Path.cwd().parents):
        candidate = directory / filename
        if candidate.is_file():
            for raw_line in candidate.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.removeprefix("export ").strip()
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)
            return candidate
    return None
