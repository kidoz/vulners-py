"""A modern, typed client for the Vulners API."""

from ._client import AsyncVulners, Vulners
from ._exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    VulnersAPIError,
    VulnersError,
)

__version__ = "0.1.0"

__all__ = [
    "AsyncVulners",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "Vulners",
    "VulnersAPIError",
    "VulnersError",
    "__version__",
]
