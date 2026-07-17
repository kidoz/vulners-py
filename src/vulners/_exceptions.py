"""Exception hierarchy for Vulners API failures."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


class VulnersError(Exception):
    """Base exception for all SDK failures."""


class VulnersAPIError(VulnersError):
    """An HTTP or API-envelope error returned by Vulners."""

    def __init__(
        self,
        status_code: int,
        error_code: int | str | None,
        message: str,
        response: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.response = response


class AuthenticationError(VulnersAPIError):
    """Authentication or authorization failed."""


class RateLimitError(VulnersAPIError):
    """The API rate limit was exceeded."""

    def __init__(
        self,
        status_code: int,
        error_code: int | str | None,
        message: str,
        response: Mapping[str, object] | None = None,
        *,
        retry_after: float | None,
    ) -> None:
        super().__init__(status_code, error_code, message, response)
        self.retry_after = retry_after


class NotFoundError(VulnersAPIError):
    """The requested API resource was not found."""


class ServerError(VulnersAPIError):
    """The Vulners service returned a 5xx response."""
