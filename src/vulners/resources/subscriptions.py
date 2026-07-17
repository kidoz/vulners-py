"""Sync and async subscription resources."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Final, Literal

from ..types.subscriptions import (
    _EMAIL_SUBSCRIPTION_ADAPTER,
    _EMAIL_SUBSCRIPTIONS_ADAPTER,
    _POLLING_DELIVERY_ADAPTER,
    _POLLING_SUBSCRIPTION_ADAPTER,
    _POLLING_SUBSCRIPTIONS_ADAPTER,
    _SUBSCRIPTION_ADAPTER,
    _SUBSCRIPTION_ID_ADAPTER,
    _SUBSCRIPTIONS_ADAPTER,
    EmailSubscription,
    PollingDelivery,
    PollingSubscription,
    Subscription,
    SubscriptionDelivery,
    SubscriptionID,
    SubscriptionQuery,
)

if TYPE_CHECKING:
    from .._transport import AsyncTransport, ResponseData, SyncTransport

_LIST: Final = "/api/v4/subscriptions/list/"
_GET: Final = "/api/v4/subscriptions/get/"
_CREATE: Final = "/api/v4/subscriptions/create/"
_UPDATE: Final = "/api/v4/subscriptions/update/"
_DELETE: Final = "/api/v4/subscriptions/delete/"
_EMAIL_LIST: Final = "/api/v3/subscriptions/listEmailSubscriptions/"
_EMAIL_ADD: Final = "/api/v3/subscriptions/addEmailSubscription/"
_EMAIL_EDIT: Final = "/api/v3/subscriptions/editEmailSubscription/"
_EMAIL_DELETE: Final = "/api/v3/subscriptions/removeEmailSubscription/"
_WEBHOOK_LIST: Final = "/api/v3/subscriptions/listWebhookSubscriptions/"
_WEBHOOK_ADD: Final = "/api/v3/subscriptions/addWebhookSubscription/"
_WEBHOOK_EDIT: Final = "/api/v3/subscriptions/editWebhookSubscription/"
_WEBHOOK_DELETE: Final = "/api/v3/subscriptions/removeWebhookSubscription/"
_WEBHOOK_READ: Final = "/api/v3/subscriptions/webhook"

_DEFAULT_FIELDS: Final = (
    "title",
    "short_description",
    "type",
    "href",
    "published",
    "modified",
    "ai_score",
)


def _result(data: ResponseData) -> object:
    if not isinstance(data, Mapping) or "result" not in data:
        msg = "Unexpected subscription response shape"
        raise ValueError(msg)
    return data["result"]


def _subscription_payload(
    name: str,
    query: SubscriptionQuery,
    delivery: SubscriptionDelivery,
    license_id: str | None,
    bulletin_fields: Sequence[str],
    is_active: bool,
    timestamp_source: str,
    send_empty_result: bool,
) -> dict[str, object]:
    return {
        "name": name,
        "query": query.model_dump(mode="json", exclude_none=True),
        "delivery": delivery.model_dump(mode="json", exclude_none=True),
        "licenseId": license_id,
        "bulletinFields": list(bulletin_fields),
        "isActive": is_active,
        "timestampSource": timestamp_source,
        "sendEmptyResult": send_empty_result,
    }


class EmailSubscriptionsResource:
    """Legacy synchronous v3 email subscription operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def list(self) -> tuple[EmailSubscription, ...]:
        """List legacy email subscriptions."""
        data = self._transport.request("GET", _EMAIL_LIST, add_api_key=True)
        subscriptions = data.get("subscriptions", ()) if isinstance(data, Mapping) else ()
        return _EMAIL_SUBSCRIPTIONS_ADAPTER.validate_python(subscriptions)

    def add(
        self,
        query: str,
        email: str,
        *,
        format: Literal["html", "json", "pdf"] = "html",
        crontab: str | None = None,
        query_type: str = "lucene",
    ) -> EmailSubscription:
        """Create a legacy email subscription."""
        payload: dict[str, object] = {
            "query": query,
            "email": email,
            "format": format,
            "query_type": query_type,
        }
        if crontab is not None:
            payload["crontab"] = crontab
        data = self._transport.request("POST", _EMAIL_ADD, json=payload, add_api_key=True)
        return _EMAIL_SUBSCRIPTION_ADAPTER.validate_python(data)

    def edit(
        self,
        id: str,
        *,
        format: Literal["html", "json", "pdf"] | None = None,
        crontab: str | None = None,
        active: bool | None = None,
    ) -> EmailSubscription:
        """Modify a legacy email subscription."""
        payload: dict[str, object] = {"subscriptionid": id}
        if format is not None:
            payload["format"] = format
        if crontab is not None:
            payload["crontab"] = crontab
        if active is not None:
            payload["active"] = "true" if active else "false"
        data = self._transport.request("POST", _EMAIL_EDIT, json=payload, add_api_key=True)
        return _EMAIL_SUBSCRIPTION_ADAPTER.validate_python(data)

    def delete(self, id: str) -> None:
        """Delete a legacy email subscription."""
        self._transport.request(
            "POST", _EMAIL_DELETE, json={"subscriptionid": id}, add_api_key=True
        )


class SubscriptionsResource:
    """Synchronous v4 subscription operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport
        self.email = EmailSubscriptionsResource(transport)

    def list(self) -> tuple[Subscription, ...]:
        """List subscriptions through ``GET /api/v4/subscriptions/list/``."""
        return _SUBSCRIPTIONS_ADAPTER.validate_python(
            _result(self._transport.request("GET", _LIST))
        )

    def get(self, id: str) -> Subscription:
        """Get one subscription through ``GET /api/v4/subscriptions/get/``."""
        data = self._transport.request("GET", _GET, params={"subscription_id": id})
        return _SUBSCRIPTION_ADAPTER.validate_python(_result(data))

    def create(
        self,
        name: str,
        query: SubscriptionQuery,
        delivery: SubscriptionDelivery,
        *,
        license_id: str | None = None,
        bulletin_fields: Sequence[str] = _DEFAULT_FIELDS,
        is_active: bool = True,
        timestamp_source: str = "modified",
        send_empty_result: bool = False,
    ) -> SubscriptionID:
        """Create a subscription through ``POST /api/v4/subscriptions/create/``."""
        payload = _subscription_payload(
            name,
            query,
            delivery,
            license_id,
            bulletin_fields,
            is_active,
            timestamp_source,
            send_empty_result,
        )
        return _SUBSCRIPTION_ID_ADAPTER.validate_python(
            _result(self._transport.request("POST", _CREATE, json=payload))
        )

    def update(
        self,
        id: str,
        name: str,
        query: SubscriptionQuery,
        delivery: SubscriptionDelivery,
        *,
        license_id: str | None = None,
        bulletin_fields: Sequence[str] = _DEFAULT_FIELDS,
        is_active: bool = True,
        timestamp_source: str = "modified",
        send_empty_result: bool = False,
    ) -> SubscriptionID:
        """Update a subscription through ``PUT /api/v4/subscriptions/update/``."""
        payload = _subscription_payload(
            name,
            query,
            delivery,
            license_id,
            bulletin_fields,
            is_active,
            timestamp_source,
            send_empty_result,
        )
        payload["id"] = id
        return _SUBSCRIPTION_ID_ADAPTER.validate_python(
            _result(self._transport.request("PUT", _UPDATE, json=payload))
        )

    def delete(self, id: str) -> SubscriptionID:
        """Delete a subscription through ``DELETE /api/v4/subscriptions/delete/``."""
        data = self._transport.request("DELETE", _DELETE, params={"id": id})
        return _SUBSCRIPTION_ID_ADAPTER.validate_python(_result(data))


class WebhooksResource:
    """Synchronous legacy polling-subscription operations."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport

    def list(self) -> tuple[PollingSubscription, ...]:
        """List polling subscriptions."""
        data = self._transport.request("GET", _WEBHOOK_LIST, add_api_key=True)
        subscriptions = data.get("subscriptions", ()) if isinstance(data, Mapping) else ()
        return _POLLING_SUBSCRIPTIONS_ADAPTER.validate_python(subscriptions)

    def add(self, query: str) -> PollingSubscription:
        """Create a polling subscription."""
        data = self._transport.request(
            "POST", _WEBHOOK_ADD, json={"query": query}, add_api_key=True
        )
        return _POLLING_SUBSCRIPTION_ADAPTER.validate_python(data)

    def edit(self, id: str, *, active: bool) -> None:
        """Change a polling subscription's active state."""
        self._transport.request(
            "POST",
            _WEBHOOK_EDIT,
            json={"subscriptionid": id, "active": "true" if active else "false"},
            add_api_key=True,
        )

    def enable(self, id: str, active: bool) -> None:
        """Enable or disable a polling subscription."""
        self.edit(id, active=active)

    def delete(self, id: str) -> None:
        """Delete a polling subscription."""
        self._transport.request(
            "POST", _WEBHOOK_DELETE, json={"subscriptionid": id}, add_api_key=True
        )

    def read(self, id: str, *, newest_only: bool = True) -> PollingDelivery:
        """Read stored polling deliveries."""
        data = self._transport.request(
            "GET",
            _WEBHOOK_READ,
            params={"subscriptionid": id, "newest_only": "true" if newest_only else "false"},
            add_api_key=True,
        )
        return _POLLING_DELIVERY_ADAPTER.validate_python(data)


class AsyncEmailSubscriptionsResource:
    """Legacy asynchronous v3 email subscription operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def list(self) -> tuple[EmailSubscription, ...]:
        """List legacy email subscriptions."""
        data = await self._transport.request("GET", _EMAIL_LIST, add_api_key=True)
        subscriptions = data.get("subscriptions", ()) if isinstance(data, Mapping) else ()
        return _EMAIL_SUBSCRIPTIONS_ADAPTER.validate_python(subscriptions)

    async def add(
        self,
        query: str,
        email: str,
        *,
        format: Literal["html", "json", "pdf"] = "html",
        crontab: str | None = None,
        query_type: str = "lucene",
    ) -> EmailSubscription:
        """Create a legacy email subscription."""
        payload: dict[str, object] = {
            "query": query,
            "email": email,
            "format": format,
            "query_type": query_type,
        }
        if crontab is not None:
            payload["crontab"] = crontab
        data = await self._transport.request("POST", _EMAIL_ADD, json=payload, add_api_key=True)
        return _EMAIL_SUBSCRIPTION_ADAPTER.validate_python(data)

    async def edit(
        self,
        id: str,
        *,
        format: Literal["html", "json", "pdf"] | None = None,
        crontab: str | None = None,
        active: bool | None = None,
    ) -> EmailSubscription:
        """Modify a legacy email subscription."""
        payload: dict[str, object] = {"subscriptionid": id}
        if format is not None:
            payload["format"] = format
        if crontab is not None:
            payload["crontab"] = crontab
        if active is not None:
            payload["active"] = "true" if active else "false"
        data = await self._transport.request("POST", _EMAIL_EDIT, json=payload, add_api_key=True)
        return _EMAIL_SUBSCRIPTION_ADAPTER.validate_python(data)

    async def delete(self, id: str) -> None:
        """Delete a legacy email subscription."""
        await self._transport.request(
            "POST", _EMAIL_DELETE, json={"subscriptionid": id}, add_api_key=True
        )


class AsyncSubscriptionsResource:
    """Asynchronous v4 subscription operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport
        self.email = AsyncEmailSubscriptionsResource(transport)

    async def list(self) -> tuple[Subscription, ...]:
        """List subscriptions through ``GET /api/v4/subscriptions/list/``."""
        return _SUBSCRIPTIONS_ADAPTER.validate_python(
            _result(await self._transport.request("GET", _LIST))
        )

    async def get(self, id: str) -> Subscription:
        """Get one subscription through ``GET /api/v4/subscriptions/get/``."""
        data = await self._transport.request("GET", _GET, params={"subscription_id": id})
        return _SUBSCRIPTION_ADAPTER.validate_python(_result(data))

    async def create(
        self,
        name: str,
        query: SubscriptionQuery,
        delivery: SubscriptionDelivery,
        *,
        license_id: str | None = None,
        bulletin_fields: Sequence[str] = _DEFAULT_FIELDS,
        is_active: bool = True,
        timestamp_source: str = "modified",
        send_empty_result: bool = False,
    ) -> SubscriptionID:
        """Create a subscription through ``POST /api/v4/subscriptions/create/``."""
        payload = _subscription_payload(
            name,
            query,
            delivery,
            license_id,
            bulletin_fields,
            is_active,
            timestamp_source,
            send_empty_result,
        )
        data = await self._transport.request("POST", _CREATE, json=payload)
        return _SUBSCRIPTION_ID_ADAPTER.validate_python(_result(data))

    async def update(
        self,
        id: str,
        name: str,
        query: SubscriptionQuery,
        delivery: SubscriptionDelivery,
        *,
        license_id: str | None = None,
        bulletin_fields: Sequence[str] = _DEFAULT_FIELDS,
        is_active: bool = True,
        timestamp_source: str = "modified",
        send_empty_result: bool = False,
    ) -> SubscriptionID:
        """Update a subscription through ``PUT /api/v4/subscriptions/update/``."""
        payload = _subscription_payload(
            name,
            query,
            delivery,
            license_id,
            bulletin_fields,
            is_active,
            timestamp_source,
            send_empty_result,
        )
        payload["id"] = id
        data = await self._transport.request("PUT", _UPDATE, json=payload)
        return _SUBSCRIPTION_ID_ADAPTER.validate_python(_result(data))

    async def delete(self, id: str) -> SubscriptionID:
        """Delete a subscription through ``DELETE /api/v4/subscriptions/delete/``."""
        data = await self._transport.request("DELETE", _DELETE, params={"id": id})
        return _SUBSCRIPTION_ID_ADAPTER.validate_python(_result(data))


class AsyncWebhooksResource:
    """Asynchronous legacy polling-subscription operations."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def list(self) -> tuple[PollingSubscription, ...]:
        """List polling subscriptions."""
        data = await self._transport.request("GET", _WEBHOOK_LIST, add_api_key=True)
        subscriptions = data.get("subscriptions", ()) if isinstance(data, Mapping) else ()
        return _POLLING_SUBSCRIPTIONS_ADAPTER.validate_python(subscriptions)

    async def add(self, query: str) -> PollingSubscription:
        """Create a polling subscription."""
        data = await self._transport.request(
            "POST", _WEBHOOK_ADD, json={"query": query}, add_api_key=True
        )
        return _POLLING_SUBSCRIPTION_ADAPTER.validate_python(data)

    async def edit(self, id: str, *, active: bool) -> None:
        """Change a polling subscription's active state."""
        await self._transport.request(
            "POST",
            _WEBHOOK_EDIT,
            json={"subscriptionid": id, "active": "true" if active else "false"},
            add_api_key=True,
        )

    async def enable(self, id: str, active: bool) -> None:
        """Enable or disable a polling subscription."""
        await self.edit(id, active=active)

    async def delete(self, id: str) -> None:
        """Delete a polling subscription."""
        await self._transport.request(
            "POST", _WEBHOOK_DELETE, json={"subscriptionid": id}, add_api_key=True
        )

    async def read(self, id: str, *, newest_only: bool = True) -> PollingDelivery:
        """Read stored polling deliveries."""
        data = await self._transport.request(
            "GET",
            _WEBHOOK_READ,
            params={"subscriptionid": id, "newest_only": "true" if newest_only else "false"},
            add_api_key=True,
        )
        return _POLLING_DELIVERY_ADAPTER.validate_python(data)
