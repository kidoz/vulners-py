"""Typed subscription and polling models."""

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class _OpenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)


class SubscriptionQuery(_OpenModel):
    """Discriminated v4 subscription query payload."""

    type: str


class SubscriptionDelivery(_OpenModel):
    """Webhook or polling delivery configuration."""

    type: str
    address: str | None = None
    crontab: str | None = None
    endpoint: str | None = None


class Subscription(_OpenModel):
    """A v4 Vulners subscription."""

    id: str
    name: str | None = None
    query: SubscriptionQuery | None = None
    delivery: SubscriptionDelivery | None = None
    bulletin_fields: tuple[str, ...] = Field(default=(), alias="bulletinFields")
    timestamp_source: str | None = Field(default=None, alias="timestampSource")
    is_active: bool = Field(default=True, alias="isActive")
    send_empty_result: bool = Field(default=False, alias="sendEmptyResult")


class SubscriptionID(_OpenModel):
    """Identifier returned by subscription mutations."""

    id: str


class EmailSubscription(_OpenModel):
    """A legacy email subscription."""

    id: str
    query: str | None = None
    email: str | None = None
    active: bool | str | None = None


class PollingSubscription(_OpenModel):
    """A legacy polling subscription."""

    id: str | None = None
    subscriptionid: str | None = None
    query: str | None = None
    active: bool | str | None = None
    webhook: str | None = None


class PollingDelivery(_OpenModel):
    """Stored result returned by a legacy polling subscription."""

    result: tuple[Mapping[str, object], ...] = ()


_SUBSCRIPTIONS_ADAPTER = TypeAdapter(tuple[Subscription, ...])
_SUBSCRIPTION_ADAPTER = TypeAdapter(Subscription)
_SUBSCRIPTION_ID_ADAPTER = TypeAdapter(SubscriptionID)
_EMAIL_SUBSCRIPTIONS_ADAPTER = TypeAdapter(tuple[EmailSubscription, ...])
_EMAIL_SUBSCRIPTION_ADAPTER = TypeAdapter(EmailSubscription)
_POLLING_SUBSCRIPTIONS_ADAPTER = TypeAdapter(tuple[PollingSubscription, ...])
_POLLING_SUBSCRIPTION_ADAPTER = TypeAdapter(PollingSubscription)
_POLLING_DELIVERY_ADAPTER = TypeAdapter(PollingDelivery)
