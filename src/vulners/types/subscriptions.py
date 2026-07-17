"""Typed subscription and polling models."""

from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .audit import AuditSoftware
from .search import SearchDocument


class _OpenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)


class _SubscriptionQuery(_OpenModel):
    type: str


class LuceneSubscriptionQuery(_SubscriptionQuery):
    """A v4 subscription driven by a Lucene query."""

    type: Literal["query"] = "query"
    query: str


class SoftwareSubscriptionQuery(_SubscriptionQuery):
    """A v4 subscription driven by structured or CPE software inputs."""

    type: Literal["software"] = "software"
    software: tuple[AuditSoftware | str, ...]


class GenericHostSubscriptionQuery(_SubscriptionQuery):
    """A v4 subscription for a generic host inventory."""

    type: Literal["host/generic"] = "host/generic"
    software: tuple[AuditSoftware | str, ...]
    application: AuditSoftware | str | None = None
    operating_system: AuditSoftware | str | None = None
    hardware: AuditSoftware | str | None = None


class LinuxHostSubscriptionQuery(_SubscriptionQuery):
    """A v4 subscription for a classic Linux host inventory."""

    type: Literal["host/linux"] = "host/linux"
    os: str
    os_version: str
    packages: tuple[str, ...]


class WindowsHostSubscriptionQuery(_SubscriptionQuery):
    """A v4 subscription for a Windows host inventory."""

    type: Literal["host/windows"] = "host/windows"
    os: str
    os_version: str
    kb_list: tuple[str, ...]
    packages: tuple[str, ...]


class LinuxAuditSubscriptionQuery(_SubscriptionQuery):
    """A v4 subscription driven by the Linux v4 audit contract."""

    type: Literal["audit/linux"] = "audit/linux"
    os_name: str
    os_version: str
    packages: tuple[str, ...]
    os_arch: str | None = None
    include_unofficial: bool = False
    include_candidates: bool = False
    include_any_version: bool = False
    cvelist_metrics: bool = False


SubscriptionQuery: TypeAlias = Annotated[
    LuceneSubscriptionQuery
    | SoftwareSubscriptionQuery
    | GenericHostSubscriptionQuery
    | LinuxHostSubscriptionQuery
    | WindowsHostSubscriptionQuery
    | LinuxAuditSubscriptionQuery,
    Field(discriminator="type"),
]


class _SubscriptionDelivery(_OpenModel):
    type: str


class WebhookSubscriptionDelivery(_SubscriptionDelivery):
    """Push subscription delivery to a webhook address."""

    type: Literal["webhook"] = "webhook"
    address: str
    crontab: str


class PollingSubscriptionDelivery(_SubscriptionDelivery):
    """Pull-based subscription delivery configuration."""

    type: Literal["pooling"] = "pooling"
    endpoint: str | None = None


SubscriptionDelivery: TypeAlias = Annotated[
    WebhookSubscriptionDelivery | PollingSubscriptionDelivery,
    Field(discriminator="type"),
]


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

    result: tuple[SearchDocument, ...] = ()


_SUBSCRIPTIONS_ADAPTER = TypeAdapter(tuple[Subscription, ...])
_SUBSCRIPTION_ADAPTER = TypeAdapter(Subscription)
_SUBSCRIPTION_ID_ADAPTER = TypeAdapter(SubscriptionID)
_EMAIL_SUBSCRIPTIONS_ADAPTER = TypeAdapter(tuple[EmailSubscription, ...])
_EMAIL_SUBSCRIPTION_ADAPTER = TypeAdapter(EmailSubscription)
_POLLING_SUBSCRIPTIONS_ADAPTER = TypeAdapter(tuple[PollingSubscription, ...])
_POLLING_SUBSCRIPTION_ADAPTER = TypeAdapter(PollingSubscription)
_POLLING_DELIVERY_ADAPTER = TypeAdapter(PollingDelivery)
