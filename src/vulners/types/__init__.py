"""Typed Vulners API response models."""

from .archive import ArchiveRecord
from .audit import (
    AuditMatch,
    AuditSoftware,
    CVEAuditResult,
    KBAuditResult,
    LegacyAuditResult,
    PackageAuditIssue,
    PackageAuditResult,
    SBOMAuditResult,
    SBOMComponent,
    SmartAuditResult,
    WindowsSoftware,
)
from .documents import BulletinReferences, BulletinWithReferences, KBSeeds
from .misc import CPEMatch, STIXBundle
from .reports import HostVulnsRow, IPSummaryRow, ScanListRow, VulnsListRow, VulnsSummaryRow
from .search import (
    HistoryEntry,
    SearchDocument,
    SearchPage,
    WebVulnerability,
    WebVulnerabilityResult,
)
from .subscriptions import (
    EmailSubscription,
    PollingDelivery,
    PollingSubscription,
    Subscription,
    SubscriptionDelivery,
    SubscriptionID,
    SubscriptionQuery,
)

__all__ = [
    "ArchiveRecord",
    "AuditMatch",
    "AuditSoftware",
    "BulletinReferences",
    "BulletinWithReferences",
    "CPEMatch",
    "CVEAuditResult",
    "EmailSubscription",
    "HistoryEntry",
    "HostVulnsRow",
    "IPSummaryRow",
    "KBAuditResult",
    "KBSeeds",
    "LegacyAuditResult",
    "PackageAuditIssue",
    "PackageAuditResult",
    "PollingDelivery",
    "PollingSubscription",
    "SBOMAuditResult",
    "SBOMComponent",
    "STIXBundle",
    "ScanListRow",
    "SearchDocument",
    "SearchPage",
    "SmartAuditResult",
    "Subscription",
    "SubscriptionDelivery",
    "SubscriptionID",
    "SubscriptionQuery",
    "VulnsListRow",
    "VulnsSummaryRow",
    "WebVulnerability",
    "WebVulnerabilityResult",
    "WindowsSoftware",
]
