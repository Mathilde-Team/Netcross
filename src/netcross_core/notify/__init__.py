# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.notify -- notifications sortantes sur seuil de gravite
(webhook, Slack, courriel), issue #280. Voir docs/notifications.md.
"""

from netcross_core.logging_config import get_logger
from netcross_core.notify.dispatch import (
    CHANNELS,
    DeliveryResult,
    notifiers_from_config,
    run_notifications,
    send_notifications,
)
from netcross_core.notify.summary import (
    DETAIL_LEVELS,
    SEVERITIES,
    NotificationSummary,
    build_summary,
    findings_fingerprint,
    meets_threshold,
)
from netcross_core.notify.transports import (
    EmailNotifier,
    Notifier,
    NotifyError,
    SlackNotifier,
    WebhookNotifier,
)

logger = get_logger(__name__)

__all__ = [
    "CHANNELS",
    "DETAIL_LEVELS",
    "SEVERITIES",
    "DeliveryResult",
    "EmailNotifier",
    "NotificationSummary",
    "Notifier",
    "NotifyError",
    "SlackNotifier",
    "WebhookNotifier",
    "build_summary",
    "findings_fingerprint",
    "meets_threshold",
    "notifiers_from_config",
    "run_notifications",
    "send_notifications",
]
