"""Tenant notification dispatch.

When a finished event meets a tenant's ``notify_level``, everyone on that
tenant's recipient list (SOC users + external emails) should be alerted.

Delivery is intentionally stubbed for now — `_deliver` only logs what *would*
be sent. Plugging in real SMTP later is a one-function change (see TODO).
"""

import logging

from sqlalchemy import select

from app.models.db import session_scope
from app.models.tenant import Tenant

logger = logging.getLogger(__name__)


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def recipients_for(tenant: Tenant) -> list[str]:
    """Resolve a tenant's recipient list to email addresses."""
    emails: list[str] = []
    for r in tenant.recipients:
        if r.user_id and r.user is not None and r.user.email:
            emails.append(r.user.email)
        elif r.email:
            emails.append(r.email)
    return emails


def maybe_notify(event_dict: dict) -> None:
    """Notify a tenant's list if a finished event meets its threshold.

    Called from the pipeline once per fully-processed event. Manages its own
    session and never raises into the pipeline.
    """
    group = event_dict.get("group")
    level = _as_int(event_dict.get("wazuh_level"))
    if not group or level is None:
        return
    try:
        with session_scope() as session:
            tenant = session.scalar(select(Tenant).where(Tenant.group == group))
            if tenant is None or level < tenant.notify_level:
                return
            emails = recipients_for(tenant)
            if emails:
                _deliver(emails, tenant, event_dict)
    except Exception as e:  # notification must never break the pipeline
        logger.warning("maybe_notify failed for %s: %s", group, e)


def _deliver(emails: list[str], tenant: Tenant, event_dict: dict) -> None:
    """Send the alert. TODO: integrate SMTP — for now we only log the intent."""
    logger.info(
        "[notify] tenant=%s level=%s event=%s → %d recipient(s): %s | %s",
        tenant.group,
        event_dict.get("wazuh_level"),
        event_dict.get("event_id"),
        len(emails),
        ", ".join(emails),
        event_dict.get("rule_description") or event_dict.get("event_type") or "",
    )
