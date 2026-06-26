"""
Tenant registry service.

Postgres is the source of truth for tenants (companies/groups/agents) and their
settings. tenants.yaml seeds the DB on first run; thereafter the DB is canonical.
A small in-memory cache of per-tenant detection thresholds lets the pipeline
decide ingestion without a DB hit per alert.
"""

import logging
import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import session_scope
from app.models.tenant import Agent, NotificationRecipient, Tenant, TenantContact
from app.models.user import User
from app.tenants.tenants import load_tenants
from app.ingestion.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

# ── Threshold cache (read by the pipeline, written on startup/PATCH) ──────────
_default_min_level: int = settings.MIN_ALERT_LEVEL
_min_levels: dict[str, int] = {}          # group -> min_level
_cache_lock = threading.Lock()


def min_level_for(group: str | None) -> int:
    """Detection threshold for a group; the global default if unknown/unattributed."""
    if not group:
        return _default_min_level
    with _cache_lock:
        return _min_levels.get(group, _default_min_level)


def floor_min_level() -> int:
    """Lowest threshold across all tenants (and the default) — the pipeline's query floor."""
    with _cache_lock:
        return min([_default_min_level, *_min_levels.values()]) if _min_levels else _default_min_level


def refresh_cache(session: Session) -> None:
    """Reload the threshold cache from the DB."""
    rows = session.execute(select(Tenant.group, Tenant.min_level)).all()
    with _cache_lock:
        _min_levels.clear()
        _min_levels.update({group: lvl for group, lvl in rows})


# ── Seeding / registration ────────────────────────────────────────────────────
def seed_from_yaml_if_empty(session: Session) -> None:
    """Populate the registry from tenants.yaml the first time (empty DB)."""
    if session.scalar(select(Tenant).limit(1)) is not None:
        return
    for t in load_tenants():
        tenant = Tenant(company=t.company, group=t.group, min_level=settings.MIN_ALERT_LEVEL)
        tenant.agents = [Agent(name=a.name) for a in t.agents]
        session.add(tenant)
    logger.info("Seeded tenant registry from tenants.yaml")


def register_with_wazuh(session: Session, client: WazuhClient) -> None:
    """Register every tenant's group + agents in Wazuh and store the agent ids."""
    tenants = session.scalars(select(Tenant)).all()
    for tenant in tenants:
        try:
            client.create_group(tenant.group)
            for agent in tenant.agents:
                agent.wazuh_agent_id = client.register_agent(agent.name)
                client.assign_agent_to_group(agent.wazuh_agent_id, tenant.group)
        except Exception as e:  # Wazuh hiccup shouldn't block boot
            logger.warning("Wazuh registration failed for %s: %s", tenant.group, e)


# ── Reads / writes for the API ────────────────────────────────────────────────
def _serialize_contact(c: TenantContact) -> dict:
    return {"id": c.id, "name": c.name, "role": c.role, "email": c.email, "phone": c.phone}


def _serialize_recipient(r: NotificationRecipient) -> dict:
    if r.user_id and r.user is not None:
        return {
            "id": r.id,
            "kind": "user",
            "user_id": r.user_id,
            "username": r.user.username,
            "email": r.user.email,
        }
    return {"id": r.id, "kind": "email", "email": r.email}


def _serialize(tenant: Tenant) -> dict:
    return {
        "company": tenant.company,
        "group": tenant.group,
        "min_level": tenant.min_level,
        "notify_level": tenant.notify_level,
        "window_size": tenant.window_size,
        "description": tenant.description,
        "industry": tenant.industry,
        "website": tenant.website,
        "phone": tenant.phone,
        "address": tenant.address,
        "agents": [
            {"name": a.name, "wazuh_agent_id": a.wazuh_agent_id} for a in tenant.agents
        ],
        "contacts": [_serialize_contact(c) for c in tenant.contacts],
        "recipients": [_serialize_recipient(r) for r in tenant.recipients],
    }


def _get(session: Session, group: str) -> Tenant | None:
    return session.scalar(select(Tenant).where(Tenant.group == group))


def list_tenants(session: Session) -> list[dict]:
    tenants = session.scalars(select(Tenant).order_by(Tenant.company)).all()
    return [_serialize(t) for t in tenants]


# Fields the API may patch on a tenant (group is the immutable key).
_EDITABLE_FIELDS = (
    "company", "description", "industry", "website", "phone", "address",
    "min_level", "notify_level", "window_size",
)


def group_windows() -> dict[str, int]:
    """Map of group -> AI assessment window size, read by the assess worker."""
    with session_scope() as session:
        rows = session.execute(select(Tenant.group, Tenant.window_size)).all()
        return {group: size for group, size in rows}


def update_tenant(session: Session, group: str, fields: dict) -> dict | None:
    tenant = _get(session, group)
    if tenant is None:
        return None
    for key in _EDITABLE_FIELDS:
        if key in fields and fields[key] is not None:
            setattr(tenant, key, fields[key])
    session.flush()
    if fields.get("min_level") is not None:
        with _cache_lock:
            _min_levels[group] = tenant.min_level
    return _serialize(tenant)


# ── Contacts ──────────────────────────────────────────────────────────────────
def add_contact(session: Session, group: str, **fields) -> dict | None:
    tenant = _get(session, group)
    if tenant is None:
        return None
    contact = TenantContact(
        tenant_id=tenant.id,
        name=fields["name"],
        role=fields.get("role"),
        email=fields.get("email"),
        phone=fields.get("phone"),
    )
    session.add(contact)
    session.flush()
    return _serialize_contact(contact)


def delete_contact(session: Session, group: str, contact_id: int) -> bool:
    tenant = _get(session, group)
    if tenant is None:
        return False
    contact = session.get(TenantContact, contact_id)
    if contact is None or contact.tenant_id != tenant.id:
        return False
    session.delete(contact)
    return True


# ── Notification recipients ─────────────────────────────────────────────────────
def add_recipient(
    session: Session, group: str, user_id: int | None = None, email: str | None = None
) -> dict | None:
    """Add a recipient. Provide exactly one of user_id or email."""
    if (user_id is None) == (email is None):
        raise ValueError("provide exactly one of user_id or email")
    tenant = _get(session, group)
    if tenant is None:
        return None
    if user_id is not None and session.get(User, user_id) is None:
        raise ValueError("user not found")
    recipient = NotificationRecipient(tenant_id=tenant.id, user_id=user_id, email=email)
    session.add(recipient)
    session.flush()
    return _serialize_recipient(recipient)


def delete_recipient(session: Session, group: str, recipient_id: int) -> bool:
    tenant = _get(session, group)
    if tenant is None:
        return False
    recipient = session.get(NotificationRecipient, recipient_id)
    if recipient is None or recipient.tenant_id != tenant.id:
        return False
    session.delete(recipient)
    return True


def bootstrap(client: WazuhClient) -> None:
    """Startup entrypoint: seed, register with Wazuh, and warm the cache."""
    with session_scope() as session:
        seed_from_yaml_if_empty(session)
    with session_scope() as session:
        register_with_wazuh(session, client)
    with session_scope() as session:
        refresh_cache(session)
