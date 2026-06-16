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
from app.db import session_scope
from app.models.tenant import Agent, Tenant
from ingestion.tenants import load_tenants
from ingestion.wazuh_client import WazuhClient

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
def _serialize(tenant: Tenant) -> dict:
    return {
        "company": tenant.company,
        "group": tenant.group,
        "min_level": tenant.min_level,
        "agents": [
            {"name": a.name, "wazuh_agent_id": a.wazuh_agent_id} for a in tenant.agents
        ],
    }


def list_tenants(session: Session) -> list[dict]:
    tenants = session.scalars(select(Tenant).order_by(Tenant.company)).all()
    return [_serialize(t) for t in tenants]


def update_min_level(session: Session, group: str, min_level: int) -> dict | None:
    tenant = session.scalar(select(Tenant).where(Tenant.group == group))
    if tenant is None:
        return None
    tenant.min_level = min_level
    session.flush()
    with _cache_lock:
        _min_levels[group] = min_level
    return _serialize(tenant)


def bootstrap(client: WazuhClient) -> None:
    """Startup entrypoint: seed, register with Wazuh, and warm the cache."""
    with session_scope() as session:
        seed_from_yaml_if_empty(session)
    with session_scope() as session:
        register_with_wazuh(session, client)
    with session_scope() as session:
        refresh_cache(session)
