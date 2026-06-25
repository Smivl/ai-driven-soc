"""
Tenant configuration for the multi-tenant Wazuh simulation.

A tenant is a company mapped to a single Wazuh group; each of its agents is a
host/system belonging to that company. Agent IDs are assigned by Wazuh at
registration time, so they are filled in later (see TenantAgent.agent_id and
ingestion.feeder.setup_tenants), not stored in the YAML.
"""

import os
from dataclasses import dataclass, field

import yaml

# Default location of the committed example config (alongside this module).
DEFAULT_TENANTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tenants.yaml")


@dataclass
class TenantAgent:
    name: str
    agent_id: str | None = None  # resolved at setup time


@dataclass
class Tenant:
    company: str
    group: str
    agents: list[TenantAgent] = field(default_factory=list)


def load_tenants(path: str = DEFAULT_TENANTS_PATH) -> list[Tenant]:
    """Parse the tenants YAML file into a list of Tenant objects."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    tenants: list[Tenant] = []
    for entry in raw.get("tenants", []):
        agents = [TenantAgent(name=name) for name in entry.get("agents", [])]
        tenants.append(
            Tenant(
                company=entry["company"],
                group=entry["group"],
                agents=agents,
            )
        )
    return tenants
