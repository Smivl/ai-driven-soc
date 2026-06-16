"""
End-to-end demo of multi-tenant attribution.

    python -m ingestion.demo_multitenant

Registers the tenants from tenants.yaml, injects a few recognizable logs as each
tenant's agents, then pulls the alerts back per group and prints a table showing
that each log came back attributed to the right company / group / agent.
"""

import time

from ingestion.feeder import setup_tenants
from ingestion.tenants import DEFAULT_TENANTS_PATH, load_tenants
from ingestion.wazuh_client import WazuhClient
from ingestion.wazuh_injector import inject_batch, wrap

CONTAINER = "single-node-wazuh.manager-1"

# Logs that reliably trigger a Wazuh rule (sshd auth failure, level 5).
_SAMPLE_LOGS = [
    "Jun 15 12:00:00 host sshd[1010]: Failed password for root from 8.8.8.8 port 22 ssh2",
    "Jun 15 12:00:05 host sshd[1011]: Failed password for admin from 45.33.12.9 port 22 ssh2",
]


def main() -> None:
    client = WazuhClient()
    tenants = load_tenants(DEFAULT_TENANTS_PATH)

    print("1. Registering tenants (groups + agents)...")
    setup_tenants(client, tenants)

    print("\n2. Injecting sample logs as each agent...")
    lines: list[str] = []
    for tenant in tenants:
        for agent in tenant.agents:
            for log in _SAMPLE_LOGS:
                lines.append(wrap(agent.agent_id, agent.name, log))
    sent = inject_batch(lines, CONTAINER)
    print(f"   injected {sent} wrapped logs")

    print("\n3. Waiting for analysisd + indexing...")
    time.sleep(12)

    print("\n4. Pulling alerts back per tenant:\n")
    header = f"{'Company':<12} {'Group':<10} {'Agent':<18} {'Lvl':<4} Rule"
    print(header)
    print("-" * len(header))
    for tenant in tenants:
        alerts = client.get_alerts_by_group(tenant.group, limit=50)
        for a in alerts:
            agent = a.get("agent", {})
            rule = a.get("rule", {})
            print(f"{tenant.company:<12} {tenant.group:<10} "
                  f"{agent.get('name', '?'):<18} {str(rule.get('level', '?')):<4} "
                  f"{rule.get('description', '')}")
        if not alerts:
            print(f"{tenant.company:<12} {tenant.group:<10} {'(no alerts yet)':<18}")
    print()


if __name__ == "__main__":
    main()
