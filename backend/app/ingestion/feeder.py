"""
Feed SIEVE CSV logs into Wazuh as if they came from per-tenant agents.

Instead of appending raw lines to a manager log file (which attributes every
alert to the manager itself), this distributes CSV rows across the agents
defined in tenants.yaml and injects each one "wrapped" with its agent identity
into the analysisd queue socket. Pulled alerts then carry the right
agent / group (tenant).
"""

import argparse
import csv
import time

from backend.app.tenants.tenants import DEFAULT_TENANTS_PATH, Tenant, load_tenants
from backend.app.ingestion.wazuh_client import WazuhClient
from backend.app.ingestion.wazuh_injector import DEFAULT_LOCATION, inject_batch, wrap


def setup_tenants(client: WazuhClient, tenants: list[Tenant]) -> None:
    """Ensure every tenant's group + agents exist in Wazuh and are assigned.

    Idempotent. Populates each TenantAgent.agent_id with the resolved Wazuh ID.
    """
    for tenant in tenants:
        client.create_group(tenant.group)
        for agent in tenant.agents:
            agent.agent_id = client.register_agent(agent.name)
            client.assign_agent_to_group(agent.agent_id, tenant.group)
            print(f"  tenant={tenant.company:<12} group={tenant.group:<10} "
                  f"agent={agent.name} (id={agent.agent_id})")


def _agent_pool(tenants: list[Tenant]) -> list[tuple[str, str]]:
    """Flat list of (agent_id, agent_name) across all tenants, for round-robin."""
    pool: list[tuple[str, str]] = []
    for tenant in tenants:
        for agent in tenant.agents:
            if agent.agent_id is None:
                raise RuntimeError(f"agent {agent.name!r} has no id — run setup_tenants first")
            pool.append((agent.agent_id, agent.name))
    return pool


def feed(
    input_file: str,
    limit: int,
    delay: float,
    container: str,
    tenants_path: str,
    location: str,
    dry_run: bool,
) -> None:
    tenants = load_tenants(tenants_path)

    print("=" * 60)
    print("  Wazuh Multi-Tenant Log Feeder")
    print("=" * 60)
    print(f"  Source     : {input_file}")
    print(f"  Limit      : {limit if limit else 'all'}")
    print(f"  Container  : {container}")
    print(f"  Tenants    : {tenants_path}")
    print(f"  Location   : {location}")
    print(f"  Dry run    : {dry_run}")
    print("=" * 60)

    if not dry_run:
        print("  Registering tenants (groups + agents)...")
        setup_tenants(WazuhClient(), tenants)
    else:
        # In dry-run we still need agent ids for the pool — fake them by index.
        for i, (tenant, agent) in enumerate(
            (t, a) for t in tenants for a in t.agents
        ):
            agent.agent_id = f"{i + 1:03d}"

    pool = _agent_pool(tenants)
    print("=" * 60)

    wrapped: list[str] = []
    with open(input_file, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if limit and len(wrapped) >= limit:
                break
            raw_log = row.get("log", "")
            if not raw_log:
                continue
            agent_id, agent_name = pool[len(wrapped) % len(pool)]
            line = wrap(agent_id, agent_name, raw_log, location)
            wrapped.append(line)
            if dry_run:
                print(f"  [DRY] {line[:110]}")

    if dry_run:
        print("=" * 60)
        print(f"  Done (dry-run). Wrapped: {len(wrapped)}")
        print("=" * 60)
        return

    # Inject — pace with --delay if set, otherwise one fast batch.
    if delay:
        sent = 0
        for line in wrapped:
            sent += inject_batch([line], container)
            time.sleep(delay)
    else:
        sent = inject_batch(wrapped, container)

    print("=" * 60)
    print(f"  Done. Injected: {sent} across {len(pool)} agents")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Feed SIEVE CSV logs into Wazuh as per-tenant agents.")
    parser.add_argument("--input",     default="../data/SIEVE_00_100K.csv")
    parser.add_argument("--limit",     type=int, default=100,
                        help="Number of rows to inject (0 = all)")
    parser.add_argument("--delay",     type=float, default=0.0,
                        help="Seconds between injections (0 = single fast batch)")
    parser.add_argument("--container", default="single-node-wazuh.manager-1")
    parser.add_argument("--tenants",   default=DEFAULT_TENANTS_PATH,
                        help="Path to tenants.yaml")
    parser.add_argument("--location",  default=DEFAULT_LOCATION,
                        help="Log source path reported to Wazuh")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Print wrapped lines without injecting")
    args = parser.parse_args()

    feed(
        input_file=args.input,
        limit=args.limit,
        delay=args.delay,
        container=args.container,
        tenants_path=args.tenants,
        location=args.location,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
