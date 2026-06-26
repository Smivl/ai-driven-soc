"""
End-to-end attack demo: push logs from one tenant agent, have Wazuh detect an
attack (correlation rule match), then pull the attack event together with the
logs that triggered it.

    python -m ingestion.demo_attack

Injects an SSH brute-force burst (rule 5712, level 10, MITRE T1110) as a single
tenant agent, then pulls it back via the significant-alerts query and prints the
attack event plus its triggering logs (full_log + previous_output).
"""

import random
import time
from datetime import datetime, timezone

from backend.app.ingestion.feeder import setup_tenants
from backend.app.log_evaluation.normalizer import extract_trigger_logs
from backend.app.tenants.tenants import DEFAULT_TENANTS_PATH, load_tenants
from backend.app.ingestion.wazuh_client import WazuhClient
from backend.app.ingestion.wazuh_injector import inject_batch, wrap

CONTAINER = "single-node-wazuh.manager-1"
# Fresh attacker IP each run so every demo shows a brand-new detection (and to
# stay clear of rule 5712's 60s re-fire "ignore" window).
ATTACKER_IP = f"198.51.100.{random.randint(2, 250)}"
BURST = 12         # > frequency(8) for rule 5712, within timeframe(120s)
PACE = 0.4         # seconds between attempts so the frequency counter builds


def main() -> None:
    client = WazuhClient()
    tenants = load_tenants(DEFAULT_TENANTS_PATH)

    print("1. Ensuring tenants exist...")
    setup_tenants(client, tenants)

    # Attack a single tenant agent.
    victim_tenant = tenants[0]
    victim = victim_tenant.agents[0]
    print(f"\n2. Simulating SSH brute force on {victim_tenant.company} / {victim.name} "
          f"(id={victim.agent_id}) from {ATTACKER_IP}...")

    # Timestamps at "now", one second apart, so all BURST attempts fall inside
    # the 120s correlation window.
    now = datetime.now(timezone.utc)
    lines = [
        wrap(
            victim.agent_id,
            victim.name,
            f"{now.strftime('%b %d %H:%M')}:{i:02d} {victim.name} sshd[5{i:02d}]: "
            f"Failed password for invalid user hacker from {ATTACKER_IP} port 4444 ssh2",
        )
        for i in range(1, BURST + 1)
    ]
    sent = inject_batch(lines, CONTAINER, pace_seconds=PACE)
    print(f"   injected {sent} failed-login attempts")

    print("\n3. Waiting for Wazuh correlation + indexing...")
    time.sleep(12)

    print("\n4. Pulling significant (attack) events for this tenant:\n")
    alerts = client.get_significant_alerts(min_level=10, group=victim_tenant.group, limit=20)
    # Scope to the attack this run just launched (by attacker IP).
    alerts = [a for a in alerts if a.get("data", {}).get("srcip") == ATTACKER_IP]
    if not alerts:
        print("   No attack detected yet — try re-running (correlation/indexing can lag).")
        return

    for alert in alerts:
        agent = alert.get("agent", {})
        rule = alert.get("rule", {})
        mitre = rule.get("mitre", {})
        print("=" * 70)
        print(f"  ATTACK DETECTED  (level {rule.get('level')})")
        print(f"  Tenant   : {victim_tenant.company}  [group={victim_tenant.group}]")
        print(f"  Agent    : {agent.get('name')} (id={agent.get('id')})")
        print(f"  Rule     : {rule.get('id')} — {rule.get('description')}")
        print(f"  MITRE    : {mitre.get('id')} / {mitre.get('tactic')} / {mitre.get('technique')}")
        triggers = extract_trigger_logs(alert)
        print(f"  Triggered by {len(triggers)} log(s):")
        for log in triggers:
            print(f"    - {log}")
    print("=" * 70)


if __name__ == "__main__":
    main()
