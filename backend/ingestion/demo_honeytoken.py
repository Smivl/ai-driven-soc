"""
End-to-end demo attack #3: a honeytoken / canary sweep against a tenant.

    python -m ingestion.demo_honeytoken

Simulates an attacker (single source IP, one compromised service account) reading
a series of decoy "honeytoken" objects across Company B's hosts. These are logged
by the bespoke "DataVault" application, which default Wazuh cannot decode or judge
— our custom decoder + rule (datavault_decoder.xml / datavault_rules.xml, rule
100110, level 13, MITRE T1552 Unsecured Credentials) flags every access as a
critical incident. The events are injected as Company B agents so they carry the
right tenant, then pulled back to confirm detection.

Contrast with demo_attack.py (SSH brute force, T1110) and demo_web_attack.py
(SQL injection, T1190).
"""

import random
import time
from datetime import datetime

from ingestion.feeder import setup_tenants
from ingestion.normalizerfixed import extract_trigger_logs
from ingestion.tenants import DEFAULT_TENANTS_PATH, load_tenants
from ingestion.wazuh_client import WazuhClient
from ingestion.wazuh_injector import inject_batch, wrap

CONTAINER = "single-node-wazuh.manager-1"
ATTACKER_IP = f"203.0.113.{random.randint(2, 250)}"
COMPROMISED_USER = "svc_backup"  # one account doing all the reads = coordinated

# Decoy objects no legitimate process should ever touch. Each path contains a
# token the custom rule matches on (honeytoken / canary / /decoy/).
_HONEYTOKENS = [
    "/vault/honeytoken/aws_keys.csv",
    "/vault/honeytoken/db_root_password.txt",
    "/srv/secrets/canary_api_token.json",
    "/vault/decoy/payroll_2026.xlsx",
    "/vault/honeytoken/ssh_id_rsa",
]


def main() -> None:
    client = WazuhClient()
    tenants = load_tenants(DEFAULT_TENANTS_PATH)

    print("1. Ensuring tenants exist...")
    setup_tenants(client, tenants)

    # Target Company B — sweep its hosts so the tenant looks broadly compromised.
    victim_tenant = next((t for t in tenants if t.group == "companyB"), tenants[-1])
    agents = victim_tenant.agents
    print(f"\n2. Simulating honeytoken sweep on {victim_tenant.company} "
          f"({len(agents)} hosts) by {COMPROMISED_USER} from {ATTACKER_IP}...")

    ts = datetime.now().strftime("%b %d %H:%M:%S")
    lines = []
    for i, obj in enumerate(_HONEYTOKENS):
        agent = agents[i % len(agents)]
        raw = (
            f"{ts} {agent.name} datavault[2211]: "
            f"action=download user={COMPROMISED_USER} src={ATTACKER_IP} object={obj} status=ok"
        )
        lines.append(wrap(agent.agent_id, agent.name, raw,
                          location="/var/log/datavault/access.log"))

    sent = inject_batch(lines, CONTAINER, pace_seconds=0.4)
    print(f"   injected {sent} honeytoken accesses across {len(agents)} hosts")

    print("\n3. Waiting for Wazuh detection + indexing...")
    time.sleep(11)

    print("\n4. Pulling significant (attack) events for this tenant:\n")
    alerts = client.get_significant_alerts(min_level=7, group=victim_tenant.group, limit=20)
    alerts = [a for a in alerts if a.get("data", {}).get("srcip") == ATTACKER_IP]
    if not alerts:
        print("   No attack detected yet — try re-running (detection/indexing can lag).")
        return

    for alert in alerts:
        agent = alert.get("agent", {})
        rule = alert.get("rule", {})
        mitre = rule.get("mitre", {})
        data = alert.get("data", {})
        print("=" * 72)
        print(f"  HONEYTOKEN ACCESS  (level {rule.get('level')})")
        print(f"  Tenant   : {victim_tenant.company}  [group={victim_tenant.group}]")
        print(f"  Agent    : {agent.get('name')} (id={agent.get('id')})")
        print(f"  Rule     : {rule.get('id')} — {rule.get('description')}")
        print(f"  MITRE    : {mitre.get('id')} / {mitre.get('tactic')} / {mitre.get('technique')}")
        print(f"  Object   : {data.get('url')}  (user={data.get('srcuser')})")
        for log in extract_trigger_logs(alert):
            print(f"    - {log}")
    print("=" * 72)
    print(f"\n  {len(alerts)} honeytoken alert(s) — Company B should now show on the radar.")


if __name__ == "__main__":
    main()
