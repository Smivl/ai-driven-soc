"""
End-to-end demo attack #2: a web SQL-injection campaign against a tenant's app
server.

    python -m ingestion.demo_web_attack

Injects malicious HTTP access logs as a tenant agent (companyB-app01). Each
SQL-injection request trips Wazuh rule 31103 ("SQL injection attempt", level 7,
MITRE T1190 — Initial Access / Exploit Public-Facing Application), then we pull
the resulting alerts back and show them attributed to the tenant.

Contrast with demo_attack.py (SSH brute force, T1110 Credential Access).
"""

import random
import time
from datetime import datetime, timezone

from ingestion.feeder import setup_tenants
from ingestion.normalizerfixed import extract_trigger_logs
from ingestion.tenants import DEFAULT_TENANTS_PATH, load_tenants
from ingestion.wazuh_client import WazuhClient
from ingestion.wazuh_injector import inject_batch, wrap

CONTAINER = "single-node-wazuh.manager-1"
ATTACKER_IP = f"203.0.113.{random.randint(2, 250)}"

# SQL-injection payloads (URL-encoded). A non-200 status keeps each request on
# rule 31103 (level 7) rather than the lower 31106 "returned 200" variant.
_PAYLOADS = [
    "/app/login.php?user=admin%27%20OR%20%271%27=%271",
    "/app/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/app/report.php?year=2026%27;%20DROP%20TABLE%20sessions;--",
    "/app/search.php?q=%27%20OR%20SLEEP(5)--",
    "/app/account.php?id=5%27%20UNION%20SELECT%20card,cvv%20FROM%20billing--",
]


def main() -> None:
    client = WazuhClient()
    tenants = load_tenants(DEFAULT_TENANTS_PATH)

    print("1. Ensuring tenants exist...")
    setup_tenants(client, tenants)

    # Target the second tenant's application server.
    victim_tenant = next((t for t in tenants if t.group == "companyB"), tenants[-1])
    victim = victim_tenant.agents[-1]
    print(f"\n2. Simulating SQL-injection campaign on {victim_tenant.company} / {victim.name} "
          f"(id={victim.agent_id}) from {ATTACKER_IP}...")

    now = datetime.now(timezone.utc)
    lines = [
        wrap(
            victim.agent_id,
            victim.name,
            f"{ATTACKER_IP} - - [{now.strftime('%d/%b/%Y:%H:%M:%S')} +0000] "
            f"\"GET {path} HTTP/1.1\" 403 162 \"-\" \"sqlmap/1.7\"",
            location="/var/log/apache2/access.log",
        )
        for path in _PAYLOADS
    ]
    sent = inject_batch(lines, CONTAINER, pace_seconds=0.3)
    print(f"   injected {sent} malicious HTTP requests")

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
        url = alert.get("data", {}).get("url", "")
        print("=" * 72)
        print(f"  ATTACK DETECTED  (level {rule.get('level')})")
        print(f"  Tenant   : {victim_tenant.company}  [group={victim_tenant.group}]")
        print(f"  Agent    : {agent.get('name')} (id={agent.get('id')})")
        print(f"  Rule     : {rule.get('id')} — {rule.get('description')}")
        print(f"  MITRE    : {mitre.get('id')} / {mitre.get('tactic')} / {mitre.get('technique')}")
        print(f"  URL      : {url}")
        for log in extract_trigger_logs(alert):
            print(f"    - {log}")
    print("=" * 72)


if __name__ == "__main__":
    main()
