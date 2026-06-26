"""
"Daily operations" demo: a realistic mix of concurrent attacks and normal
activity across both tenants, injected interleaved so different attacks overlap
in time.

    python -m ingestion.demo_daily

This exercises the whole system the way a real day would:

  * Company A — SSH brute force (rule 5712, T1110)
  * Company B — SQL-injection campaign (rule 31103, T1190)
  * Company B — honeytoken sweep (custom rule 100110, T1552)
  * Both tenants — benign background traffic (logins, web 200s, normal app access)

The campaigns are interleaved (round-robin) rather than injected one after
another, so the brute-force attempts are spread out among SQLi requests,
honeytoken reads and benign noise. This demonstrates that detection/correlation
and the per-tenant AI window reason over the *whole* tenant context — not just
the most recent N log lines — and that events stay correctly attributed per
tenant even when everything happens at once.
"""

import random
import time
from datetime import datetime, timezone
from itertools import zip_longest

from backend.app.ingestion.feeder import setup_tenants
from backend.app.tenants.tenants import DEFAULT_TENANTS_PATH, load_tenants
from backend.app.ingestion.wazuh_client import WazuhClient
from backend.app.ingestion.wazuh_injector import inject_batch, wrap

CONTAINER = "single-node-wazuh.manager-1"

# Distinct attacker IPs per campaign so each shows up as its own actor.
IP_SSH = f"198.51.100.{random.randint(2, 250)}"
IP_SQLI = f"203.0.113.{random.randint(2, 250)}"
IP_HONEY = f"203.0.113.{random.randint(2, 250)}"

SYSLOG = "%b %d %H:%M:%S"
APACHE = "%d/%b/%Y:%H:%M:%S +0000"


# ── Campaign builders (each returns a list of wrapped, agent-attributed lines) ──
def ssh_bruteforce(agent) -> list[str]:
    base = datetime.now(timezone.utc)
    return [
        wrap(agent.agent_id, agent.name,
             f"{base.strftime('%b %d %H:%M')}:{i:02d} {agent.name} sshd[5{i:02d}]: "
             f"Failed password for invalid user hacker from {IP_SSH} port 4444 ssh2")
        for i in range(1, 13)  # 12 > rule 5712 frequency (8) within 120s
    ]


def sqli_campaign(agent) -> list[str]:
    ts = datetime.now(timezone.utc).strftime(APACHE)
    payloads = [
        "/app/login.php?user=admin%27%20OR%20%271%27=%271",
        "/app/index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/app/report.php?year=2026%27;%20DROP%20TABLE%20sessions;--",
        "/app/search.php?q=%27%20OR%20SLEEP(5)--",
    ]
    return [
        wrap(agent.agent_id, agent.name,
             f"{IP_SQLI} - - [{ts}] \"GET {p} HTTP/1.1\" 403 162 \"-\" \"sqlmap/1.7\"",
             location="/var/log/apache2/access.log")
        for p in payloads
    ]


def honeytoken_sweep(agents) -> list[str]:
    ts = datetime.now(timezone.utc).strftime(SYSLOG)
    objs = [
        "/vault/honeytoken/aws_keys.csv",
        "/srv/secrets/canary_api_token.json",
        "/vault/decoy/payroll_2026.xlsx",
        "/vault/honeytoken/ssh_id_rsa",
    ]
    out = []
    for i, obj in enumerate(objs):
        a = agents[i % len(agents)]
        out.append(wrap(a.agent_id, a.name,
                        f"{ts} {a.name} datavault[2211]: action=download user=svc_backup "
                        f"src={IP_HONEY} object={obj} status=ok",
                        location="/var/log/datavault/access.log"))
    return out


def benign(agents) -> list[str]:
    """Normal day-to-day activity that should NOT raise high alerts."""
    ts_sys = datetime.now(timezone.utc).strftime(SYSLOG)
    ts_web = datetime.now(timezone.utc).strftime(APACHE)
    a0, a1 = agents[0], agents[-1]
    return [
        wrap(a0.agent_id, a0.name,
             f"{ts_sys} {a0.name} sshd[6001]: Accepted password for alice from 10.0.0.5 port 22 ssh2"),
        wrap(a1.agent_id, a1.name,
             f"10.0.0.9 - - [{ts_web}] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"",
             location="/var/log/apache2/access.log"),
        wrap(a1.agent_id, a1.name,
             f"{ts_sys} {a1.name} datavault[2211]: action=download user=alice src=10.0.0.5 "
             f"object=/vault/reports/q3_summary.pdf status=ok",
             location="/var/log/datavault/access.log"),
        wrap(a0.agent_id, a0.name,
             f"{ts_sys} {a0.name} sshd[6002]: Accepted publickey for deploy from 10.0.0.8 port 22 ssh2"),
    ]


def interleave(*campaigns: list[str]) -> list[str]:
    """Round-robin merge so the campaigns overlap instead of running in blocks."""
    merged: list[str] = []
    for group in zip_longest(*campaigns):
        merged.extend(line for line in group if line is not None)
    return merged


def main() -> None:
    client = WazuhClient()
    tenants = load_tenants(DEFAULT_TENANTS_PATH)

    print("1. Ensuring tenants exist...")
    setup_tenants(client, tenants)

    company_a = next(t for t in tenants if t.group == "companyA")
    company_b = next(t for t in tenants if t.group == "companyB")

    print("\n2. Building a day's worth of interleaved activity:")
    campaigns = {
        f"A · SSH brute force ({IP_SSH})": ssh_bruteforce(company_a.agents[0]),
        f"B · SQL injection ({IP_SQLI})": sqli_campaign(company_b.agents[-1]),
        f"B · Honeytoken sweep ({IP_HONEY})": honeytoken_sweep(company_b.agents),
        "A · Benign activity": benign(company_a.agents),
        "B · Benign activity": benign(company_b.agents),
    }
    for label, lines in campaigns.items():
        print(f"   {len(lines):>2} events — {label}")

    merged = interleave(*campaigns.values())
    print(f"\n3. Injecting {len(merged)} interleaved events (attacks overlap in time)...")
    sent = inject_batch(merged, CONTAINER, pace_seconds=0.3)
    print(f"   injected {sent} events")

    print("\n4. Waiting for Wazuh correlation + indexing...")
    time.sleep(13)

    print("\n5. Significant (level ≥ 7) detections per tenant:\n")
    for tenant in (company_a, company_b):
        alerts = client.get_significant_alerts(min_level=7, group=tenant.group, limit=50)
        seen: dict[str, int] = {}
        for a in alerts:
            desc = a.get("rule", {}).get("description", "?")
            lvl = a.get("rule", {}).get("level")
            seen[f"[L{lvl}] {desc}"] = seen.get(f"[L{lvl}] {desc}", 0) + 1
        print(f"  {tenant.company} [{tenant.group}] — {len(alerts)} significant alert(s)")
        for k, n in sorted(seen.items(), key=lambda kv: kv[0], reverse=True):
            print(f"      {n}× {k}")
        print()

    print("Watch the radar: both tenants should light up. The AI agent will then")
    print("assess each tenant's window and classify the coordinated activity.")


if __name__ == "__main__":
    main()
