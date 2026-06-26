# Custom Wazuh decoder + rule — Honeytoken access detection

This is a documented copy of a custom decoder and rule installed into the Wazuh
manager to demonstrate that the SOC is extensible to attacks the default Wazuh
ruleset does **not** detect. These files live in the Wazuh manager only; there
is no corresponding frontend component.

## The attack

A **honeytoken** (a.k.a. canary) is a decoy secret — a fake AWS key, password
file, or document — placed where an attacker would look but no legitimate user
or process should ever touch. Any read of it is, by definition, malicious
(credential theft / data exfiltration reconnaissance).

Default Wazuh cannot detect this for two reasons:

1. It has **no decoder** for our bespoke "DataVault" application log format, so
   the events are dropped as undecoded.
2. Even decoded, stock rules have **no concept** of which objects are decoys.

## The log format

The DataVault application logs access events via syslog (program `datavault`):

```
Jun 17 10:00:00 web01 datavault[2211]: action=download user=jsmith src=203.0.113.66 object=/vault/honeytoken/aws_keys.csv status=ok
```

## What we added

| File | Installed path | Purpose |
|------|----------------|---------|
| [`decoders/datavault_decoder.xml`](decoders/datavault_decoder.xml) | `/var/ossec/etc/decoders/datavault_decoder.xml` | Parses DataVault events into `action`, `srcuser`, `srcip`, `url`, `status`. |
| [`rules/datavault_rules.xml`](rules/datavault_rules.xml) | `/var/ossec/etc/rules/datavault_rules.xml` | Rule `100100` decodes the event (level 0); rule `100110` fires **level 13 (critical)** when the accessed `object` matches `honeytoken`, `canary`, or `/decoy/`. Tagged MITRE **T1552** (Unsecured Credentials). |

`/var/ossec/etc/decoders` and `/var/ossec/etc/rules` are scanned by the default
`ossec.conf` ruleset config, so dedicated files load without editing it and
without clobbering the stock `local_decoder.xml` / `local_rules.xml`.

## Install (Wazuh manager container)

```bash
MGR=single-node-wazuh.manager-1
docker cp wazuh/custom/decoders/datavault_decoder.xml "$MGR":/var/ossec/etc/decoders/datavault_decoder.xml
docker cp wazuh/custom/rules/datavault_rules.xml       "$MGR":/var/ossec/etc/rules/datavault_rules.xml
docker exec "$MGR" chown wazuh:wazuh /var/ossec/etc/decoders/datavault_decoder.xml /var/ossec/etc/rules/datavault_rules.xml

# Validate the ruleset BEFORE restarting (does not touch the running analysisd):
docker exec "$MGR" /var/ossec/bin/wazuh-analysisd -t

# Apply:
docker exec "$MGR" /var/ossec/bin/wazuh-control restart
```

## Test

```bash
docker exec -i single-node-wazuh.manager-1 /var/ossec/bin/wazuh-logtest <<'EOF'
Jun 17 10:00:00 web01 datavault[2211]: action=download user=jsmith src=203.0.113.66 object=/vault/honeytoken/aws_keys.csv status=ok
EOF
```

Expected: decoder `datavault-access` extracts the fields and **rule 100110**
(level 13, "Honeytoken accessed…") fires. A benign object (e.g.
`object=/vault/reports/q3.pdf`) decodes but only matches the level-0 base rule.
