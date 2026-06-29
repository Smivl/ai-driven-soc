# tenants

Tenant configuration and the per-tenant AI assessment agent.

A tenant is one company, mapped to a single Wazuh group, with one or more agents
(hosts) reporting under it.

## Files

- **tenants.yaml** — the starting list of tenants and their agents. Used to seed
  the database on first run.
- **tenants.py** — reads tenants.yaml into simple objects.
- **tenant_agent.py** — looks at a tenant's recent events as a group and judges
  its overall state (secured, at risk, or under attack). Where per-event scoring
  looks at one alert at a time, this catches slow or coordinated activity. Uses
  the same LLM as the explainer, with a simple fallback when it is unavailable.
