# ingestion

Getting alerts in from Wazuh, and the tools used to feed Wazuh test data.

The actual ingest, score, and explain worker threads live one level up in
pipeline_concurrent.py. This folder holds the pieces those workers and the test
tooling rely on.

## Files

- **wazuh_client.py** — talks to Wazuh: the REST API for managing groups and
  agents, and the search indexer for reading the alerts they produce. Handles
  logging in and refreshing the token.
- **feeder.py** — command-line tool that replays the sample CSV logs into Wazuh,
  spreading them across each tenant's agents so alerts come back correctly
  attributed. Useful for demos and testing.
- **wazuh_injector.py** — the low-level helper the feeder uses to push a log line
  into Wazuh as if it came from a chosen agent, without running real agents.
