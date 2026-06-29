# backend/app

The FastAPI backend. It runs the SOC pipeline that pulls security alerts from
Wazuh, scores them, explains them with an LLM, and serves the results to the
dashboard over a small HTTP API.

## How an event flows through it

1. **ingest** — pull new alerts from Wazuh and turn each into a clean event.
2. **score** — give the event a severity from 0 to 100.
3. **explain** — ask the LLM what happened and what to do about it.
4. The finished event is kept in memory for the dashboard and saved to the
   database for history.

Steps 1 to 3 run as background worker threads that start with the server.

## Files at this level

- **main.py** — starts the server, sets up the database and tenants, launches the
  worker threads, and wires up the API routes.
- **pipeline_concurrent.py** — the four worker threads (ingest, score, explain,
  and the per-tenant assessment agent) and how they hand events to each other.
- **perf_trace.py** — optional timing tap used for latency benchmarks. Off unless
  switched on by an environment variable.

## Areas (see each folder's README)

- **api/** — the HTTP routes the dashboard calls.
- **core/** — app settings and login/security helpers.
- **ingestion/** — getting alerts in from Wazuh, plus tools to feed it test data.
- **log_evaluation/** — the event type, log parsing, scoring, and LLM explanation.
- **services/** — the logic that sits between the API or pipeline and the data.
- **models/** — the database tables and connection setup.
- **tenants/** — tenant configuration and the per-tenant AI assessment agent.
- **ml_unimplemented/** — experimental ML modules not yet wired into the pipeline.
