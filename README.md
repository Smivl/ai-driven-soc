# AI-Driven SOC

An AI-driven Security Operations Center. It pulls security alerts from Wazuh,
scores and explains each one with an LLM, and shows the results on a live
dashboard. The backend runs the detection pipeline and serves an API; the
frontend is the monitoring dashboard.

For how the code is laid out, see the area overviews in
[backend/app/README.md](backend/app/README.md) and
[frontend/src/README.md](frontend/src/README.md).

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- Node.js 22+
- Docker (for the Postgres database)

## Database

The backend stores tenants, users, and saved events in Postgres. Start it first:

```bash
docker compose up -d
```

## Backend

```bash
cd backend
cp .env.example .env
uv sync
uv run uvicorn app.main:app --reload
```

Runs at http://localhost:8000. API docs at http://localhost:8000/docs.

## Frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Runs at http://localhost:5173.

## Feeding Wazuh with test data

The feeder replays the sample CSV logs into a running Wazuh container so the
pipeline has something to process. Run it from the repository root. It needs the
Wazuh credentials in the root `.env` (copy `.env.example` first).

```bash
# Dry run first to check the CSV is readable and Docker is reachable
uv run --project backend python -m backend.app.ingestion.feeder \
  --input data/SIEVE_00_100K.csv --limit 10 --dry-run

# Live injection: inject 100 log lines as per-tenant agents
uv run --project backend python -m backend.app.ingestion.feeder \
  --input data/SIEVE_00_100K.csv --limit 100
```
