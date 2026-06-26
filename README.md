# AI-Driven SOC

An AI-driven Security Operations Center.

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- Node.js 22+

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


cd /Users/nicholasandersen/Desktop/ai-driven-soc/backend

## Feed Wazuh

# Dry run first to verify CSV is readable and Docker is reachable
python -m ingestion.feeder --input ../data/SIEVE_00_100K.csv --limit 10 --dry-run

# Live injection: inject 100 log lines into the Wazuh container
python -m ingestion.feeder --input ../data/SIEVE_00_100K.csv --limit 100