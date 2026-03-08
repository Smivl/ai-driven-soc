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
