# API Deployment — Railway

The API deploys as a standalone service on Railway with a managed PostgreSQL database.
Everything is simulated on synthetic data; no real financial connections exist.

## One-time setup

1. Push this repo to GitHub as its own repository (API only).
2. In Railway: **New Project → Deploy from GitHub repo** → pick this repo.
3. Add a **PostgreSQL** plugin to the project. Railway injects `DATABASE_URL`
   automatically; the app normalizes `postgres://` / `postgresql://` to the psycopg 3
   driver, so no manual editing is needed.
4. Set the service **Variables**:

   | Variable | Value |
   |---|---|
   | `DEMO_MODE` | `true` |
   | `LLM_PROVIDER` | `mock` |
   | `TRACE_HASH_SECRET` | a long random string (keep secret) |
   | `ALLOWED_ORIGINS` | your Vercel URL, e.g. `https://<app>.vercel.app` |
   | `DATABASE_URL` | provided by the Postgres plugin (leave as injected) |

   > `PORT` is provided by Railway; do not set it manually. Do **not** commit a real
   > `TRACE_HASH_SECRET`.

## Build & start

- Builder: Nixpacks (Python detected via `requirements.txt` + `.python-version` = 3.12).
- Start command (from `Procfile` / `railway.json`):
  `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Health check: `GET /health` (configured in `railway.json`).
- Tables are created on startup (`create_all`); Alembic migrations are a future addition.

## After deploy

1. Hit `GET /health` → `{"status":"healthy", ...}`.
2. Seed demo state: `GET /v1/demo/bootstrap` (idempotent).
3. Confirm CORS: the browser app at `ALLOWED_ORIGINS` can call the API.

## Local parity

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
uvicorn app.main:app --reload --port 8000
```

## Notes

- `ALLOWED_ORIGINS` is comma-separated; add extra origins (e.g. a preview domain) as needed.
  Because credentials are allowed, wildcard `*` is not valid — list explicit origins.
- The SQLite default (`DATABASE_URL=sqlite:///./safedelegate.db`) is for local only.
