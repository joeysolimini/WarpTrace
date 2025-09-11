# Warptrace — Cybersecurity Log Analyzer

Warptrace is a minimal, Dockerized app to upload and analyze authentication and web logs. It parses common formats (Zscaler‑style CSV, plain line logs, and Auth0 JSONL), builds a timeline, groups anomalies with examples, and can generate a concise AI summary.

## Features
- **Auth**: Simple username/password login (demo‑grade, not production).
- **Upload**: Drag‑and‑drop .log/.txt/.csv.
- **Parse**: Zscaler‑like CSV (`time, src_ip, user, url, action, status, bytes, user_agent`), Auth0 JSONL, plus a line‑based fallback.
- **Analyze**:
  - Background processing with progress: `uploaded → processing → summarizing → done`.
  - Grouped findings with example events, impacted users/IPs, and reasons.
  - Per‑minute timeline chart of activity.
  - Optional AI summaries (OpenRouter) for overall findings and per‑group guidance.
- **UI**: React + Vite + TypeScript + Tailwind (+ Recharts for charts).
- **API**: Flask REST API; CORS enabled for the frontend.
- **DB**: PostgreSQL via SQLAlchemy models for uploads, events, and anomalies.

---

## Quickstart (Docker)
1. Optionally export your OpenRouter key (for AI summaries):
   ```bash
   export OPENROUTER_API_KEY=sk-or-...   # optional
   ```
2. Build and run:
   ```bash
   docker compose up --build
   ```
3. Open the frontend: http://localhost:5173
4. Login with the demo creds configured in `docker-compose.yml` (`admin` / `demopass`).

Notes
- Frontend talks to backend at `http://localhost:8000` by default (overridable via `VITE_API_BASE`).
- Postgres runs locally on `5432`; data persisted in the `pgdata` volume.

## Local Development (no Docker)
- Backend
  ```bash
  cd backend
  python -m venv .venv && source .venv/bin/activate
  pip install -r requirements.txt
  cp .env.example .env  # set DEMO_USERNAME/DEMO_PASSWORD, DATABASE_URL, etc.
  flask --app app run --debug  # http://localhost:8000
  ```
- Frontend
  ```bash
  cd frontend
  npm ci
  # Option A: rely on default fallback to http://localhost:8000
  npm run dev  # http://localhost:5173
  # Option B: explicitly set API base
  # echo "VITE_API_BASE=http://localhost:8000" > .env.local
  ```

## API Endpoints
- `POST /api/login` → `{ token }`
- `POST /api/upload` (multipart `file`) → `{ upload_id, status, progress }`  [auth]
- `POST /api/analyze/<upload_id>` → starts analysis; returns 202 with `{ status, progress }`  [auth]
- `GET  /api/status/<upload_id>` → `{ status, progress }` for polling  [auth]
- `GET  /api/analysis/<upload_id>` → when ready: `{ upload, events, timeline, anomaly_groups, summary, status, progress }`  [auth]
- `GET  /api/uploads` → recent uploads list  [auth]
- `GET  /api/health` → `{ ok, db }` (for platform health checks)

Auth: send `Authorization: Bearer <token>` on protected routes.

## Configuration
Backend (`backend/.env` or environment)
- `DATABASE_URL`: SQLAlchemy URL for Postgres.
- `SECRET_KEY`: Flask secret key.
- `DEMO_USERNAME`, `DEMO_PASSWORD`: demo login.
- `LLM_ENABLED`: `true|false` to enable AI summaries.
- `OPENROUTER_API_KEY`: API key for OpenRouter (required when `LLM_ENABLED=true`).
- `OPENROUTER_BASE_URL`: defaults to `https://openrouter.ai/api/v1`.
- `OPENROUTER_SITE_URL`, `OPENROUTER_APP_NAME`: optional attribution headers.
- `LLM_MODEL`: e.g., `openrouter/auto`.

Frontend (`frontend/.env` or environment)
- `VITE_API_BASE`: backend base URL, e.g., `http://localhost:8000` or your deployed backend URL.

## Repo Structure
```
backend/
  app.py           # routes, background pipeline, CORS
  anomaly.py       # simple detectors and scoring
  parser.py        # CSV, Auth0 JSONL, and line fallback
  models.py, db.py # SQLAlchemy models and session/engine
  summarizer.py    # optional OpenRouter summaries (safe defaults)
  auth.py          # demo auth
  Dockerfile, requirements.txt, entrypoint.sh
frontend/
  index.html, vite.config.ts, tailwind.config.cjs
  src/ (React + TS components)
  Dockerfile, Caddyfile
docker-compose.yml, railway.toml
```

## Example Logs
Once logged in, use the link to download sample logs for testing.

## Deployment
- **Docker images**: `backend/` and `frontend/` each have a Dockerfile.
- **Railway**: `railway.toml` includes two services. Deploy backend first (Postgres plugin recommended), then frontend; set `VITE_API_BASE` in the frontend to your backend’s URL.

## License
MIT (see repository for details).
