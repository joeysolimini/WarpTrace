# Full‑Stack Cybersecurity Log Analyzer (Take‑Home)

A minimal, Dockerized full‑stack app to upload and analyze logs (Zscaler-style CSV or generic web/server logs), summarize timelines, and flag anomalies with confidence scores.

## Features
- **Auth**: Basic username/password login (demo, not production).
- **Upload**: Drag‑and‑drop .log/.txt/.csv.
- **Parse**: Zscaler Web Proxy–like CSV (`time, src_ip, user, url, action, status, bytes, user_agent`), plus simple line‑parser fallback.
- **Analyze**:
  - Timeline of events with aggregation.
  - Anomaly detection (high request rate per IP, rare user‑agents, concentrated errors).
  - Confidence scores (0–1) + human explanation.
- **UI**: React + Vite + TypeScript + Tailwind + Recharts (table + charts, highlighted anomalies).
- **DB**: PostgreSQL via SQLAlchemy models for Users, Uploads, Events, Anomalies.
- **API**: Flask REST endpoints for auth, upload, analysis, and retrieval.
- **Docs**: Example logs + clear instructions.
- **Bonus‑ready**: Easy place to plug in LLM for summarization/explanations (commented stub).

> Functionality over production readiness—kept intentionally simple and explainable.

---

## Quickstart (Docker)
1. **Copy `.env.example` to `.env`** and adjust values.
2. **Build & run**:
   ```bash
   docker compose up --build
   ```
3. Open the **frontend** at http://localhost:5173
4. Login with the creds in your `.env` (defaults: `admin` / `changeme`).

## Local (no Docker)
- Backend:
  ```bash
  cd backend
  python -m venv .venv && source .venv/bin/activate
  pip install -r requirements.txt
  cp .env.example .env  # adjust
  flask --app app run --debug
  ```
- Frontend:
  ```bash
  cd frontend
  npm i
  npm run dev
  ```

## Endpoints (Backend)
- `POST /api/login` → `{ token }`
- `POST /api/upload` (multipart: `file`) → `{ upload_id }`
- `GET /api/analysis/<upload_id>` → parsed events, timeline, anomalies
- `GET /api/uploads` → list prior uploads

Auth: send header `Authorization: Bearer <token>` to protected endpoints.

## AI / LLM Usage (optional)
The system does **statistical anomaly detection** locally. You can enable optional LLM summarization for “key learnings” by setting `LLM_ENABLED=true` and providing `OPENAI_API_KEY`. See comments in `anomaly.py` for the stub.
> If you prefer **no external calls**, leave it off. The assignment doesn’t require an LLM.

## Example Logs
See `sample_logs/zscaler_sample.csv`. You can also upload plain line‑based logs; the fallback parser will treat each line as an event.

## Tech Choices
- **Backend**: Flask + SQLAlchemy + psycopg2 + pydantic
- **Frontend**: React + Vite + TS + Tailwind + Recharts
- **DB**: Postgres (Docker) — you can swap to SQLite for quick tests
- **Why Flask?** Keeps the anomaly logic in Python where analysis is concise.

## Repo Structure
```
backend/
  app.py
  anomaly.py
  parser.py
  models.py
  db.py
  auth.py
  requirements.txt
  Dockerfile
  .env.example
frontend/
  index.html
  vite.config.ts
  package.json
  tsconfig.json
  postcss.config.cjs
  tailwind.config.cjs
  src/
    main.tsx
    App.tsx
    api.ts
    types.ts
    components/
      Login.tsx
      Uploader.tsx
      Results.tsx
      TimelineChart.tsx
      AnomalyTable.tsx
docker-compose.yml
sample_logs/
  zscaler_sample.csv
```

## Notes for Interview
- You can walk through the anomaly rules in `anomaly.py` and how confidence is computed.
- Point to the LLM stub and how you’d expand it (few-shot prompts with compact schema).
- Discuss improvements: auth (JWT/refresh), RBAC, chunked uploads, streaming parse, schema evolution, geo-IP, more detectors, and alerting.

---

© You. MIT‑style license preferred for take‑home submissions.
