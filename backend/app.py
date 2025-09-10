import os
import time
import threading
import traceback
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
from sqlalchemy import select, text
from db import Base, engine, SessionLocal
from models import Upload, LogEvent, Anomaly
from parser import parse_csv, parse_fallback_lines, parse_auth0_jsonl
from anomaly import detect_anomalies
from auth import login_handler, require_auth
from summarizer import summarize_anomaly, summarize_log  # NEW

app = Flask(__name__)

# ---------- Async DB warmup so the server can start immediately ----------
DB_READY = False

def ensure_db_async(max_attempts: int = 60, delay: float = 1.5):
    """Warm DB + ensure tables/columns in a background thread (non-blocking)."""
    def worker():
        nonlocal max_attempts, delay
        global DB_READY
        for i in range(max_attempts):
            try:
                # connectivity
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))

                # tables
                Base.metadata.create_all(bind=engine)

                # columns used for LLM summary cache (idempotent)
                with engine.begin() as conn:
                    conn.execute(text("""
                        ALTER TABLE uploads
                        ADD COLUMN IF NOT EXISTS ai_summary TEXT,
                        ADD COLUMN IF NOT EXISTS ai_summary_model VARCHAR(120),
                        ADD COLUMN IF NOT EXISTS ai_summary_at TIMESTAMPTZ
                    """))

                app.logger.info("✅ Database ready; tables/columns ensured.")
                DB_READY = True
                return
            except Exception as e:
                app.logger.warning(f"⏳ Waiting for database... ({i+1}/{max_attempts}) {e}")
                time.sleep(delay)
        app.logger.error("🚫 Database not reachable after retries")

    threading.Thread(target=worker, daemon=True).start()

# kick off the background warmup (do NOT block startup)
ensure_db_async()

# CORS (Auth header + multipart)
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    supports_credentials=False,
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Authorization", "Content-Type"],
)

# ---------- helpers ----------
def set_state(dbsess, upload_id: int, *, status: str | None = None, progress: int | None = None):
    up = dbsess.get(Upload, upload_id)
    if not up:
        return
    changed = False
    if status is not None and up.status != status:
        up.status = status
        changed = True
    if progress is not None:
        val = max(0, min(100, int(progress)))
        if up.progress != val:
            up.progress = val
            changed = True
    if changed:
        dbsess.add(up)
        dbsess.commit()

def _norm_ts(s: str | None):
    if not s:
        return None
    s = s.strip()
    try:
        if s.endswith(("Z","z")):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        pass
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

EXPECTED_KEYS = {"time","timestamp","ts","src_ip","srcip","client_ip","user","status","url"}

def smart_parse(raw_content: str, filename: str = ""):
    txt = (raw_content or "").lstrip()
    looks_jsonl = filename.lower().endswith(".jsonl") or (txt.startswith("{") or txt.startswith("["))
    if looks_jsonl:
        try:
            rows = parse_auth0_jsonl(raw_content)
            return rows, "auth0-jsonl"
        except Exception:
            pass
    try:
        rows = parse_csv(raw_content)
        good = sum(1 for r in rows if EXPECTED_KEYS.intersection(r.keys()))
        if good >= max(1, int(0.3 * max(1, len(rows)))):
            return rows, "csv"
    except Exception:
        pass
    try:
        rows = parse_auth0_jsonl(raw_content)
        return rows, "auth0-jsonl"
    except Exception:
        pass
    return parse_fallback_lines(raw_content), "fallback"

def _group_anomalies(rich_anoms, id_to_event):
    """
    Group by kind; aggregate counts, users, ips, and sample events.
    Returns list[dict]: {kind, count, reasons, users, src_ips, samples[]}
    """
    from collections import defaultdict
    g = defaultdict(lambda: {
        "kind": None, "count": 0, "reasons": set(), "users": set(), "src_ips": set(),
        "event_ids": [], "samples": []
    })
    for a in rich_anoms:
        kind = a.get("kind") or "other"
        meta = a.get("meta") or {}
        ev_ids = meta.get("event_ids") or []
        bucket = g[kind]
        bucket["kind"] = kind
        bucket["count"] += 1
        if a.get("reason"):
            bucket["reasons"].add(a["reason"])
        # accumulate users/src_ips from sample rows we have
        for eid in ev_ids:
            if eid in id_to_event:
                ev = id_to_event[eid]
                if ev.get("user"): bucket["users"].add(ev["user"])
                if ev.get("src_ip"): bucket["src_ips"].add(ev["src_ip"])
        # keep up to 25 distinct event samples
        for eid in ev_ids:
            if len(bucket["event_ids"]) >= 25: break
            if eid not in bucket["event_ids"]:
                bucket["event_ids"].append(eid)
                if eid in id_to_event:
                    bucket["samples"].append(id_to_event[eid])
    # finalize structures
    out = []
    for _, v in g.items():
        out.append({
            "kind": v["kind"],
            "count": v["count"],
            "reasons": sorted(v["reasons"])[:5],
            "users": sorted(v["users"])[:10],
            "src_ips": sorted(v["src_ips"])[:10],
            "samples": v["samples"][:25],
        })
    out.sort(key=lambda x: x["count"], reverse=True)
    return out

def _process_analysis(upload_id: int):
    """Background analysis worker: parse -> insert events -> detect + group -> (optional) LLM overall summary."""
    dbt = SessionLocal()
    try:
        u = dbt.get(Upload, upload_id)
        if not u or not u.raw_content:
            set_state(dbt, upload_id, status="failed", progress=100)
            return

        set_state(dbt, upload_id, status="processing", progress=5)

        rows, fmt = smart_parse(u.raw_content or "", getattr(u, "filename", ""))
        app.logger.info(f"[upload {upload_id}] parsed {len(rows)} rows as {fmt}")
        set_state(dbt, upload_id, progress=15)

        total = len(rows) or 1
        inserted = 0
        for r in rows:
            ts = None
            for key in ("time","timestamp","ts"):
                ts = _norm_ts(r.get(key))
                if ts: break
            ev = LogEvent(
                upload_id=upload_id,
                ts=ts,
                src_ip=r.get("src_ip") or r.get("srcip") or r.get("client_ip"),
                user=r.get("user") or r.get("username"),
                url=r.get("url") or r.get("host") or None,
                action=r.get("action"),
                status=(int(r.get("status")) if str(r.get("status") or "").isdigit() else None),
                bytes=int(r.get("bytes") or 0) if str(r.get("bytes") or "").isdigit() else None,
                user_agent=r.get("user_agent") or r.get("ua") or None,
                raw=r.get("raw") or None,
            )
            dbt.add(ev)
            inserted += 1
            if inserted % 500 == 0:
                dbt.commit()
                prog = 15 + int(55 * (inserted / total))
                set_state(dbt, upload_id, progress=min(70, prog))
        dbt.commit()
        set_state(dbt, upload_id, progress=75)

        # Detect anomalies (light store)
        evs = dbt.execute(select(LogEvent).where(LogEvent.upload_id == upload_id)).scalars().all()
        ev_dicts = [{
            "event_id": e.id,
            "ts": e.ts, "src_ip": e.src_ip, "user": e.user,
            "url": e.url, "action": e.action, "status": e.status,
            "user_agent": e.user_agent, "raw": e.raw
        } for e in evs]
        found = detect_anomalies(ev_dicts)

        for a in found:
            meta = a.get("meta") or {}
            ev_id = a.get("event_id") or (meta.get("event_ids", [None])[0])
            dbt.add(Anomaly(upload_id=upload_id, event_id=ev_id, reason=a.get("reason"), score=a.get("score")))
        dbt.commit()

        # ---- Summarizing (single LLM call per upload) ----
        id_to_event = {e.id: {
            "id": e.id,
            "ts": e.ts.isoformat() if e.ts else None,
            "src_ip": e.src_ip, "user": e.user, "url": e.url,
            "action": e.action, "status": e.status, "bytes": e.bytes,
            "user_agent": e.user_agent, "raw": e.raw
        } for e in evs}
        grouped = _group_anomalies(found, id_to_event)

        # Simple per-minute timeline (counts only) for context
        from collections import Counter
        timeline = Counter()
        for e in evs:
            if e.ts:
                minute = e.ts.replace(second=0, microsecond=0).isoformat()
                timeline[minute] += 1
        timeline_points = [{"minute": k, "count": v} for k, v in sorted(timeline.items())]

        # Show UI progress during LLM call
        set_state(dbt, upload_id, status="summarizing", progress=88)

        try:
            ai_text = summarize_log(
                context={
                    "filename": u.filename,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                    "counts": {"events": len(evs), "anomalies": len(found), "groups": len(grouped)},
                },
                groups=grouped,
                timeline=timeline_points[-60:],  # last 60 points for brevity
            )
        except Exception:
            ai_text = None

        # Cache the overall summary (guard if columns not ready yet)
        try:
            u = dbt.get(Upload, upload_id)
            u.ai_summary = ai_text
            u.ai_summary_model = os.getenv("LLM_MODEL")
            u.ai_summary_at = datetime.now(timezone.utc)
            dbt.add(u)
            dbt.commit()
        except Exception as e:
            app.logger.warning(f"LLM summary cache skipped (columns not ready?): {e}")

        set_state(dbt, upload_id, status="done", progress=100)

    except Exception:
        traceback.print_exc()
        set_state(dbt, upload_id, status="failed", progress=100)
    finally:
        dbt.close()

# ---------- routes ----------
@app.post("/api/login")
def login():
    return login_handler()

@app.get("/api/health")
def health():
    # report DB readiness but always return 200 so Railway healthcheck passes quickly
    return {"ok": True, "db": "ready" if DB_READY else "not_ready"}

@app.route("/api/upload", methods=["OPTIONS"])
def upload_options():
    return ("", 204)

@app.post("/api/upload")
@require_auth
def upload():
    if "file" not in request.files:
        return {"error": "no file"}, 400
    up_file = request.files["file"]
    content = up_file.read().decode(errors="ignore")

    db = SessionLocal()
    up = Upload(
        filename=up_file.filename,
        status="uploaded",
        progress=0,
        raw_content=content,
    )
    db.add(up)
    db.commit()
    db.refresh(up)
    upload_id = up.id
    db.close()
    return {"upload_id": upload_id, "status": "uploaded", "progress": 0}, 200

@app.route("/api/analyze/<int:upload_id>", methods=["OPTIONS"])
def analyze_options(upload_id: int):
    return ("", 204)

@app.post("/api/analyze/<int:upload_id>")
@require_auth
def analyze(upload_id: int):
    db = SessionLocal()
    up = db.get(Upload, upload_id)
    if not up:
        db.close()
        return {"error": "not found"}, 404
    if up.status in ("processing", "summarizing", "done"):
        res = {"upload_id": up.id, "status": up.status, "progress": up.progress}
        db.close()
        return jsonify(res), 202 if up.status != "done" else 200

    up.status = "processing"
    up.progress = 5
    db.add(up); db.commit(); db.close()

    threading.Thread(target=_process_analysis, args=(upload_id,), daemon=True).start()
    return {"upload_id": upload_id, "status": "processing", "progress": 5}, 202

@app.get("/api/status/<int:upload_id>")
@require_auth
def status(upload_id: int):
    db = SessionLocal()
    up = db.get(Upload, upload_id)
    if not up:
        db.close()
        return {"error": "not found"}, 404
    data = {"upload_id": up.id, "status": up.status or "uploaded", "progress": up.progress or 0}
    db.close()
    return jsonify(data)

@app.get("/api/analysis/<int:upload_id>")
@require_auth
def analysis(upload_id: int):
    db = SessionLocal()
    up = db.get(Upload, upload_id)
    if not up:
        db.close()
        return {"error": "not found"}, 404

    if (up.status or "uploaded") != "done":
        data = {
            "upload": {"id": up.id, "filename": up.filename, "created_at": up.created_at.isoformat()},
            "status": up.status or "uploaded",
            "progress": up.progress or 0,
        }
        db.close()
        return jsonify(data), 202

    evs = db.execute(select(LogEvent).where(LogEvent.upload_id == upload_id)).scalars().all()

    # Timeline
    from collections import Counter
    timeline = Counter()
    for e in evs:
        if e.ts:
            minute = e.ts.replace(second=0, microsecond=0).isoformat()
            timeline[minute] += 1
    timeline_points = [{"minute": k, "count": v} for k, v in sorted(timeline.items())]

    # id -> event dict
    id_to_event = {e.id: {
        "id": e.id,
        "ts": e.ts.isoformat() if e.ts else None,
        "src_ip": e.src_ip, "user": e.user, "url": e.url,
        "action": e.action, "status": e.status, "bytes": e.bytes,
        "user_agent": e.user_agent, "raw": e.raw
    } for e in evs}

    # Recompute rich anomalies to get event_ids
    ev_dicts = [{
        "event_id": e.id,
        "ts": e.ts, "src_ip": e.src_ip, "user": e.user,
        "url": e.url, "action": e.action, "status": e.status,
        "user_agent": e.user_agent, "raw": e.raw
    } for e in evs]
    rich_anoms = detect_anomalies(ev_dicts)
    grouped = _group_anomalies(rich_anoms, id_to_event)

    data = {
        "upload": {"id": up.id, "filename": up.filename, "created_at": up.created_at.isoformat()},
        "events": list(id_to_event.values()),
        "timeline": timeline_points,
        "anomaly_groups": grouped,
        "summary": getattr(up, "ai_summary", None),  # overall LLM summary (cached)
        "status": "done",
        "progress": 100,
    }
    db.close()
    return jsonify(data)

@app.get("/api/uploads")
@require_auth
def list_uploads():
    db = SessionLocal()
    ups = db.execute(select(Upload).order_by(Upload.created_at.desc())).scalars().all()
    data = [{
        "id": u.id,
        "filename": u.filename,
        "created_at": u.created_at.isoformat(),
        "status": (u.status or "uploaded"),
        "progress": (u.progress or 0),
        "has_summary": bool(getattr(u, "ai_summary", None)),
    } for u in ups]
    db.close()
    return jsonify(data)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, threaded=True)
