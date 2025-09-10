# anomaly.py
from __future__ import annotations
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# Tunables
BRUTE_FORCE_WINDOW_SEC = 120
BRUTE_FORCE_MIN_FAILS  = 10
ERROR_RATE_WINDOW_MIN  = 10
ERROR_RATE_MIN_EVENTS  = 20
ERROR_RATE_THRESHOLD   = 0.65
RARE_UA_MIN_COUNT      = 2
OFF_HOURS_START        = 0
OFF_HOURS_END          = 5

# Keyword recognizers for Auth0-like logs
PASSWORD_RESET_RE = re.compile(
    r"(password[\s_-]*(reset|change|changed|update|updated)|reset\s+password|pwd[\s_-]*reset|post-change-password|recovery\s+(email|ticket))",
    re.I,
)
MFA_RE = re.compile(
    r"\b(mfa|multi[-\s]?factor|guardian|otp|one[-\s]?time|webauthn|duo|push|factor|challenge|enroll|enrollment|recovery\s+code)\b",
    re.I,
)

def _freeze(x):
    """Make nested dict/list/set hashable for de-duplication keys."""
    if isinstance(x, dict):
        return tuple(sorted((k, _freeze(v)) for k, v in x.items()))
    if isinstance(x, (list, tuple)):
        return tuple(_freeze(v) for v in x)
    if isinstance(x, set):
        return tuple(sorted(_freeze(v) for v in x))
    return x

def _as_dt(x: Any) -> Optional[datetime]:
    if x is None: return None
    if isinstance(x, datetime): return x
    s = str(x).strip()
    try:
        if s.endswith(("Z","z")):
            return datetime.fromisoformat(s[:-1] + "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

def _as_int(x: Any) -> Optional[int]:
    try: return int(x)
    except Exception: return None

def _host(url: Optional[str]) -> str:
    if not url: return ""
    try: return urlparse(url).hostname or ""
    except Exception: return ""

def _bucket_minute(ts: Optional[datetime]) -> str:
    if not ts:
        return "unknown"
    return ts.replace(second=0, microsecond=0).isoformat()

def detect_anomalies(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Input events (normalized by app.py):
        keys: ts, src_ip, user, url, action, status, bytes, user_agent, raw, (event_id or id)
    Output anomalies with rich meta (including event_ids):
        { reason, score, kind, meta: {event_ids: [...], ...} }
    """
    if not events: return []

    norm: List[Dict[str, Any]] = []
    for e in events:
        # tolerate either "event_id" or "id" coming from the backend
        evid = e.get("event_id")
        if evid is None:
            evid = e.get("id")
        norm.append({
            "ts": _as_dt(e.get("ts")),
            "status": _as_int(e.get("status")),
            "src_ip": e.get("src_ip") or "",
            "user": e.get("user") or "",
            "user_agent": (e.get("user_agent") or "").strip(),
            "action": (e.get("action") or "").strip().lower(),
            "url": e.get("url") or "",
            "host": _host(e.get("url")),
            "raw": (e.get("raw") or "").lower(),
            "event_id": evid,
        })

    ua_counts = Counter(ev["user_agent"] for ev in norm if ev["user_agent"])
    time_sorted = sorted([ev for ev in norm if ev["ts"] is not None], key=lambda x: x["ts"])

    anomalies: List[Dict[str, Any]] = []

    # 0) Explicit password reset / MFA activity (bucketed by minute, user, ip)
    def _pwd_mfa_activity():
        pwd_buckets: Dict[tuple, List[int]] = defaultdict(list)  # (minute,user,ip) -> [event_id]
        mfa_buckets: Dict[tuple, List[int]] = defaultdict(list)

        for ev in norm:
            text = " ".join(
                str(x) for x in [
                    ev.get("action",""),
                    ev.get("status",""),
                    ev.get("url",""),
                    ev.get("user_agent",""),
                    ev.get("raw",""),
                ] if x
            )
            minute = _bucket_minute(ev.get("ts"))
            user   = (ev.get("user") or "").strip() or "<unknown>"
            ip     = (ev.get("src_ip") or "").strip() or "<ip?>"
            evid   = ev.get("event_id")

            if PASSWORD_RESET_RE.search(text):
                if evid is not None:
                    pwd_buckets[(minute, user, ip)].append(evid)
                else:
                    pwd_buckets.setdefault((minute, user, ip), [])

            if MFA_RE.search(text):
                if evid is not None:
                    mfa_buckets[(minute, user, ip)].append(evid)
                else:
                    mfa_buckets.setdefault((minute, user, ip), [])

        for (minute, user, ip), ids in pwd_buckets.items():
            anomalies.append({
                "reason": f"Password reset/change observed for {user}.",
                "score": 0.65,
                "kind": "auth.password_reset",
                "meta": {"user": user, "src_ip": ip, "minute": minute, "event_ids": ids[:50]},
            })

        for (minute, user, ip), ids in mfa_buckets.items():
            anomalies.append({
                "reason": f"MFA activity observed (enroll/challenge/reset) for {user}.",
                "score": 0.55,
                "kind": "auth.mfa_activity",
                "meta": {"user": user, "src_ip": ip, "minute": minute, "event_ids": ids[:50]},
            })

    # 1) Brute force (many 401s in short window)
    def _brute_force():
        win_user: Dict[str, deque] = defaultdict(deque)            # deque[(ts, id)]
        win_pair: Dict[tuple, deque] = defaultdict(deque)          # deque[(ts, id)]
        for ev in time_sorted:
            if ev["status"] != 401: continue
            t = ev["ts"]; eid = ev.get("event_id")
            k_user = ev["user"] or "<unknown>"
            k_pair = (ev["user"] or "<unknown>", ev["src_ip"] or "<ip?>")
            for q in (win_user[k_user], win_pair[k_pair]):
                q.append((t, eid))
                while q and (t - q[0][0]).total_seconds() > BRUTE_FORCE_WINDOW_SEC:
                    q.popleft()
            if len(win_user[k_user]) >= BRUTE_FORCE_MIN_FAILS:
                anomalies.append({
                    "reason": f"Brute-force suspected against user {k_user}",
                    "score": 0.95,
                    "kind": "auth.bruteforce_user",
                    "meta": {
                        "window_sec": BRUTE_FORCE_WINDOW_SEC,
                        "failures": len(win_user[k_user]),
                        "user": k_user,
                        "event_ids": [x[1] for x in list(win_user[k_user]) if x[1] is not None][:50],
                    },
                })
                win_user[k_user].clear()
            if len(win_pair[k_pair]) >= BRUTE_FORCE_MIN_FAILS:
                anomalies.append({
                    "reason": f"Brute-force suspected from {k_pair[1]} targeting {k_pair[0]}",
                    "score": 0.96,
                    "kind": "auth.bruteforce_pair",
                    "meta": {
                        "window_sec": BRUTE_FORCE_WINDOW_SEC,
                        "failures": len(win_pair[k_pair]),
                        "user": k_pair[0], "src_ip": k_pair[1],
                        "event_ids": [x[1] for x in list(win_pair[k_pair]) if x[1] is not None][:50],
                    },
                })
                win_pair[k_pair].clear()

    # 2) Auth0 protection blocked
    def _blocked_protection():
        for ev in norm:
            if ev["status"] == 403 and ("brute-force" in ev["raw"] or "blocked" in ev["raw"]):
                anomalies.append({
                    "reason": f"Auth0 protection blocked login (user={ev['user']} ip={ev['src_ip']})",
                    "score": 0.9,
                    "kind": "auth.blocked",
                    "meta": {"status": ev["status"], "event_ids": [ev["event_id"]] if ev.get("event_id") else []},
                })

    # 3) High-risk source (risk score / TOR)
    def _high_risk_source():
        for ev in norm:
            raw = ev["raw"]
            if "risk=" in raw:
                try:
                    frag = raw.split("risk=", 1)[1]
                    val = float(frag.split()[0].strip(" ;,"))
                except Exception:
                    val = 0.9
                score = min(1.0, max(0.0, 0.85 + 0.15 * val))
                anomalies.append({
                    "reason": f"High-risk login source (user={ev['user']} ip={ev['src_ip']})",
                    "score": score,
                    "kind": "auth.high_risk",
                    "meta": {"risk": val, "event_ids": [ev["event_id"]] if ev.get("event_id") else []},
                })
            elif "tor" in raw or "tor_exit" in raw:
                anomalies.append({
                    "reason": f"Login from TOR-like source (user={ev['user']} ip={ev['src_ip']})",
                    "score": 0.88,
                    "kind": "auth.tor",
                    "meta": {"event_ids": [ev["event_id"]] if ev.get("event_id") else []},
                })

    # 4) High error rate buckets
    def _high_error_rate():
        by_bucket: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for ev in time_sorted:
            b = ev["ts"].replace(second=0, microsecond=0)
            b = b - timedelta(minutes=b.minute % ERROR_RATE_WINDOW_MIN)
            by_bucket[("user", ev["user"], b)].append(ev)
            by_bucket[("host", ev["host"], b)].append(ev)

        for (kind, who, b), lst in by_bucket.items():
            if len(lst) < ERROR_RATE_MIN_EVENTS: continue
            errors = sum(1 for x in lst if x["status"] and 400 <= x["status"] < 600)
            ratio = errors / max(1, len(lst))
            if ratio >= ERROR_RATE_THRESHOLD:
                anomalies.append({
                    "reason": f"High error rate ({ratio:.0%}) in 10-min window for {who}",
                    "score": 0.82 if ratio >= 0.8 else 0.75,
                    "kind": f"web.error_{kind}",
                    "meta": {
                        "events": len(lst), "errors": errors,
                        "event_ids": [e["event_id"] for e in lst if e.get("event_id")][:50],
                    },
                })

    # 5) Rare UA
    def _rare_ua():
        seen = set()
        for ev in norm:
            ua = ev["user_agent"]
            if not ua or ua in seen: continue
            if ua_counts[ua] < RARE_UA_MIN_COUNT:
                ids = [e.get("event_id") for e in norm if e["user_agent"] == ua and e.get("event_id")][:10]
                anomalies.append({
                    "reason": f"Rare user-agent observed: '{ua}'",
                    "score": 0.62 if ua_counts[ua] == 1 else 0.58,
                    "kind": "web.rare_ua",
                    "meta": {"count": ua_counts[ua], "event_ids": ids},
                })
                seen.add(ua)

    # 6) Off-hours 00:00–05:59
    def _off_hours_logins():
        ids = []
        for ev in time_sorted:
            if ev["status"] == 200 and ev["ts"] is not None:
                if OFF_HOURS_START <= ev["ts"].hour <= OFF_HOURS_END:
                    if ev.get("event_id"): ids.append(ev["event_id"])
        if ids:
            anomalies.append({
                "reason": "Off-hours successful logins detected",
                "score": 0.55,
                "kind": "auth.offhours",
                "meta": {"event_ids": ids[:50]},
            })

    # 7) Token exchange failures burst (/oauth/token 401)
    def _token_exchange_failures():
        win: Dict[str, deque] = defaultdict(deque)  # host -> deque[(ts,id)]
        for ev in time_sorted:
            if ev["status"] != 401: continue
            if "/oauth/token" not in (ev["url"] or ""): continue
            host = ev["host"] or "<auth>"
            t = ev["ts"]; eid = ev.get("event_id")
            q = win[host]; q.append((t, eid))
            while q and (t - q[0][0]).total_seconds() > 300:
                q.popleft()
            if len(q) >= 15:
                anomalies.append({
                    "reason": f"Spike of token-exchange failures at {host}",
                    "score": 0.8,
                    "kind": "auth.token_fail_burst",
                    "meta": {"window_sec": 300, "failures": len(q),
                            "event_ids": [x[1] for x in list(q) if x[1] is not None][:50]},
                })
                q.clear()

    # Run passes
    _pwd_mfa_activity()
    _brute_force()
    _blocked_protection()
    _high_risk_source()
    _high_error_rate()
    _rare_ua()
    _off_hours_logins()
    _token_exchange_failures()

    # de-dupe identical reasons/meta
    seen, unique = set(), []
    for a in anomalies:
        key = (a.get("kind"), a.get("reason"), _freeze(a.get("meta") or {}))
        if key in seen:
            continue
        seen.add(key)
        unique.append(a)
    return unique
