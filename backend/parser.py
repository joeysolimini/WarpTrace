from datetime import datetime
from typing import List, Dict, Any
import csv, io
import json

# Expected Zscaler‑ish CSV headers sample:
# time,src_ip,user,url,action,status,bytes,user_agent

def parse_auth0_jsonl(text: str, auth_domain: str = "auth.warptrace.corp"):
    """
    Parse Auth0-style JSON Lines into Warptrace's normalized row dicts:
    returns list[dict] with keys: time, src_ip, user, url, action, status, bytes, user_agent, raw
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)

        etype = (obj.get("type") or "").lower()
        date = (obj.get("date") or "").strip()

        # Choose URL by event type (rough approximation)
        if etype in ("s", "f"):                  # login success/failure
            url = f"https://{auth_domain}/authorize"
        elif etype in ("seacft", "feacft"):      # token exchange success/failure
            url = f"https://{auth_domain}/oauth/token"
        else:
            url = f"https://{auth_domain}/"

        # Action/status mapping
        if etype in ("s", "seacft"):
            action, status = "allow", 200
        elif etype in ("f", "feacft"):           # app rejected creds / token
            action, status = "allow", 401
        elif etype in ("w", "limit", "blocked"): # brute-force protection / blocked
            action, status = "block", 403
        else:
            action, status = "allow", 200

        ua = (
            (obj.get("details") or {}).get("device")
            or (obj.get("details") or {}).get("user_agent")
            or "Auth0"
        )

# Surface risk hints for anomaly engine
        risk = ""
        det = obj.get("details") or {}
        if isinstance(det.get("risk"), dict) and "score" in det["risk"]:
            risk = f" risk={det['risk'].get('score')} reason={det['risk'].get('reason','')}"

        out.append({
            "time": date,
            "src_ip": obj.get("ip"),
            "user": obj.get("user_name") or obj.get("user_id"),
            "url": url,
            "action": action,
            "status": status,
            "bytes": 0,
            "user_agent": ua,
            "raw": (obj.get("description") or obj.get("log_id") or "") + risk,
        })
    return out

def parse_csv(content: str) -> List[Dict[str, Any]]:
    rows = []
    reader = csv.DictReader(io.StringIO(content))
    for r in reader:
        rows.append({k.strip(): (v.strip() if isinstance(v,str) else v) for k,v in r.items()})
    return rows

def parse_fallback_lines(content: str) -> List[Dict[str, Any]]:
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line: 
            continue
        rows.append({
            "time": None, "src_ip": None, "user": None, "url": None,
            "action": None, "status": None, "bytes": None, "user_agent": None,
            "raw": line
        })
    return rows
