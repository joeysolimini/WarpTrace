from __future__ import annotations
import os, json, re, logging, typing as t

from openai import OpenAI
from openai._exceptions import OpenAIError  # type: ignore

# ---------- logging ----------
log = logging.getLogger("warptrace.summarizer")

# ---------- OpenRouter config (safe defaults) ----------
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
DEFAULT_MODEL       = os.getenv("LLM_MODEL", "openrouter/auto")  # stable auto route
SITE = os.getenv("OPENROUTER_SITE_URL", "http://localhost:5173")
APP  = os.getenv("OPENROUTER_APP_NAME", "WarpTrace")

def _or_headers() -> dict[str, str]:
    # OpenRouter asks for these headers to attribute usage.
    site  = os.getenv("OPENROUTER_SITE_URL", SITE) or ""
    title = os.getenv("OPENROUTER_APP_NAME", APP) or "WarpTrace"
    hdrs  = {"X-Title": title}
    if site:
        hdrs["HTTP-Referer"] = site
    return hdrs

def _client() -> OpenAI:
    return OpenAI(
        base_url=os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL),
        api_key=os.getenv("OPENROUTER_API_KEY"),
        default_headers=_or_headers(),
        timeout=30.0,
    )

# ---------- helpers ----------
def _looks_html(s: str | None) -> bool:
    if not s: return False
    t = s.strip().lower()
    return t.startswith("<!doctype html") or t.startswith("<html")

def _strip_reasoning(text: str) -> str:
    if not text:
        return text
    text = re.sub(r"<think>.*?</think>\s*", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"```(?:thinking|reasoning)?\s*.*?```", "", text, flags=re.DOTALL | re.IGNORECASE)
    return text.strip()

def _rule_based_log_summary(context: dict[str, t.Any], groups: list[dict[str, t.Any]], timeline: list[dict[str, t.Any]]) -> str:
    lines = []
    c = (context or {}).get("counts", {})
    lines.append(f"Review {c.get('events','?')} events with {c.get('anomalies','?')} notable findings across {c.get('groups','?')} categories.")
    for g in groups[:5]:
        kind = g.get("kind","finding")
        ex_user = (g.get("users") or ["users"])[0]
        ex_ip   = (g.get("src_ips") or ["sources"])[0]
        if kind.startswith("auth.bruteforce"):
            lines.append(f"Investigate repeated login failures (e.g., {ex_user} from {ex_ip}); lock account, reset password, enforce MFA.")
        elif kind == "auth.blocked":
            lines.append("Review Auth0 blocks and preceding failures; if legit, force password reset and re-enroll MFA.")
        elif kind in ("auth.high_risk","auth.tor"):
            lines.append(f"Verify session owners (e.g., {ex_user}); block/geo-fence suspect IPs (e.g., {ex_ip}) and require step-up MFA.")
        elif kind.startswith("web.error_"):
            lines.append("Correlate elevated error rates with deploys/metrics; mitigate and watch for abuse patterns.")
        elif kind == "web.rare_ua":
            lines.append("Validate rare clients; if unsanctioned, rate-limit or block and capture samples.")
        elif kind == "auth.offhours":
            lines.append("Confirm off-hours access and enable conditional access or step-up MFA.")
        elif kind == "auth.token_fail_burst":
            lines.append("Audit client credential usage/rotation and OAuth scopes for token failure spikes.")
        else:
            lines.append(f"Address {kind} findings with targeted containment and user validation.")
    return "• " + "\n• ".join(lines)

def _rule_based_summary(anom: dict[str, t.Any], samples: list[dict[str, t.Any]]) -> str:
    kind = (anom.get("kind") or "")
    meta = anom.get("meta") or {}
    user = meta.get("user") or (samples[0].get("user") if samples else None)
    ip   = meta.get("src_ip") or (samples[0].get("src_ip") if samples else None)

    if kind.startswith("auth.bruteforce"):
        who = user or "this account"; src = ip or "one source"
        return f"Investigate rapid failed logins for {who} from {src}. Lock the account, reset the password, and review recent IP activity."
    if kind == "auth.blocked":
        who = user or "the account"
        return f"Review the blocked login and preceding failures for {who}. If legitimate, force a password reset and re-enroll MFA."
    if kind in ("auth.high_risk", "auth.tor"):
        who = user or "the account"; src = ip or "this IP"
        return f"Verify the session owner for {who} out-of-band. Geo-fence or block {src} and require step-up MFA."
    if kind.startswith("web.error_"):
        return "Correlate the elevated error rate with deploys and service metrics. Roll back or mitigate and watch for abuse patterns."
    if kind == "web.rare_ua":
        return "Confirm whether the rare client is sanctioned. If not, rate-limit or block and capture request samples."
    if kind == "auth.offhours":
        return "Confirm off-hours access with the user and enable step-up MFA or conditional access for unusual times."
    if kind == "auth.token_fail_burst":
        return "Audit client credentials usage and rotation. Check for expired or leaked secrets and misconfigured OAuth scopes."
    return (anom.get("reason") or "Review this anomaly.") + " Take immediate, minimal steps to validate and contain."

# ---------- low-level LLM call ----------
def _chat(messages: list[dict[str, str]], *, model: str, temperature=0.2, max_tokens=220) -> str:
    client = _client()
    try:
        comp = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        txt = (comp.choices[0].message.content or "").strip()
        if _looks_html(txt):
            log.warning("openrouter html_response_detected base=%s model=%s (check API key & headers)", client.base_url, model)
            raise RuntimeError("html_response")
        return _strip_reasoning(txt)
    except OpenAIError as e:
        status = getattr(e, "status_code", None) or getattr(e, "status", None)
        body   = getattr(e, "response", None)
        try:
            body = getattr(body, "json", lambda: {})()
        except Exception:
            body = str(body)
        log.warning("openrouter api_error status=%s detail=%s", status, body)
        raise
    except Exception as e:
        log.warning("openrouter client_error err=%s", e)
        raise

# ---------- single-anomaly summary ----------
def summarize_anomaly(anom: dict[str, t.Any], samples: list[dict[str, t.Any]]) -> str:
    llm_on  = os.getenv("LLM_ENABLED", "false").lower() == "true"
    has_key = bool(os.getenv("OPENROUTER_API_KEY"))
    model   = os.getenv("LLM_MODEL", DEFAULT_MODEL)

    log.info(
        "summarize start kind=%s llm_enabled=%s key=%s model=%s samples=%d",
        anom.get("kind"),
        llm_on,
        "yes" if has_key else "no",
        model,
        len(samples or []),
    )

    if llm_on and has_key:
        try:
            payload = {
                "reason": anom.get("reason"),
                "kind": anom.get("kind"),
                "user": (anom.get("meta") or {}).get("user"),
                "src_ip": (anom.get("meta") or {}).get("src_ip"),
                "samples": [{
                    "ts": s.get("ts"),
                    "user": s.get("user"),
                    "ip": s.get("src_ip"),
                    "status": s.get("status"),
                    "url": (s.get("url") or "")[:120],
                    "ua": (s.get("user_agent") or "")[:80],
                } for s in (samples or [])[:5]],
            }
            system = (
                "You are a senior SOC analyst. Write a concise, actionable summary of the anomaly. "
                "Rules: 1–2 short sentences, imperative voice. No metrics or probabilities. "
                "Focus on next steps: validate user, reset creds, enforce MFA, block/geo-fence IP, correlate with deploys."
            )
            user = "Anomaly context (JSON):\n" + json.dumps(payload, ensure_ascii=False)

            text = _chat(
                [{"role":"system","content":system}, {"role":"user","content":user}],
                model=model, temperature=0.2, max_tokens=120
            )
            log.info("summarize llm_ok chars=%d model=%s", len(text), model)
            return text
        except Exception:
            pass  # fall through to rules

    text = _rule_based_summary(anom, samples)
    log.info("summarize fallback_ok chars=%d", len(text))
    return text

# ---------- overall-log summary (one call per upload) ----------
def summarize_log(*, context: dict[str, t.Any], groups: list[dict[str, t.Any]], timeline: list[dict[str, t.Any]]) -> str:
    llm_on  = os.getenv("LLM_ENABLED", "false").lower() == "true"
    has_key = bool(os.getenv("OPENROUTER_API_KEY"))
    model   = os.getenv("LLM_MODEL", DEFAULT_MODEL)

    log.info(
        "summarize_log start llm=%s key=%s base=%s model=%s groups=%d",
        llm_on, "yes" if has_key else "no", os.getenv("OPENROUTER_BASE_URL", OPENROUTER_BASE_URL), model, len(groups or [])
    )

    total_groups = len(groups or [])
    total_anoms  = (context or {}).get("counts", {}).get("anomalies", total_groups)

    # --- clean baseline message
    if total_groups == 0 or total_anoms == 0:
        return (
            "No investigation necessary — events align with expected baseline. "
            "No anomalous authentication or traffic patterns detected."
        )

    payload = {
        "context": context,
        "groups": [
            {k: v for k, v in g.items() if k in ("kind","count","reasons","users","src_ips")}
            for g in (groups or [])
        ][:8],
        "timeline": (timeline or [])[-60:],
    }

    if llm_on and has_key:
        try:
            system = (
                "You are a senior SOC analyst. Produce a concise incident overview of this log upload. "
                "4–7 bullet points, imperative voice; do not include probabilities. "
                "Call out top finding types, affected users/IPs, and next steps (MFA, resets, blocks, geo-fence, correlate with deploys)."
            )
            user = "Analysis input (JSON):\n" + json.dumps(payload, ensure_ascii=False)

            text = _chat(
                [{"role":"system","content":system}, {"role":"user","content":user}],
                model=model, temperature=0.2, max_tokens=220
            )
            if len(text) > 2000:
                text = text[:2000].rstrip() + "…"
            log.info("summarize_log llm_ok chars=%d", len(text))
            return text
        except Exception as e:
            log.warning("summarize_log llm_failed err=%s", e)

    rb = _rule_based_log_summary(context, groups, timeline)
    log.info("summarize_log fallback_ok chars=%d", len(rb))
    return rb
