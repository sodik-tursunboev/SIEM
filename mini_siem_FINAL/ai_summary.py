"""
ai_summary.py
-------------
Turns a batch of raw alerts into a short, plain-English incident summary
using an LLM API. This is the kind of "triage assistant" feature real SOC
teams are actively adding to their tooling right now - useful to have
built yourself so you can talk through exactly how it works, what it does
and doesn't do, and its limitations, rather than just knowing it exists
as a buzzword.

Supports two providers - pick one with the SIEM_AI_PROVIDER environment
variable:

  SIEM_AI_PROVIDER=anthropic  (default)  - needs ANTHROPIC_API_KEY
      Get a key at https://console.anthropic.com

  SIEM_AI_PROVIDER=groq                  - needs GROQ_API_KEY
      Get a key at https://console.groq.com (has a free tier)

    Windows (cmd):
        set SIEM_AI_PROVIDER=groq
        set GROQ_API_KEY=gsk_...
    Windows (PowerShell):
        $env:SIEM_AI_PROVIDER="groq"
        $env:GROQ_API_KEY="gsk_..."

If the relevant key isn't set, summarize() returns a clear explanatory
message instead of failing - the rest of the app works completely fine
without this feature configured.

IMPORTANT: alert data (rule names, usernames, IPs, descriptions) is sent
to whichever provider's API you configure when you use this feature.
Don't use it on a real production system's real data unless that's
acceptable for your environment - for a portfolio/learning project
running demo or your own test data, that's fine.
"""

import os
import json
import requests

# Pick your provider with SIEM_AI_PROVIDER - "anthropic" (default) or "groq".
# Groq's free tier is a good option if you don't want to pay for API usage -
# see https://console.groq.com to get a key.
PROVIDER = os.environ.get("SIEM_AI_PROVIDER", "anthropic").lower()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-5"  # good balance of quality/cost for this use case

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
# llama-3.3-70b-versatile is deprecated as of mid-2026 - gpt-oss-120b is
# Groq's current recommended general-purpose model. Override with
# SIEM_GROQ_MODEL if you want a different one from console.groq.com/docs/models.
GROQ_MODEL = os.environ.get("SIEM_GROQ_MODEL", "openai/gpt-oss-120b")

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst assistant. \
You will be given a JSON list of security alerts from a SIEM. Write a concise, \
plain-English incident summary a busy analyst could read in 20 seconds. Cover:
1. What happened, in plain language (not just restating alert names)
2. Likely attack pattern or intent, if the alerts suggest one (e.g. "this looks \
like a brute-force attempt followed by successful privilege escalation")
3. Which users/hosts/IPs are most involved
4. A recommended next action (investigate, contain, or likely benign)

Be direct and specific. Do not pad with generic security advice. If the alerts \
don't clearly connect into one incident, say so plainly instead of forcing a \
narrative. Keep the whole summary under 180 words."""


def is_configured():
    if PROVIDER == "groq":
        return bool(GROQ_API_KEY)
    return bool(ANTHROPIC_API_KEY)


def _format_alerts_for_prompt(alerts):
    slim = [{
        "time": a.get("timestamp"),
        "severity": a.get("severity"),
        "rule": a.get("rule_name"),
        "description": a.get("description"),
        "user": a.get("related_user"),
        "ip": a.get("related_ip"),
        "mitre": a.get("mitre_id"),
    } for a in alerts]
    return json.dumps(slim, indent=2)


def summarize(alerts: list) -> dict:
    """Returns {"ok": True, "summary": "..."} on success, or
    {"ok": False, "error": "..."} with a human-readable reason on failure -
    callers should always check "ok" before trusting "summary"."""
    if PROVIDER not in ("anthropic", "groq"):
        return {"ok": False, "error": f"Unknown SIEM_AI_PROVIDER '{PROVIDER}' - use 'anthropic' or 'groq'."}

    if not is_configured():
        key_name = "GROQ_API_KEY" if PROVIDER == "groq" else "ANTHROPIC_API_KEY"
        where = "console.groq.com" if PROVIDER == "groq" else "console.anthropic.com"
        return {
            "ok": False,
            "error": f"AI summaries aren't configured yet. Set the {key_name} "
                     f"environment variable (get a key at {where}) and restart the app.",
        }

    if not alerts:
        return {"ok": False, "error": "No alerts in this time range to summarize."}

    prompt_data = _format_alerts_for_prompt(alerts)

    if PROVIDER == "groq":
        result = _call_groq(prompt_data)
    else:
        result = _call_anthropic(prompt_data)

    if not result["ok"]:
        return result

    text = result["text"].strip()
    if not text:
        return {"ok": False, "error": "API returned an empty response."}
    return {"ok": True, "summary": text, "alert_count": len(alerts)}


def _call_anthropic(prompt_data: str) -> dict:
    try:
        response = requests.post(
            ANTHROPIC_URL,
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 400,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt_data}],
            },
            timeout=30,
        )
    except requests.RequestException as e:
        return {"ok": False, "error": f"Couldn't reach the Anthropic API: {e}"}

    if response.status_code == 401:
        return {"ok": False, "error": "API key was rejected (401). Check ANTHROPIC_API_KEY is correct."}
    if response.status_code == 429:
        return {"ok": False, "error": "Rate limited by the Anthropic API (429). Try again shortly."}
    if response.status_code != 200:
        return {"ok": False, "error": f"Anthropic API returned an error: {response.status_code} {response.text[:200]}"}

    try:
        data = response.json()
        text = "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
    except Exception as e:
        return {"ok": False, "error": f"Couldn't parse the Anthropic response: {e}"}

    return {"ok": True, "text": text}


def _call_groq(prompt_data: str) -> dict:
    try:
        response = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "max_tokens": 400,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt_data},
                ],
            },
            timeout=30,
        )
    except requests.RequestException as e:
        return {"ok": False, "error": f"Couldn't reach the Groq API: {e}"}

    if response.status_code == 401:
        return {"ok": False, "error": "API key was rejected (401). Check GROQ_API_KEY is correct."}
    if response.status_code == 429:
        return {"ok": False, "error": "Rate limited by the Groq API (429). Try again shortly."}
    if response.status_code == 404:
        return {"ok": False, "error": f"Groq model '{GROQ_MODEL}' not found - it may have been "
                                       f"deprecated. Check console.groq.com/docs/models for current names "
                                       f"and set SIEM_GROQ_MODEL to override."}
    if response.status_code != 200:
        return {"ok": False, "error": f"Groq API returned an error: {response.status_code} {response.text[:200]}"}

    try:
        data = response.json()
        text = data["choices"][0]["message"]["content"]
    except Exception as e:
        return {"ok": False, "error": f"Couldn't parse the Groq response: {e}"}

    return {"ok": True, "text": text}


# ---------------------------------------------------------------------
# Self-contained Flask route - packaged as a Blueprint so app.py only
# needs two lines added to wire this in (see bottom of this file's
# docstring / the setup instructions you were given).
# ---------------------------------------------------------------------
from flask import Blueprint, request, jsonify, render_template
from datetime import datetime, timedelta
import auth
import database as db

bp = Blueprint("ai_summary", __name__)


@bp.route("/ai-summary")
@auth.login_required
def ai_summary_page():
    """The page with the button. Anyone logged in can view it - the
    generate button itself calls /api/ai-summary, which is gated at
    Analyst role or above, so a Viewer clicking it just sees a clear
    permission message instead of the page being hidden outright."""
    return render_template("ai_summary.html")


@bp.route("/api/ai-summary")
@auth.role_required("Analyst")
def api_ai_summary():
    """On-demand AI incident summary over a time window (default: last 24h).
    Gated at Analyst role or above since each call costs real API usage."""
    hours = int(request.args.get("hours", 24))
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    alerts, _ = db.search_alerts(date_from=since, limit=200)
    result = summarize(alerts)
    return jsonify(result)
