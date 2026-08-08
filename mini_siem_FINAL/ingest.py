"""
ingest.py
---------
Receiving side of log forwarding. Remote machines (your Windows Server
2022 VM, Windows Enterprise VM, etc.) run forwarder.py, which POSTs each
event here. This validates a shared secret, then feeds the event through
the exact same save_event() pipeline local collection uses - so forwarded
events get the same detection rules, MITRE tagging, SOAR playbooks,
everything, with zero special-casing anywhere else in the app.

AUTH MODEL: this endpoint is machine-to-machine, not a logged-in browser
session, so it doesn't use the same cookie-based auth as everything else.
Instead, forwarders send a shared secret in the X-SIEM-Key header. Set it
with the SIEM_INGEST_KEY environment variable before starting the app -
if you don't set one, a random key is generated and printed once at
startup (same pattern as the default admin password).

This is HTTP, not HTTPS - fine for an isolated lab/VM network, but if you
ever point this at anything beyond your own local network, that traffic
(including the shared secret) is unencrypted. Worth knowing, and worth
mentioning if this comes up in an interview.
"""

import os
import secrets

import collector

KEY_FILE = os.path.join(os.path.dirname(__file__), "ingest_key.txt")


def _load_or_create_key():
    if os.environ.get("SIEM_INGEST_KEY"):
        return os.environ["SIEM_INGEST_KEY"]
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            return f.read().strip()
    key = secrets.token_hex(16)
    with open(KEY_FILE, "w") as f:
        f.write(key)
    print(f"[INGEST] Generated a new forwarder key (also saved to {KEY_FILE}):")
    print(f"[INGEST]   {key}")
    print(f"[INGEST] Use this as SIEM_INGEST_KEY on every machine running forwarder.py")
    return key


INGEST_KEY = _load_or_create_key()

# Fields a forwarded event must include - anything else is optional and
# defaults sensibly, same as local collection does.
REQUIRED_FIELDS = {"event_id", "event_type", "host"}


# ---------------------------------------------------------------------
# Self-contained Flask Blueprint - app.py only needs:
#   import ingest
#   app.register_blueprint(ingest.bp)
# ---------------------------------------------------------------------
from flask import Blueprint, request, jsonify

bp = Blueprint("ingest", __name__)


@bp.route("/api/ingest/event", methods=["POST"])
def api_ingest_event():
    if request.headers.get("X-SIEM-Key") != INGEST_KEY:
        return jsonify({"error": "Invalid or missing X-SIEM-Key header."}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Expected a JSON body."}), 400

    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        return jsonify({"error": f"Missing required fields: {sorted(missing)}"}), 400

    try:
        entry, alerts = collector.save_event(
            source=data.get("source", "Forwarded"),
            event_id=int(data["event_id"]),
            event_type=data["event_type"],
            user=data.get("user", ""),
            source_ip=data.get("source_ip", ""),
            host=data["host"],
            message=data.get("message", ""),
        )
    except (ValueError, TypeError) as e:
        return jsonify({"error": f"Bad event data: {e}"}), 400

    return jsonify({"ok": True, "log_id": entry["id"], "alerts_triggered": len(alerts)})


@bp.route("/api/ingest/ping")
def api_ingest_ping():
    """Lets a forwarder (or you, with curl/browser) verify connectivity
    and the key BEFORE setting up continuous forwarding - saves a lot of
    'is it even reaching the server' debugging."""
    if request.headers.get("X-SIEM-Key") != INGEST_KEY:
        return jsonify({"error": "Invalid or missing X-SIEM-Key header."}), 401
    return jsonify({"ok": True, "message": "Ingest endpoint reachable and key accepted."})
