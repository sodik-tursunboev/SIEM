"""
saved_queries.py
-----------------
Threat Hunt Queries - saved searches for the Threat Hunting page, the
same idea as Elastic Discover's saved searches: click a preset to
instantly run a known-useful hunt, or save your own query once you've
built something worth reusing.

The 8 built-in presets below are seeded once at startup (see
register_builtin_queries, called from app.py) using the query language
from query_lang.py. A few of these (Golden Ticket, Kerberos Tickets) are
deliberately framed as HUNTS, not automatic detection rules - there's no
dedicated "Golden Ticket" alert in rules.py because reliably
distinguishing a forged ticket from a legitimate one needs a human
looking at ticket lifetime/context, not a fixed pattern match. That's
exactly the kind of thing threat hunting is for, as distinct from
automated detection.
"""

from datetime import datetime
from flask import Blueprint, request, jsonify, session

import database as db
import auth

bp = Blueprint("saved_queries", __name__)

# (name, query) - query syntax matches query_lang.py, run against /api/logs
BUILTIN_QUERIES = [
    ("Failed Logins", "eventtype:FailedLogon"),
    ("PowerShell", "eventtype:ProcessCreated AND message:*powershell*"),
    ("Encoded Commands", "message:*-enc* OR message:*encodedcommand*"),
    ("New Services", "eventtype:ServiceInstalled"),
    ("New Scheduled Tasks", "eventtype:ScheduledTaskCreated"),
    ("Kerberos Tickets", "eventid:4769"),
    ("Golden Ticket", "eventid:4768"),
    ("LSASS Access", "message:*lsass*"),
]


def register_builtin_queries():
    """Called once at app startup - safe to call every time, never
    duplicates or overwrites an existing query with the same name."""
    for name, query_text in BUILTIN_QUERIES:
        db.ensure_builtin_query(name, query_text)


@bp.route("/api/saved-queries")
@auth.login_required
def api_list_saved_queries():
    return jsonify(db.list_saved_queries())


@bp.route("/api/saved-queries", methods=["POST"])
@auth.role_required("Analyst")
def api_create_saved_query():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    query_text = (data.get("query_text") or "").strip()
    if not name or not query_text:
        return jsonify({"error": "Both a name and a query are required."}), 400
    db.create_saved_query(name, query_text, session.get("username", "unknown"))
    return jsonify({"ok": True})


@bp.route("/api/saved-queries/<int:query_id>/delete", methods=["POST"])
@auth.role_required("Analyst")
def api_delete_saved_query(query_id):
    query = db.get_saved_query(query_id)
    if not query:
        return jsonify({"error": "Query not found."}), 404
    if query["is_builtin"]:
        return jsonify({"error": "Built-in queries can't be deleted (they're the reference library)."}), 400
    db.delete_saved_query(query_id)
    return jsonify({"ok": True})
