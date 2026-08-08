"""
rule_management.py
-------------------
The "Detection Rules" page - a catalog view of every built-in detection
rule (Windows, Linux, anomaly), showing exactly what a real enterprise
SIEM's rule management screen shows: name, severity, MITRE mapping,
enabled/disabled, last triggered, and hit count.

Toggling a rule off here actually disables it - rules.evaluate() checks
this registry before running each rule, so a disabled rule doesn't just
get hidden, it stops firing entirely.

Sigma rules aren't included here - they already have their own
management page (Sigma Rules), since they're user-added/removed files
rather than a fixed catalog.
"""

from flask import Blueprint, jsonify, render_template

import database as db
import auth

bp = Blueprint("rule_management", __name__)


@bp.route("/rules")
@auth.login_required
def rules_page():
    return render_template("rules.html")


@bp.route("/api/rules")
@auth.login_required
def api_list_rules():
    return jsonify(db.list_rule_registry())


@bp.route("/api/rules/<rule_key>/toggle", methods=["POST"])
@auth.role_required("Analyst")
def api_toggle_rule(rule_key):
    rows = db.list_rule_registry()
    match = next((r for r in rows if r["rule_key"] == rule_key), None)
    if not match:
        return jsonify({"error": f"Unknown rule: {rule_key}"}), 404
    new_state = not bool(match["enabled"])
    db.set_rule_enabled(rule_key, new_state)
    return jsonify({"ok": True, "rule_key": rule_key, "enabled": new_state})
