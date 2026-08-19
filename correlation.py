"""
correlation.py
---------------
Attack chain correlation - the piece that turns "5 separate alerts" into
"this looks like one coordinated attack." A real intrusion rarely trips
just one rule: recon, then brute force, then privilege escalation, then
persistence. Right now each of those shows up as an independent alert
with no link between them. This module watches for that pattern and
clusters them into one "chain" automatically.

THE RULE: when an alert fires for a user or IP, and that same entity has
3+ DISTINCT rule types firing within the last 60 minutes, that's treated
as one attack chain rather than isolated noise. Distinct rule types
matter more than raw alert count - five "Failed Logon" hits are still
just one brute-force attempt; one brute force + one privilege escalation
+ one persistence alert is a very different, much more serious story
even though it's also three alerts.

This is deliberately a HEURISTIC, not a certainty. A chain is a strong
hint worth an analyst's attention, not an automatic verdict - which is
why chains queue for review rather than auto-creating a case. That
mirrors how the SOAR playbooks in this app work too: flag and queue,
require a human before anything more happens.
"""

from datetime import datetime, timedelta

import database as db


def check_correlation(alert: dict):
    """Called right after every alert is created. Looks at whether this
    alert plus recent alerts for the same entity add up to a chain, and
    if so, creates or extends one. Returns the chain_id if a chain was
    touched, None otherwise (the common case - most alerts are isolated)."""
    if alert.get("related_user"):
        entity_type, entity_value = "user", alert["related_user"]
    elif alert.get("related_ip"):
        entity_type, entity_value = "ip", alert["related_ip"]
    else:
        return None  # nothing to correlate against

    since_dt = datetime.utcnow() - timedelta(minutes=db.CHAIN_CORRELATION_WINDOW_MINUTES)
    since = since_dt.isoformat()

    recent_alerts = db.get_alerts_for_entity(entity_type, entity_value, since)
    # recent_alerts already includes this alert if it was inserted before
    # this call, but don't rely on that - build the distinct-rule set
    # explicitly from recent_alerts plus this one, so it's correct either way.
    distinct_rules = {a["rule_name"] for a in recent_alerts}
    distinct_rules.add(alert["rule_name"])

    if len(distinct_rules) < db.CHAIN_CORRELATION_THRESHOLD:
        return None  # not enough distinct attack stages yet to call this a chain

    chain = db.find_active_chain(entity_type, entity_value, since)
    if not chain:
        first_seen = min([a["timestamp"] for a in recent_alerts] + [alert["timestamp"]])
        chain_id = db.create_chain(entity_type, entity_value, first_seen)
        # Backfill: pull in every alert that's part of the pattern, not
        # just the one that happened to cross the threshold.
        for a in recent_alerts:
            db.add_alert_to_chain(chain_id, a["id"], a["timestamp"])
    else:
        chain_id = chain["id"]

    db.add_alert_to_chain(chain_id, alert["id"], alert["timestamp"])
    return chain_id


# ---------------------------------------------------------------------
# Self-contained Flask Blueprint - same pattern as soar.py/cases.py.
# app.py only needs: import correlation; app.register_blueprint(correlation.bp)
# ---------------------------------------------------------------------
from flask import Blueprint, jsonify, render_template, session, request

import auth

bp = Blueprint("correlation", __name__)


def _enrich_chain(chain: dict) -> dict:
    """Adds the actual alert list and a tactic-ordered summary to a raw
    chain row, for the API/detail view."""
    alerts = db.get_chain_alerts(chain["id"])
    for a in alerts:
        a["tactic"] = db.MITRE_TACTIC_MAP.get(a.get("mitre_id"), "Other")
    chain = dict(chain)
    chain["alerts"] = alerts
    chain["distinct_rules"] = sorted({a["rule_name"] for a in alerts})
    chain["distinct_tactics"] = sorted({a["tactic"] for a in alerts})
    return chain


@bp.route("/chains")
@auth.login_required
def chains_page():
    return render_template("chains.html")


@bp.route("/api/chains")
@auth.login_required
def api_list_chains():
    status = request.args.get("status") or None
    chains = db.list_chains(status=status)
    return jsonify([_enrich_chain(c) for c in chains])


@bp.route("/api/chains/<int:chain_id>")
@auth.login_required
def api_get_chain(chain_id):
    chain = db.get_chain(chain_id)
    if not chain:
        return jsonify({"error": "Chain not found."}), 404
    return jsonify(_enrich_chain(chain))


@bp.route("/api/chains/<int:chain_id>/dismiss", methods=["POST"])
@auth.role_required("Analyst")
def api_dismiss_chain(chain_id):
    chain = db.get_chain(chain_id)
    if not chain:
        return jsonify({"error": "Chain not found."}), 404
    db.update_chain_status(chain_id, "Dismissed")
    return jsonify({"ok": True})


@bp.route("/api/chains/<int:chain_id>/create-case", methods=["POST"])
@auth.role_required("Analyst")
def api_create_case_from_chain(chain_id):
    chain = db.get_chain(chain_id)
    if not chain:
        return jsonify({"error": "Chain not found."}), 404
    if chain.get("case_number"):
        return jsonify({"error": f"A case already exists for this chain: {chain['case_number']}"}), 400

    alerts = db.get_chain_alerts(chain_id)
    entity_label = f"{chain['entity_type']}={chain['entity_value']}"
    title = f"Correlated attack chain - {entity_label} ({len(alerts)} alerts)"
    rule_names = ", ".join(sorted({a["rule_name"] for a in alerts}))
    description = (
        f"Auto-correlated from {len(alerts)} alerts spanning {chain['first_seen']} to {chain['last_seen']}. "
        f"Rules involved: {rule_names}."
    )
    # Highest severity among the chain's alerts drives the case priority -
    # a chain containing any Critical alert deserves Critical priority
    # regardless of what the other alerts in it were.
    severities = [a["severity"] for a in alerts]
    priority = "Critical" if "Critical" in severities else "High" if "High" in severities else "Medium"

    case_id, case_number = db.create_case(
        title=title, description=description, priority=priority,
        assigned_to=None, created_by=session.get("username", "unknown"),
    )
    for a in alerts:
        db.add_case_evidence(
            case_id, "alert", a["id"],
            f"Alert #{a['id']}: {a['rule_name']} ({a['severity']}, {a['timestamp']}, "
            f"user={a['related_user'] or '-'}, ip={a['related_ip'] or '-'}, mitre={a['mitre_id'] or '-'})",
            session.get("username", "unknown"),
        )
    db.add_case_note(
        case_id,
        f"Case auto-created from attack chain #{chain_id} ({entity_label}). "
        f"{len(alerts)} alerts were automatically attached as evidence - review each one.",
        "system",
    )
    db.update_chain_status(chain_id, "Reviewed", case_number=case_number)

    return jsonify({"ok": True, "case_number": case_number})
