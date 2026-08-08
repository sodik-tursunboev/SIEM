"""
cases.py
--------
Case Management - the piece that turns "here's a pile of alerts" into an
actual SOC workflow. An analyst opens a case (INC-001, INC-002...),
attaches evidence (existing alerts/logs or free-text notes), logs
investigation notes as they work it, and records a resolution when done.

Cases are independent of alerts - an alert doesn't have to have a case,
and a case can reference multiple alerts as evidence. This mirrors how
real case management works (a phishing campaign might span 20 alerts,
one case ties them together).

RBAC: everyone logged in can view cases (read-only for Viewers).
Creating cases, changing status/priority/assignment, and adding
notes/evidence requires Analyst role or above - same tier as alert
triage and SOAR approval elsewhere in this app.
"""

from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, session

import database as db
import auth

bp = Blueprint("cases", __name__)

VALID_STATUSES = ("Open", "In Progress", "Resolved", "Closed")
VALID_PRIORITIES = ("Low", "Medium", "High", "Critical")
VALID_EVIDENCE_TYPES = ("alert", "log", "note")


@bp.route("/cases")
@auth.login_required
def cases_page():
    return render_template("cases.html")


@bp.route("/cases/<case_number>")
@auth.login_required
def case_detail_page(case_number):
    return render_template("case_detail.html", case_number=case_number)


@bp.route("/api/cases")
@auth.login_required
def api_list_cases():
    rows = db.list_cases(
        status=request.args.get("status") or None,
        priority=request.args.get("priority") or None,
        assigned_to=request.args.get("assigned_to") or None,
    )
    return jsonify(rows)


@bp.route("/api/cases", methods=["POST"])
@auth.role_required("Analyst")
def api_create_case():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Title is required."}), 400
    priority = data.get("priority") or "Medium"
    if priority not in VALID_PRIORITIES:
        return jsonify({"error": f"Priority must be one of: {', '.join(VALID_PRIORITIES)}"}), 400

    case_id, case_number = db.create_case(
        title=title,
        description=(data.get("description") or "").strip(),
        priority=priority,
        assigned_to=data.get("assigned_to") or None,
        created_by=session.get("username", "unknown"),
    )
    return jsonify({"ok": True, "case_id": case_id, "case_number": case_number})


@bp.route("/api/cases/<case_number>")
@auth.login_required
def api_get_case(case_number):
    case = db.get_case(case_number)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    return jsonify({
        "case": case,
        "notes": db.list_case_notes(case["id"]),
        "evidence": db.list_case_evidence(case["id"]),
    })


@bp.route("/api/cases/<case_number>/update", methods=["POST"])
@auth.role_required("Analyst")
def api_update_case(case_number):
    case = db.get_case(case_number)
    if not case:
        return jsonify({"error": "Case not found."}), 404

    data = request.get_json(silent=True) or {}
    fields = {}

    if "status" in data:
        if data["status"] not in VALID_STATUSES:
            return jsonify({"error": f"Status must be one of: {', '.join(VALID_STATUSES)}"}), 400
        fields["status"] = data["status"]
    if "priority" in data:
        if data["priority"] not in VALID_PRIORITIES:
            return jsonify({"error": f"Priority must be one of: {', '.join(VALID_PRIORITIES)}"}), 400
        fields["priority"] = data["priority"]
    if "assigned_to" in data:
        fields["assigned_to"] = data["assigned_to"] or None
    if "resolution" in data:
        fields["resolution"] = data["resolution"]

    if not fields:
        return jsonify({"error": "No valid fields to update."}), 400

    db.update_case(case["id"], fields)
    return jsonify({"ok": True})


@bp.route("/api/cases/<case_number>/notes", methods=["POST"])
@auth.role_required("Analyst")
def api_add_note(case_number):
    case = db.get_case(case_number)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    note_text = ((request.get_json(silent=True) or {}).get("note_text") or "").strip()
    if not note_text:
        return jsonify({"error": "Note text is required."}), 400
    db.add_case_note(case["id"], note_text, session.get("username", "unknown"))
    return jsonify({"ok": True})


@bp.route("/api/cases/<case_number>/evidence", methods=["POST"])
@auth.role_required("Analyst")
def api_add_evidence(case_number):
    case = db.get_case(case_number)
    if not case:
        return jsonify({"error": "Case not found."}), 404

    data = request.get_json(silent=True) or {}
    evidence_type = data.get("evidence_type") or "note"
    if evidence_type not in VALID_EVIDENCE_TYPES:
        return jsonify({"error": f"evidence_type must be one of: {', '.join(VALID_EVIDENCE_TYPES)}"}), 400
    description = (data.get("description") or "").strip()
    if not description:
        return jsonify({"error": "Evidence description is required."}), 400

    reference_id = data.get("reference_id") or None
    # If attaching an existing alert as evidence, pull its details into the
    # description automatically so the case is self-contained and readable
    # without needing to cross-reference the alerts table separately.
    if evidence_type == "alert" and reference_id:
        alerts, _ = db.search_alerts(limit=1000)
        alert = next((a for a in alerts if a["id"] == int(reference_id)), None)
        if alert:
            description = (
                f"{description} — Alert #{alert['id']}: {alert['rule_name']} "
                f"({alert['severity']}, {alert['timestamp']}, user={alert['related_user'] or '-'}, "
                f"ip={alert['related_ip'] or '-'})"
            )

    db.add_case_evidence(case["id"], evidence_type, reference_id, description, session.get("username", "unknown"))
    return jsonify({"ok": True})


@bp.route("/api/cases/assignable-users")
@auth.login_required
def api_assignable_users():
    """Just usernames, for populating the 'Assigned to' dropdown - not the
    full user objects (no need to expose roles/created dates here)."""
    users = db.list_users()
    return jsonify([u["username"] for u in users])
