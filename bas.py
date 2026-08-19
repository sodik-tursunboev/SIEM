"""
bas.py
------
Sentinel BAS - Detection Validation Engine.

The runner script (bas_runner.ps1, deployed to the Windows VM with Atomic
Red Team installed) calls the two endpoints below around each atomic
test it executes: /api/bas/test-run/start right before, and
/<id>/end right after. Once a test is marked ended, this module scores
it against the alerts table to determine whether it was Detected,
Delayed, or Missed - see database.py's score_bas_test_run for the
actual matching logic and reasoning.

This is intentionally a thin Blueprint - almost all the real logic
lives in database.py so it's testable without spinning up Flask at all,
which is how it actually got tested during development.
"""

from flask import Blueprint, jsonify, render_template, request

import auth
import database as db
import ingest

bp = Blueprint("bas", __name__)


def _check_ingest_key(req) -> bool:
    """Same shared secret the log forwarder uses - the BAS runner script
    is calling in from the same untrusted remote VM, so it needs the
    same authentication, not session-cookie auth."""
    return req.headers.get("X-SIEM-Key") == ingest.INGEST_KEY


@bp.route("/bas")
@auth.login_required
def bas_page():
    return render_template("bas.html")


@bp.route("/api/bas/test-run/start", methods=["POST"])
def api_start_test_run():
    """Called by the runner script right before Invoke-AtomicTest runs.
    Uses the same shared ingest key as the log forwarder - this endpoint
    is being called from the same untrusted-network remote machine, so
    it needs the same authentication, not session-cookie auth."""
    if not _check_ingest_key(request):
        return jsonify({"error": "Invalid or missing X-SIEM-Key header."}), 401

    data = request.get_json(silent=True) or {}
    required = ["technique_id", "atomic_test_name", "host"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required field(s): {', '.join(missing)}"}), 400

    run_id = db.create_bas_test_run(
        technique_id=data["technique_id"],
        technique_name=data.get("technique_name", ""),
        atomic_test_name=data["atomic_test_name"],
        atomic_test_guid=data.get("atomic_test_guid", ""),
        host=data["host"],
    )
    return jsonify({"ok": True, "run_id": run_id})


@bp.route("/api/bas/test-run/<int:run_id>/end", methods=["POST"])
def api_end_test_run(run_id):
    if not _check_ingest_key(request):
        return jsonify({"error": "Invalid or missing X-SIEM-Key header."}), 401

    db.end_bas_test_run(run_id)
    # First scoring pass happens immediately - catches fast detections
    # right away. Delayed detections and finalized misses need the
    # grace window to actually pass first; that's what /rescore is for.
    result = db.score_bas_test_run(run_id)
    return jsonify({"ok": True, "run": result})


@bp.route("/api/bas/runs")
@auth.login_required
def api_list_runs():
    status = request.args.get("status") or None
    return jsonify(db.list_bas_test_runs(status=status))


@bp.route("/api/bas/coverage")
@auth.login_required
def api_coverage():
    return jsonify(db.get_bas_coverage_summary())


@bp.route("/api/bas/rescore", methods=["POST"])
@auth.role_required("Analyst")
def api_rescore():
    """Manual trigger to re-check every still-Pending run - catches
    delayed detections that have arrived since the run ended, and
    finalizes genuine misses once their grace window has passed."""
    results = db.rescore_pending_bas_runs()
    return jsonify({"ok": True, "rescored": len(results)})
