"""
app.py
------
The web server. Serves the SOC dashboard and several other pages (threat
hunting, MITRE heatmap, asset inventory, attack timelines, IOC watchlist,
user management), plus the JSON API endpoints their JavaScript calls.

Also serves on-demand PDF reports, runs a background scheduler that
auto-generates daily/weekly reports, starts the syslog listener, and
(if configured) emails on Critical alerts.

Run: python app.py
Then open: http://127.0.0.1:5000
First login: username "admin", password "admin123" - CHANGE IT immediately
via User Management (top nav, Admin role only).
"""

import os
import csv
import io
import secrets
import threading
import time as time_module
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, jsonify, send_file, abort, request, Response,
    session, redirect, url_for, flash,
)
from werkzeug.security import generate_password_hash

import database as db
import collector
import rules
import report
import sigma_rules
import soar
import ai_summary
import ingest
import query_lang
import rule_management
import cases
import saved_queries
import correlation
import auth
import syslog_listener

app = Flask(__name__)
app.register_blueprint(ai_summary.bp)
app.register_blueprint(sigma_rules.bp)
app.register_blueprint(soar.bp)
app.register_blueprint(rule_management.bp)
app.register_blueprint(cases.bp)
app.register_blueprint(saved_queries.bp)
app.register_blueprint(correlation.bp)
app.register_blueprint(ingest.bp)

# Persist the session-signing secret across restarts (in a gitignored-style
# local file) so people don't get logged out every time the app restarts.
_SECRET_PATH = os.path.join(os.path.dirname(__file__), "instance_secret.key")
if os.path.exists(_SECRET_PATH):
    app.secret_key = open(_SECRET_PATH, "r").read().strip()
else:
    key = secrets.token_hex(32)
    with open(_SECRET_PATH, "w") as f:
        f.write(key)
    app.secret_key = key


# ---------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or ""

        # Locked out - reject before even checking the password. Still
        # record the attempt and feed it into the SIEM's own detection
        # pipeline, since someone hammering a locked account is exactly
        # the kind of thing worth an analyst seeing.
        if username and db.is_username_locked(username):
            db.record_login_attempt(username, client_ip, False)
            collector.save_event(
                source="SIEM", event_id=rules.EVENT_SIEM_LOGIN_FAILED,
                event_type="SIEM_LoginAttemptWhileLocked", user=username, source_ip=client_ip,
                host="mini-siem",
                message=f"Login attempt for '{username}' rejected - account temporarily "
                        f"locked after repeated recent failures.",
            )
            flash(f"Too many failed attempts for '{username}'. Try again in a few minutes.", "error")
            return render_template("login.html")

        user = auth.verify_login(username, password)
        if user:
            db.record_login_attempt(username, client_ip, True)
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            next_url = request.args.get("next") or url_for("dashboard")
            return redirect(next_url)

        # Failed login - record it AND feed it into the SIEM's own detection
        # pipeline (same rules.evaluate() every other log goes through), so
        # rule_siem_login_brute_force can catch repeated attempts and it
        # shows up in the dashboard/alerts like any other threat.
        if username:
            db.record_login_attempt(username, client_ip, False)
            collector.save_event(
                source="SIEM", event_id=rules.EVENT_SIEM_LOGIN_FAILED, event_type="SIEM_FailedLogin",
                user=username, source_ip=client_ip, host="mini-siem",
                message=f"Failed login attempt for '{username}' against the SIEM's own web login.",
            )
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.context_processor
def inject_user():
    """Makes the logged-in user available in every template automatically."""
    return {"current_username": session.get("username"), "current_role": session.get("role")}


# ---------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------

@app.route("/")
@auth.login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/hunting")
@auth.login_required
def hunting():
    return render_template("hunting.html")


@app.route("/heatmap")
@auth.login_required
def heatmap():
    return render_template("heatmap.html")


@app.route("/assets")
@auth.login_required
def assets_page():
    return render_template("assets.html")


@app.route("/timeline")
@auth.login_required
def timeline_page():
    return render_template("timeline.html")


@app.route("/iocs")
@auth.login_required
def iocs_page():
    return render_template("iocs.html")


@app.route("/risk")
@auth.login_required
def risk_page():
    return render_template("risk.html")


@app.route("/users")
@auth.role_required("Admin")
def users_page():
    return render_template("users.html", users=db.list_users())


# ---------------------------------------------------------------------
# User management API (Admin only)
# ---------------------------------------------------------------------

@app.route("/users/create", methods=["POST"])
@auth.role_required("Admin")
def api_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "Viewer")
    if role not in ("Viewer", "Analyst", "Admin"):
        role = "Viewer"
    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("users_page"))
    if db.get_user_by_username(username):
        flash(f"User '{username}' already exists.", "error")
        return redirect(url_for("users_page"))
    db.create_user(username, generate_password_hash(password), role)
    flash(f"User '{username}' created.", "ok")
    return redirect(url_for("users_page"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@auth.role_required("Admin")
def api_delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("You can't delete your own account while logged in as it.", "error")
        return redirect(url_for("users_page"))
    db.delete_user(user_id)
    flash("User deleted.", "ok")
    return redirect(url_for("users_page"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@auth.role_required("Admin")
def api_reset_user_password(user_id):
    """Admin can set a new password for ANY user, including their own -
    this is the actual way to change the default admin/admin123 login,
    since an admin can't delete their own account to recreate it."""
    new_password = request.form.get("new_password", "")
    if len(new_password) < 4:
        flash("Password must be at least 4 characters.", "error")
        return redirect(url_for("users_page"))
    db.update_user_password(user_id, generate_password_hash(new_password))
    flash("Password updated.", "ok")
    return redirect(url_for("users_page"))


@app.route("/account", methods=["GET", "POST"])
@auth.login_required
def account_page():
    """Self-service password change for whoever is logged in, regardless
    of role - doesn't require Admin access like the /users page does."""
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user = db.get_user_by_id(session["user_id"])
        if not auth.verify_login(user["username"], current_password):
            flash("Current password is incorrect.", "error")
        elif len(new_password) < 4:
            flash("New password must be at least 4 characters.", "error")
        elif new_password != confirm_password:
            flash("New password and confirmation don't match.", "error")
        else:
            db.update_user_password(user["id"], generate_password_hash(new_password))
            flash("Password changed successfully.", "ok")
    return render_template("account.html")


# ---------------------------------------------------------------------
# Core stats / logs / alerts API
# ---------------------------------------------------------------------

@app.route("/api/stats")
@auth.login_required
def api_stats():
    return jsonify(db.get_stats())


def _filters_from_request():
    """Shared query-param parsing for both /api/logs and /api/alerts."""
    args = request.args
    return {
        "search": args.get("search") or None,
        "date_from": args.get("date_from") or None,
        "date_to": args.get("date_to") or None,
        "limit": min(int(args.get("limit", 25)), 500),   # cap so a bad request can't pull the whole DB
        "offset": int(args.get("offset", 0)),
    }


@app.route("/api/logs")
@auth.login_required
def api_logs():
    f = _filters_from_request()
    try:
        rows, total = db.search_logs(
            source=request.args.get("source") or None,
            event_type=request.args.get("event_type") or None,
            host=request.args.get("host") or None,
            user=request.args.get("user") or None,
            source_ip=request.args.get("source_ip") or None,
            search=f["search"], date_from=f["date_from"], date_to=f["date_to"],
            query=request.args.get("q") or None,
            limit=f["limit"], offset=f["offset"],
        )
    except query_lang.QueryError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"logs": rows, "total": total})


@app.route("/api/alerts")
@auth.login_required
def api_alerts():
    f = _filters_from_request()
    try:
        rows, total = db.search_alerts(
            severity=request.args.get("severity") or None,
            status=request.args.get("status") or None,
            mitre_id=request.args.get("mitre_id") or None,
            related_user=request.args.get("related_user") or None,
            related_ip=request.args.get("related_ip") or None,
            search=f["search"], date_from=f["date_from"], date_to=f["date_to"],
            query=request.args.get("q") or None,
            limit=f["limit"], offset=f["offset"],
        )
    except query_lang.QueryError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"alerts": rows, "total": total})


@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
@auth.role_required("Analyst")
def api_update_alert_status(alert_id):
    """Triage workflow: mark an alert New / Acknowledged / Resolved.
    Requires Analyst or Admin - Viewers can look but not touch."""
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in ("New", "Acknowledged", "Resolved"):
        return jsonify({"error": "status must be New, Acknowledged, or Resolved"}), 400
    db.update_alert_status(alert_id, status)
    return jsonify({"ok": True, "id": alert_id, "status": status})


@app.route("/api/alerts/export.csv")
@auth.login_required
def api_export_alerts_csv():
    """Exports alerts matching the current filters as a CSV download -
    same filter params as /api/alerts, but returns everything that
    matches (no pagination) since it's meant to leave the app."""
    rows, _ = db.search_alerts(
        severity=request.args.get("severity") or None,
        status=request.args.get("status") or None,
        mitre_id=request.args.get("mitre_id") or None,
        related_user=request.args.get("related_user") or None,
        related_ip=request.args.get("related_ip") or None,
        search=request.args.get("search") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
        limit=10000, offset=0,
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "severity", "status", "rule_name", "description",
                      "related_user", "related_ip", "mitre_id", "mitre_technique"])
    for a in rows:
        writer.writerow([a["timestamp"], a["severity"], a["status"], a["rule_name"],
                          a["description"], a["related_user"], a["related_ip"],
                          a["mitre_id"], a["mitre_technique"]])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
    )


@app.route("/api/logs/export.csv")
@auth.login_required
def api_export_logs_csv():
    rows, _ = db.search_logs(
        source=request.args.get("source") or None,
        event_type=request.args.get("event_type") or None,
        host=request.args.get("host") or None,
        user=request.args.get("user") or None,
        source_ip=request.args.get("source_ip") or None,
        search=request.args.get("search") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
        limit=10000, offset=0,
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "source", "event_id", "event_type", "user", "source_ip", "host", "message"])
    for l in rows:
        writer.writerow([l["timestamp"], l["source"], l["event_id"], l["event_type"],
                          l["user"], l["source_ip"], l["host"], l["message"]])
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=logs_export.csv"},
    )


@app.route("/api/report/<period>")
@auth.login_required
def api_report(period):
    """Generates a report on demand and sends it as a download.
    /api/report/daily or /api/report/weekly"""
    if period not in ("daily", "weekly"):
        abort(404)
    filepath = report.build_report(period)
    return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))


@app.route("/api/ai-summary")
@auth.role_required("Analyst")
def api_ai_summary():
    """On-demand AI incident summary over a time window (default: last 24h).
    Gated at Analyst role or above since each call costs real API usage -
    Viewers can see summaries already generated but not spend the quota
    generating new ones. Requires ANTHROPIC_API_KEY to be set - see
    ai_summary.py for setup."""
    hours = int(request.args.get("hours", 24))
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
    alerts, _ = db.search_alerts(date_from=since, limit=200)
    result = ai_summary.summarize(alerts)
    return jsonify(result)


# ---------------------------------------------------------------------
# IOC watchlist API
# ---------------------------------------------------------------------

@app.route("/api/iocs")
@auth.login_required
def api_list_iocs():
    return jsonify(db.list_iocs())


@app.route("/api/iocs", methods=["POST"])
@auth.role_required("Analyst")
def api_add_ioc():
    data = request.get_json(silent=True) or {}
    indicator = (data.get("indicator") or "").strip()
    ioc_type = data.get("ioc_type") or "ip"
    description = data.get("description") or ""
    if not indicator:
        return jsonify({"error": "indicator is required"}), 400
    db.add_ioc(indicator, ioc_type, description, session.get("username"))
    return jsonify({"ok": True})


@app.route("/api/iocs/<int:ioc_id>/delete", methods=["POST"])
@auth.role_required("Analyst")
def api_delete_ioc(ioc_id):
    db.delete_ioc(ioc_id)
    return jsonify({"ok": True})


@app.route("/api/iocs/search")
@auth.login_required
def api_search_ioc():
    indicator = request.args.get("q", "").strip()
    if not indicator:
        return jsonify({"results": []})
    return jsonify({"results": db.search_iocs_in_logs(indicator)})


# ---------------------------------------------------------------------
# Asset inventory API
# ---------------------------------------------------------------------

@app.route("/api/assets")
@auth.login_required
def api_assets():
    return jsonify(db.get_assets_summary())


@app.route("/api/assets/<hostname>", methods=["POST"])
@auth.role_required("Analyst")
def api_update_asset(hostname):
    data = request.get_json(silent=True) or {}
    db.upsert_asset_meta(
        hostname,
        data.get("criticality", "Medium"),
        data.get("owner", ""),
        data.get("notes", ""),
    )
    return jsonify({"ok": True})


# ---------------------------------------------------------------------
# Risk scoring API
# ---------------------------------------------------------------------

@app.route("/api/risk")
@auth.login_required
def api_risk():
    days = int(request.args.get("days", 7))
    return jsonify(db.get_risk_scores(days=days))


# ---------------------------------------------------------------------
# Attack timeline API
# ---------------------------------------------------------------------

@app.route("/api/timeline")
@auth.login_required
def api_timeline():
    entity_type = request.args.get("type", "user")
    entity_value = request.args.get("value", "")
    if entity_type not in ("user", "host") or not entity_value:
        return jsonify({"error": "type must be 'user' or 'host', and value is required"}), 400
    return jsonify(db.get_timeline(entity_type, entity_value))


# ---------------------------------------------------------------------
# MITRE ATT&CK heatmap API
# ---------------------------------------------------------------------

@app.route("/api/mitre-matrix")
@auth.login_required
def api_mitre_matrix():
    return jsonify(db.get_mitre_matrix())


# ---------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------

def start_background_collector(mode="demo"):
    """Runs the log collector in a background thread so the web server
    and the collection process run at the same time."""
    if mode == "demo":
        target = collector.run_demo_generator
    else:
        target = collector.collect_windows_events
    thread = threading.Thread(target=target, daemon=True)
    thread.start()


def start_report_scheduler():
    """Checks once a minute whether it's time to auto-generate a report.
    Daily report: once every day at 00:05. Weekly report: Mondays at 00:10.
    Simple and dependency-free - good enough for a single-instance app like this."""
    def loop():
        last_daily_date = None
        last_weekly_date = None
        while True:
            now = datetime.now()
            today = now.date()
            if now.hour == 0 and now.minute == 5 and last_daily_date != today:
                try:
                    path = report.build_report("daily")
                    print(f"[SCHEDULER] Auto-generated daily report: {path}")
                except Exception as e:
                    print(f"[SCHEDULER] Daily report failed: {e}")
                last_daily_date = today
            if now.weekday() == 0 and now.hour == 0 and now.minute == 10 and last_weekly_date != today:
                try:
                    path = report.build_report("weekly")
                    print(f"[SCHEDULER] Auto-generated weekly report: {path}")
                except Exception as e:
                    print(f"[SCHEDULER] Weekly report failed: {e}")
                last_weekly_date = today
            time_module.sleep(30)

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()


if __name__ == "__main__":
    import sys

    db.init_db()
    rules.register_all_rules()
    saved_queries.register_builtin_queries()
    auth.ensure_default_admin()

    # Usage:
    #   python app.py            -> demo mode (simulated logs, works anywhere)
    #   python app.py windows    -> real Windows Event Viewer collection
    mode = "windows" if len(sys.argv) > 1 and sys.argv[1] == "windows" else "demo"
    start_background_collector(mode)
    start_report_scheduler()
    syslog_listener.start_syslog_listener_thread()

    print(f"Mini SIEM running in '{mode}' mode.")
    print("Dashboard: http://127.0.0.1:5000")
    print("On-demand reports: http://127.0.0.1:5000/api/report/daily  or  /weekly")
    # host="0.0.0.0" is required for VMs/other machines to reach this at
    # all - the default (127.0.0.1) only accepts connections from this
    # same machine, which silently blocks every forwarder and remote
    # dashboard access regardless of firewall rules.
    app.run(debug=False, host="0.0.0.0", port=5000)
