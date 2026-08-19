"""
soar.py
-------
SOAR = Security Orchestration, Automation and Response. Where every other
module in this app DETECTS things, this one can ACT on them - block an
attacker's IP in the firewall, disable a compromised account. This is
what separates a SIEM (watches and alerts) from a SOAR (watches, alerts,
and can respond) - a real distinction worth knowing for interviews.

SAFETY DESIGN - read this before changing defaults:
  - Nothing executes automatically out of the box. Every playbook match
    creates a PENDING action that a human has to click Approve on. This
    is deliberate: auto-running firewall/account changes on a machine
    you're actively using for work is a great way to lock yourself out
    of your own PC. AUTO_FIRE_RULES below is empty by default - add a
    rule_name to it only once you're confident in that specific rule's
    accuracy and you understand what executing it does.
  - Even on approval, a few hard guardrails can't be bypassed (see
    _is_safe_to_disable / _is_safe_to_block below) - the point is that a
    typo or a bad detection shouldn't be able to disable your own admin
    account or block your own management IP.
  - All actions - pending, approved, executed, rejected, failed - are
    logged permanently in the actions table for audit purposes. Nothing
    happens silently.

Two actions are implemented, since they're the two that are both genuinely
useful and safe to automate on a single machine:
  - block_ip     : adds a Windows Firewall / iptables DROP rule
  - disable_user : disables a local OS account (net user /active:no)

Run on Windows for real block_ip/disable_user execution. On non-Windows
(this includes wherever you're just reading the code), execution is
simulated and clearly labeled as such - the workflow, approval, and audit
trail all still work for demoing the feature.
"""

import os
import re
import platform
import subprocess
from datetime import datetime

import database as db
import auth

IS_WINDOWS = platform.system() == "Windows"

# ---------------------------------------------------------------------
# Playbooks: which alert patterns suggest which response action.
# Matched against alert["rule_name"] by substring (case-insensitive).
# ---------------------------------------------------------------------
PLAYBOOKS = [
    {"match": "brute force", "action": "block_ip", "reason": "Repeated failed logons from this IP"},
    {"match": "password spray", "action": "block_ip", "reason": "Password spray source IP"},
    {"match": "ssh brute force", "action": "block_ip", "reason": "Repeated failed SSH logons from this IP"},
    {"match": "suspicious sudo command", "action": "disable_user", "reason": "Account ran a known-risky sudo command"},
    {"match": "privilege escalation", "action": "disable_user", "reason": "Account performed unauthorized privilege escalation"},
    {"match": "credential dumping", "action": "disable_user", "reason": "Account associated with credential dumping tool execution"},
]

# Rules allowed to fire WITHOUT approval. Empty by default - see the
# safety note above. Add a rule_name (exact match) here only once you
# trust it, e.g.: AUTO_FIRE_RULES = {"Brute Force - Repeated Failed Logons (Source IP)"}
AUTO_FIRE_RULES = set()

# Accounts that can NEVER be disabled through this feature, no matter
# what triggered the playbook - a bad detection should not be able to
# lock out the machine's own admin or system accounts.
PROTECTED_ACCOUNTS = {"administrator", "admin", "system", "root", "svc_backup"}

# IP ranges that can NEVER be blocked - protects your own local network
# and loopback from a detection accidentally cutting off your own access.
PROTECTED_IP_PREFIXES = ("127.", "10.", "192.168.", "0.0.0.0")


def _now():
    return datetime.utcnow().isoformat()


def _is_safe_to_disable(username: str) -> tuple:
    if not username or not username.strip():
        return False, "No username provided."
    if username.strip().lower() in PROTECTED_ACCOUNTS:
        return False, f"'{username}' is a protected account and cannot be disabled through SOAR."
    return True, ""


def _is_safe_to_block(ip: str) -> tuple:
    if not ip or not ip.strip():
        return False, "No IP address provided."
    if any(ip.startswith(prefix) for prefix in PROTECTED_IP_PREFIXES):
        return False, f"'{ip}' is in a protected range and cannot be blocked through SOAR."
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip.strip()):
        return False, f"'{ip}' doesn't look like a valid IPv4 address."
    return True, ""


# ---------------------------------------------------------------------
# Playbook matching - called after every alert is created
# ---------------------------------------------------------------------

def check_playbooks(alert: dict):
    """Looks at a freshly-created alert, and if it matches a playbook,
    queues a response action (Pending, unless the rule is in
    AUTO_FIRE_RULES). Safe to call on every alert - most won't match
    anything and this is a no-op."""
    rule_name_lower = (alert.get("rule_name") or "").lower()

    for playbook in PLAYBOOKS:
        if playbook["match"] not in rule_name_lower:
            continue

        action_type = playbook["action"]
        target = alert.get("related_ip") if action_type == "block_ip" else alert.get("related_user")
        if not target:
            continue  # nothing to act on

        checker = _is_safe_to_block if action_type == "block_ip" else _is_safe_to_disable
        is_safe, reason = checker(target)

        status = "Pending"
        result_message = playbook["reason"]
        if not is_safe:
            status = "Blocked"
            result_message = f"Guardrail prevented this action: {reason}"

        action_id = db.insert_soar_action({
            "timestamp": _now(),
            "alert_id": alert.get("id"),
            "rule_name": alert.get("rule_name"),
            "action_type": action_type,
            "target": target,
            "status": status,
            "reason": result_message,
            "executed_by": None,
            "executed_at": None,
            "result_message": None,
        })

        if is_safe and alert.get("rule_name") in AUTO_FIRE_RULES:
            execute_action(action_id, executed_by="AUTO_FIRE")

        return action_id  # one action per alert is enough for this scale
    return None


# ---------------------------------------------------------------------
# Execution - the part that actually touches the OS
# ---------------------------------------------------------------------

def _run_command(cmd: list) -> tuple:
    """Runs a real OS command. Returns (success, output). Never raises -
    failures are captured and returned as a result string instead, since
    a failed response action should show up in the audit trail, not
    crash the request handling it."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return True, (result.stdout or "Command completed successfully.").strip()[:500]
        return False, (result.stderr or result.stdout or "Command failed.").strip()[:500]
    except Exception as e:
        return False, f"Failed to run command: {e}"


def _block_ip(ip: str) -> tuple:
    if not IS_WINDOWS:
        return True, f"[SIMULATED - not running on Windows] Would run: netsh advfirewall firewall add rule name=\"SIEM Block {ip}\" dir=in action=block remoteip={ip}"
    rule_name = f"SIEM_Block_{ip.replace('.', '_')}"
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
           f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
    return _run_command(cmd)


def _disable_user(username: str) -> tuple:
    if not IS_WINDOWS:
        return True, f"[SIMULATED - not running on Windows] Would run: net user {username} /active:no"
    cmd = ["net", "user", username, "/active:no"]
    return _run_command(cmd)


def execute_action(action_id: int, executed_by: str):
    """Actually performs the action. Called when an analyst clicks Approve,
    or by check_playbooks() itself for AUTO_FIRE_RULES."""
    action = db.get_soar_action(action_id)
    if not action:
        return {"ok": False, "error": "Action not found."}
    if action["status"] not in ("Pending",):
        return {"ok": False, "error": f"Action already {action['status']}, cannot execute again."}

    if action["action_type"] == "block_ip":
        success, output = _block_ip(action["target"])
    elif action["action_type"] == "disable_user":
        success, output = _disable_user(action["target"])
    else:
        success, output = False, f"Unknown action type: {action['action_type']}"

    db.update_soar_action(action_id, {
        "status": "Executed" if success else "Failed",
        "executed_by": executed_by,
        "executed_at": _now(),
        "result_message": output,
    })
    return {"ok": success, "output": output}


def reject_action(action_id: int, rejected_by: str):
    action = db.get_soar_action(action_id)
    if not action:
        return {"ok": False, "error": "Action not found."}
    if action["status"] != "Pending":
        return {"ok": False, "error": f"Action already {action['status']}, cannot reject."}
    db.update_soar_action(action_id, {
        "status": "Rejected", "executed_by": rejected_by,
        "executed_at": _now(), "result_message": "Rejected by analyst.",
    })
    return {"ok": True}


# ---------------------------------------------------------------------
# Self-contained Flask Blueprint - same pattern as ai_summary.py and
# sigma_rules.py. app.py only needs: import soar; app.register_blueprint(soar.bp)
# ---------------------------------------------------------------------
from flask import Blueprint, jsonify, render_template, session

bp = Blueprint("soar", __name__)


@bp.route("/soar")
@auth.login_required
def soar_page():
    return render_template("soar.html")


@bp.route("/api/soar/actions")
@auth.login_required
def api_list_actions():
    return jsonify(db.list_soar_actions(limit=100))


@bp.route("/api/soar/actions/<int:action_id>/approve", methods=["POST"])
@auth.role_required("Analyst")
def api_approve_action(action_id):
    result = execute_action(action_id, executed_by=session.get("username", "unknown"))
    return jsonify(result)


@bp.route("/api/soar/actions/<int:action_id>/reject", methods=["POST"])
@auth.role_required("Analyst")
def api_reject_action(action_id):
    result = reject_action(action_id, rejected_by=session.get("username", "unknown"))
    return jsonify(result)


@bp.route("/api/soar/playbooks")
@auth.login_required
def api_list_playbooks():
    return jsonify({
        "playbooks": PLAYBOOKS,
        "auto_fire_rules": list(AUTO_FIRE_RULES),
        "platform": "Windows" if IS_WINDOWS else "Non-Windows (simulated execution)",
    })
