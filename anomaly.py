"""
anomaly.py
----------
Lightweight behavioral anomaly detection - no ML libraries required.

Instead of matching a fixed pattern (like the rules in rules.py do), these
functions build a simple baseline of "normal" behavior per user from their
own history, then flag events that fall outside that baseline. This is the
same basic idea real UEBA (User and Entity Behavior Analytics) features use
- just without the statistics/ML machinery a production system layers on
top. It's an honest, explainable first version you can point to in an
interview and say exactly how it works.

Both rules require a minimum amount of history before they'll fire, so a
brand-new user/account doesn't get flagged just for not having a baseline
yet - that would just be noise, not a real anomaly.
"""

from datetime import datetime
import database as db

MIN_HISTORY_FOR_BASELINE = 8
EVENT_SUCCESS_LOGON = 4624


def rule_unusual_login_hour(new_log: dict):
    """Flags a successful logon at an hour-of-day this user has never
    logged in during before, once we have enough history to trust the
    baseline. MITRE: T1078 - Valid Accounts (a legitimate account behaving
    in an atypical way is a classic sign of a compromised credential)."""
    if new_log["event_id"] != EVENT_SUCCESS_LOGON or not new_log.get("user"):
        return None

    history = db.get_user_logon_history(
        new_log["user"], event_id=EVENT_SUCCESS_LOGON, before_log_id=new_log["id"]
    )
    if len(history) < MIN_HISTORY_FOR_BASELINE:
        return None  # not enough baseline yet to say what's "normal" for this user

    known_hours = {datetime.fromisoformat(h["timestamp"]).hour for h in history}
    current_hour = datetime.fromisoformat(new_log["timestamp"]).hour

    if current_hour not in known_hours:
        return {
            "rule_name": "Anomaly - Unusual Login Hour",
            "severity": "Medium",
            "description": (
                f"User '{new_log['user']}' logged on at {current_hour:02d}:00, "
                f"a time not seen across their last {len(history)} logons "
                f"(usual hours: {sorted(known_hours)})."
            ),
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1078",
            "mitre_technique": "Valid Accounts",
        }
    return None


def rule_new_source_ip(new_log: dict):
    """Flags a successful logon from a source IP this user has never used
    before, once there's enough history to establish a baseline. This is
    the 'lite' version of impossible-travel / new-location detection real
    SIEMs run - catches credential reuse from an unexpected place."""
    if new_log["event_id"] != EVENT_SUCCESS_LOGON or not new_log.get("user") or not new_log.get("source_ip"):
        return None

    history = db.get_user_logon_history(
        new_log["user"], event_id=EVENT_SUCCESS_LOGON, before_log_id=new_log["id"]
    )
    if len(history) < MIN_HISTORY_FOR_BASELINE:
        return None

    known_ips = {h["source_ip"] for h in history if h["source_ip"]}
    if known_ips and new_log["source_ip"] not in known_ips:
        return {
            "rule_name": "Anomaly - Login From New Source IP",
            "severity": "Medium",
            "description": (
                f"User '{new_log['user']}' logged on from '{new_log['source_ip']}', "
                f"an IP not seen across their last {len(history)} logons."
            ),
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1078",
            "mitre_technique": "Valid Accounts",
        }
    return None
