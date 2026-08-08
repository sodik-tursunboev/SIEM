"""
linux_rules.py
--------------
Linux-specific log parsing + detection rules, layered on top of the
generic syslog receiver (syslog_listener.py). Covers the most common
Linux auth events: SSH logons, sudo usage, su, and user account changes -
the Linux equivalent of the Windows Event ID rules in rules.py.

WHY THIS EXISTS: syslog_listener.py's generic parser can receive any
syslog line and stores it fine, but its field extraction is generic
(a loose "user=X" regex, first IP found anywhere in the text). Real
Linux auth logs don't format things that way - sshd writes "Failed
password for root from 203.0.113.5 port 51226 ssh2", not "user=root".
Without daemon-specific parsing, every SSH/sudo/su log would come through
with an empty user field and none of the detection rules below could
ever match. refine_linux_fields() re-parses the raw message using the
actual format each daemon uses.

These rules key off event_type values the syslog listener assigns based
on the syslog "tag" field (e.g. "Syslog:sshd", "Syslog:sudo").
"""

import re
import database as db

# ---------------------------------------------------------------------
# Refined field extraction for common Linux daemons - real auth.log formats
# ---------------------------------------------------------------------

SSHD_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
SSHD_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
SSHD_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)")
SUDO_RE = re.compile(r"^(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$")
SU_RE = re.compile(r"\(to (?P<target>\S+)\)\s*(?P<user>\S+) on")
SU_SESSION_OPENED_RE = re.compile(r"session opened for user \S+ by (?P<user>[\w.\-]+)\(")
USERADD_RE = re.compile(r"new user:\s*name=(?P<user>[^,\s]+)")
USERMOD_GROUP_RE = re.compile(r"add '(?P<user>\S+)' to group '(?P<group>\S+)'")


def refine_linux_fields(tag: str, message: str, fallback_user: str, fallback_ip: str):
    """Re-extracts user/ip from the raw message using daemon-specific
    patterns, since the generic syslog regex misses most of these.
    Falls back to whatever the generic parser already found if no
    daemon-specific pattern matches. Call this from syslog_listener.py
    right after the generic parse."""
    user, ip = fallback_user, fallback_ip

    if tag == "sshd":
        m = SSHD_FAILED_RE.search(message) or SSHD_ACCEPTED_RE.search(message) or SSHD_INVALID_USER_RE.search(message)
        if m:
            user = m.group("user")
            ip = m.group("ip")
    elif tag == "sudo":
        m = SUDO_RE.search(message)
        if m:
            user = m.group("user").strip()
    elif tag == "su":
        m = SU_RE.search(message) or SU_SESSION_OPENED_RE.search(message)
        if m:
            user = m.group("user")

    return user, ip


# ---------------------------------------------------------------------
# Detection rules - same shape as rules.py, so they plug straight into
# the existing evaluate() pipeline once added to the RULES list there.
# ---------------------------------------------------------------------

def rule_ssh_brute_force(new_log: dict):
    """5+ SSH failed password attempts, same user or IP, within 5 minutes.
    Linux equivalent of the Windows brute-force rule."""
    if new_log["event_type"] != "Syslog:sshd":
        return None
    msg = (new_log.get("message") or "").lower()
    if "failed password" not in msg and "invalid user" not in msg:
        return None

    recent = db.get_logs_since(minutes=5)

    def is_failed_ssh(l):
        m = (l.get("message") or "").lower()
        return l["event_type"] == "Syslog:sshd" and ("failed password" in m or "invalid user" in m)

    same_user = [l for l in recent if is_failed_ssh(l) and new_log["user"] and l["user"] == new_log["user"]]
    same_ip = [l for l in recent if is_failed_ssh(l) and new_log["source_ip"] and l["source_ip"] == new_log["source_ip"]]

    base = {
        "related_user": new_log["user"], "related_ip": new_log["source_ip"],
        "mitre_id": "T1110", "mitre_technique": "Brute Force",
    }
    if len(same_user) >= 5:
        return {**base, "rule_name": "SSH Brute Force - Repeated Failed Logons (User)", "severity": "High",
                "description": f"{len(same_user)} failed SSH logon attempts for user "
                                f"'{new_log['user']}' within 5 minutes."}
    if len(same_ip) >= 5:
        return {**base, "rule_name": "SSH Brute Force - Repeated Failed Logons (Source IP)", "severity": "High",
                "description": f"{len(same_ip)} failed SSH logon attempts from IP "
                                f"'{new_log['source_ip']}' within 5 minutes."}
    return None


def rule_linux_privilege_escalation(new_log: dict):
    """su to root, or sudo used to get an interactive root shell -
    direct escalation to root, distinct from just running one command."""
    msg = (new_log.get("message") or "").lower()

    if new_log["event_type"] == "Syslog:su" and ("(to root)" in msg or "session opened for user root" in msg):
        return {
            "rule_name": "Linux Privilege Escalation - su to root",
            "severity": "Medium",
            "description": f"User '{new_log['user']}' switched to the root account via su.",
            "related_user": new_log["user"], "related_ip": new_log["source_ip"],
            "mitre_id": "T1548", "mitre_technique": "Abuse Elevation Control Mechanism",
        }
    if new_log["event_type"] == "Syslog:sudo" and re.search(r"command=.*(/bin/su|/bin/bash|/bin/sh)\s*$", msg):
        return {
            "rule_name": "Linux Privilege Escalation - sudo to shell",
            "severity": "Medium",
            "description": f"User '{new_log['user']}' used sudo to get an interactive root shell.",
            "related_user": new_log["user"], "related_ip": new_log["source_ip"],
            "mitre_id": "T1548", "mitre_technique": "Abuse Elevation Control Mechanism",
        }
    return None


# Common attacker-favorite commands run via sudo, each mapped to the
# real technique it's usually part of.
SUSPICIOUS_SUDO_PATTERNS = {
    "curl": ("T1105", "Ingress Tool Transfer"),
    "wget": ("T1105", "Ingress Tool Transfer"),
    "chmod 777": ("T1222", "File and Directory Permissions Modification"),
    "nc -e": ("T1059", "Command and Scripting Interpreter"),
    "/etc/shadow": ("T1003", "OS Credential Dumping"),
    "usermod -ag sudo": ("T1098", "Account Manipulation"),
    "usermod -ag wheel": ("T1098", "Account Manipulation"),
    "iptables -f": ("T1562", "Impair Defenses"),
    "systemctl stop": ("T1562", "Impair Defenses"),
    "history -c": ("T1070.003", "Indicator Removal: Clear Command History"),
}


def rule_suspicious_sudo_command(new_log: dict):
    if new_log["event_type"] != "Syslog:sudo":
        return None
    msg = (new_log.get("message") or "").lower()
    for keyword, (mitre_id, mitre_name) in SUSPICIOUS_SUDO_PATTERNS.items():
        if keyword in msg:
            return {
                "rule_name": "Suspicious Sudo Command",
                "severity": "High",
                "description": f"User '{new_log['user']}' ran a sudo command matching a "
                                f"known risky pattern: '{keyword}'.",
                "related_user": new_log["user"], "related_ip": new_log["source_ip"],
                "mitre_id": mitre_id, "mitre_technique": mitre_name,
            }
    return None


def rule_linux_user_created(new_log: dict):
    if new_log["event_type"] not in ("Syslog:useradd", "Syslog:adduser"):
        return None
    m = USERADD_RE.search(new_log.get("message") or "")
    created_user = m.group("user") if m else new_log["user"]
    return {
        "rule_name": "New Linux User Created",
        "severity": "Medium",
        "description": f"A new local Linux user account was created: '{created_user}'.",
        "related_user": created_user, "related_ip": new_log["source_ip"],
        "mitre_id": "T1136.001", "mitre_technique": "Create Account: Local Account",
    }


def rule_linux_user_added_to_privileged_group(new_log: dict):
    if new_log["event_type"] not in ("Syslog:usermod", "Syslog:groupadd"):
        return None
    msg = (new_log.get("message") or "").lower()
    if "sudo" not in msg and "wheel" not in msg and "admin" not in msg:
        return None
    m = USERMOD_GROUP_RE.search(new_log.get("message") or "")
    user = m.group("user") if m else new_log["user"]
    return {
        "rule_name": "Linux User Added to Privileged Group",
        "severity": "Critical",
        "description": f"User '{user}' was added to a privileged group (sudo/wheel/admin).",
        "related_user": user, "related_ip": new_log["source_ip"],
        "mitre_id": "T1098", "mitre_technique": "Account Manipulation",
    }


# Same pattern as anomaly.RULES - a plain list of rule functions that
# rules.py's RULES list gets extended with.
RULES = [
    rule_ssh_brute_force,
    rule_linux_privilege_escalation,
    rule_suspicious_sudo_command,
    rule_linux_user_created,
    rule_linux_user_added_to_privileged_group,
]
