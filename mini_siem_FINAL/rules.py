"""
rules.py
--------
This is the detection engine. Every time a new log comes in, we run it
through a set of rules. Each rule looks at recent logs and decides
whether to raise an alert.

This mirrors how real SIEMs work (Wazuh, Splunk, Sentinel): correlation
rules over a time window, not just "one bad log = one alert".

Every rule also tags its alert with a MITRE ATT&CK technique ID/name.
MITRE ATT&CK (https://attack.mitre.org) is the industry-standard catalog
of real attacker behaviors - tagging alerts against it is exactly what
real SOC tooling (Wazuh, Sentinel, Splunk ES) does, and it's a phrase
worth knowing well for interviews.

To add your own rule: write a function that takes the new log entry
and returns an alert dict (or None), then add it to RULES at the bottom.
"""

from datetime import datetime, timedelta
import re
import database as db
import anomaly
import linux_rules
import sigma_rules
import notifier
import soar
import correlation

# ---- Windows Event IDs we care about (the real ones Windows uses) ----
EVENT_FAILED_LOGON = 4625
EVENT_SUCCESS_LOGON = 4624
EVENT_ACCOUNT_LOCKOUT = 4740
EVENT_NEW_USER_CREATED = 4720
EVENT_USER_ADDED_TO_ADMIN_GROUP = 4732
EVENT_PROCESS_CREATED = 4688
EVENT_LOG_CLEARED = 1102
EVENT_USB_DEVICE = 6416
EVENT_SCHEDULED_TASK_CREATED = 4698
EVENT_SERVICE_INSTALLED = 7045
EVENT_KERBEROS_TGS_REQUEST = 4769

# Synthetic event ID - NOT a real Windows event, used only for login
# attempts against this SIEM's own web login. Namespaced in the 9000s
# specifically so it can never collide with a real Windows/Sysmon event ID.
EVENT_SIEM_LOGIN_FAILED = 9001


def _now():
    return datetime.utcnow().isoformat()


def rule_brute_force(new_log: dict):
    """5+ failed logons from the same user OR same source IP within 5 minutes."""
    if new_log["event_id"] != EVENT_FAILED_LOGON:
        return None

    recent = db.get_logs_since(minutes=5)
    same_user = [
        l for l in recent
        if l["event_id"] == EVENT_FAILED_LOGON and l["user"] == new_log["user"]
    ]
    same_ip = []
    if new_log["source_ip"]:
        same_ip = [
            l for l in recent
            if l["event_id"] == EVENT_FAILED_LOGON and l["source_ip"] == new_log["source_ip"]
        ]

    base = {
        "mitre_id": "T1110",
        "mitre_technique": "Brute Force",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
    }

    if len(same_user) >= 5:
        return {
            **base,
            "rule_name": "Brute Force - Repeated Failed Logons (User)",
            "severity": "High",
            "description": f"{len(same_user)} failed logon attempts for user "
                            f"'{new_log['user']}' within 5 minutes.",
        }
    if len(same_ip) >= 5:
        return {
            **base,
            "rule_name": "Brute Force - Repeated Failed Logons (Source IP)",
            "severity": "High",
            "description": f"{len(same_ip)} failed logon attempts from IP "
                            f"'{new_log['source_ip']}' within 5 minutes.",
        }
    return None


def rule_account_lockout(new_log: dict):
    if new_log["event_id"] != EVENT_ACCOUNT_LOCKOUT:
        return None
    return {
        "rule_name": "Account Lockout",
        "severity": "Medium",
        "description": f"Account '{new_log['user']}' was locked out, likely after "
                        f"repeated failed logon attempts.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1110",
        "mitre_technique": "Brute Force",
    }


def rule_new_admin_account(new_log: dict):
    """New user created and immediately added to an admin group = classic
    privilege-escalation / persistence technique."""
    if new_log["event_id"] not in (EVENT_NEW_USER_CREATED, EVENT_USER_ADDED_TO_ADMIN_GROUP):
        return None

    if new_log["event_id"] == EVENT_USER_ADDED_TO_ADMIN_GROUP:
        recent = db.get_logs_since(minutes=10)
        was_just_created = any(
            l["event_id"] == EVENT_NEW_USER_CREATED and l["user"] == new_log["user"]
            for l in recent
        )
        severity = "Critical" if was_just_created else "Medium"
        desc = (f"User '{new_log['user']}' was added to an administrative group"
                + (" shortly after being created — possible persistence technique."
                   if was_just_created else "."))
        return {
            "rule_name": "Privilege Escalation - Admin Group Change",
            "severity": severity,
            "description": desc,
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            # T1136.001 covers the account creation step; T1098 covers the
            # group-membership change itself, which is what this rule fires on.
            "mitre_id": "T1098",
            "mitre_technique": "Account Manipulation",
        }
    return None


def rule_log_cleared(new_log: dict):
    """Attackers clear the event log to cover their tracks. Always suspicious."""
    if new_log["event_id"] != EVENT_LOG_CLEARED:
        return None
    return {
        "rule_name": "Audit Log Cleared",
        "severity": "Critical",
        "description": "The Windows event log was cleared. This is commonly done "
                        "by attackers to hide evidence of their activity.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1070.001",
        "mitre_technique": "Indicator Removal: Clear Windows Event Logs",
    }


# Each known "living off the land" / attacker tool mapped to its real
# MITRE ATT&CK technique - much more useful than one generic tag for all of them.
SUSPICIOUS_TOOL_MITRE = {
    "mimikatz":               ("T1003", "OS Credential Dumping"),
    "psexec":                 ("T1570", "Lateral Tool Transfer"),
    "certutil -urlcache":     ("T1105", "Ingress Tool Transfer"),
    "whoami /all":            ("T1033", "System Owner/User Discovery"),
    "net user /add":          ("T1136.001", "Create Account: Local Account"),
    "vssadmin delete shadows": ("T1490", "Inhibit System Recovery"),
}


def rule_suspicious_process(new_log: dict):
    """Flag common living-off-the-land / recon tools if they show up as a
    newly created process. PowerShell gets its own dedicated rule below -
    it's common enough, and specific enough, to be worth tracking and
    tuning separately rather than folding into this generic catch-all."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None

    message = (new_log.get("message") or "").lower()
    for tool, (mitre_id, mitre_name) in SUSPICIOUS_TOOL_MITRE.items():
        if tool in message:
            return {
                "rule_name": "Suspicious Process Execution",
                "severity": "High",
                "description": f"Process matching known attacker technique detected: '{tool}'.",
                "related_user": new_log["user"],
                "related_ip": new_log["source_ip"],
                "mitre_id": mitre_id,
                "mitre_technique": mitre_name,
            }
    return None


# PowerShell-specific attacker patterns - a real enterprise SIEM tracks
# this as its own named rule (not lumped into "suspicious process") since
# it's one of the highest-signal single indicators in a Windows
# environment, and tuning it separately (raising/lowering sensitivity,
# adding exceptions) is common in practice.
SUSPICIOUS_POWERSHELL_PATTERNS = [
    "-enc", "-encodedcommand", "-e ", "-nop", "-noni", "-noprofile",
    "-w hidden", "-windowstyle hidden", "-ep bypass", "-executionpolicy bypass",
    "iex(", "invoke-expression", "downloadstring", "downloadfile",
    "frombase64string", "invoke-mimikatz", "invoke-webrequest", "net.webclient",
]


def rule_suspicious_powershell(new_log: dict):
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    if "powershell" not in message:
        return None
    matched = [p for p in SUSPICIOUS_POWERSHELL_PATTERNS if p in message]
    if not matched:
        return None
    return {
        "rule_name": "Suspicious PowerShell",
        "severity": "High",
        "description": f"PowerShell launched with suspicious argument(s): {', '.join(matched)}.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1059.001",
        "mitre_technique": "Command and Scripting Interpreter: PowerShell",
    }


def rule_password_spray(new_log: dict):
    """Password spraying looks different from brute force: instead of many
    attempts against ONE account, it's a handful of attempts against MANY
    accounts from the same source, to stay under per-account lockout
    thresholds. 4+ distinct usernames failing from the same IP in 10 minutes."""
    if new_log["event_id"] != EVENT_FAILED_LOGON or not new_log["source_ip"]:
        return None

    recent = db.get_logs_since(minutes=10)
    same_ip_attempts = [
        l for l in recent
        if l["event_id"] == EVENT_FAILED_LOGON and l["source_ip"] == new_log["source_ip"]
    ]
    distinct_users = {l["user"] for l in same_ip_attempts if l["user"]}

    if len(distinct_users) >= 4:
        return {
            "rule_name": "Password Spray - Multiple Accounts, Same Source",
            "severity": "High",
            "description": f"{len(distinct_users)} different accounts had failed logons "
                            f"from IP '{new_log['source_ip']}' within 10 minutes: "
                            f"{', '.join(sorted(distinct_users))}.",
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1110.003",
            "mitre_technique": "Password Spraying",
        }
    return None


def rule_usb_device(new_log: dict):
    """A new external/removable device was recognized. Not inherently
    malicious, but it's how a lot of real-world data exfiltration and
    initial-access incidents start, so SOCs track it as a Low-severity
    informational alert worth having on record."""
    if new_log["event_id"] != EVENT_USB_DEVICE:
        return None
    return {
        "rule_name": "External Device Connected",
        "severity": "Low",
        "description": f"A new external/removable device was connected"
                        f"{' by ' + new_log['user'] if new_log['user'] and new_log['user'] != 'UNKNOWN' else ''}.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1200",
        "mitre_technique": "Hardware Additions",
    }


def rule_scheduled_task_created(new_log: dict):
    """New scheduled tasks are a common persistence mechanism - malware
    creates one so it keeps running after reboot without needing a user
    logged in."""
    if new_log["event_id"] != EVENT_SCHEDULED_TASK_CREATED:
        return None
    return {
        "rule_name": "New Scheduled Task Created",
        "severity": "Medium",
        "description": f"A new scheduled task was created by '{new_log['user']}'. "
                        f"Worth confirming this was expected - scheduled tasks are a "
                        f"common way attackers maintain persistence.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1053.005",
        "mitre_technique": "Scheduled Task",
    }


def rule_service_installed(new_log: dict):
    """New Windows services are another classic persistence mechanism, and
    also how tools like PsExec execute commands remotely. Severity bumps
    to High if the service details look scripted/suspicious."""
    if new_log["event_id"] != EVENT_SERVICE_INSTALLED:
        return None
    message = (new_log.get("message") or "").lower()
    looks_suspicious = any(kw in message for kw in ["powershell", "cmd.exe /c", "temp\\", "appdata\\"])
    return {
        "rule_name": "New Service Installed",
        "severity": "High" if looks_suspicious else "Medium",
        "description": "A new Windows service was installed"
                        + (", with a suspicious-looking command/path in its configuration."
                           if looks_suspicious else "."),
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1543.003",
        "mitre_technique": "Windows Service",
    }


def rule_siem_login_brute_force(new_log: dict):
    """Brute force / password spray against the SIEM's OWN web login -
    not a Windows/Linux target, the tool's own front door. Structurally
    identical logic to rule_brute_force, kept as its own rule so it shows
    up clearly labeled as "someone is attacking the SIEM itself", not
    conflated with attacks on monitored systems."""
    if new_log["event_id"] != EVENT_SIEM_LOGIN_FAILED:
        return None

    recent = db.get_logs_since(minutes=15)

    def is_failed_siem_login(l):
        return l["event_id"] == EVENT_SIEM_LOGIN_FAILED

    same_user = [l for l in recent if is_failed_siem_login(l) and new_log["user"] and l["user"] == new_log["user"]]
    same_ip = [l for l in recent if is_failed_siem_login(l) and new_log["source_ip"] and l["source_ip"] == new_log["source_ip"]]

    base = {
        "related_user": new_log["user"], "related_ip": new_log["source_ip"],
        "mitre_id": "T1110", "mitre_technique": "Brute Force",
    }
    if len(same_user) >= 5:
        return {**base,
                "rule_name": "SIEM Login Brute Force (Account)", "severity": "Critical",
                "description": f"{len(same_user)} failed login attempts against this SIEM's own web "
                                f"login for account '{new_log['user']}' within 15 minutes."}
    if len(same_ip) >= 5:
        return {**base,
                "rule_name": "SIEM Login Brute Force (Source IP)", "severity": "Critical",
                "description": f"{len(same_ip)} failed login attempts against this SIEM's own web "
                                f"login from IP '{new_log['source_ip']}' within 15 minutes."}
    return None


def rule_kerberoasting(new_log: dict):
    """Kerberoasting: an attacker requests Kerberos service tickets (TGS)
    for service accounts, then cracks the ticket offline to recover the
    account's password. The signature isn't the ticket request itself -
    that's normal Kerberos activity - it's REQUESTING MANY TICKETS WITH
    WEAK (RC4) ENCRYPTION in a short window, which is what tools like
    Rubeus/Impacket's GetUserSPNs do when enumerating and roasting every
    SPN-registered account they can find. A single RC4 ticket request is
    unremarkable; 3+ from the same user in 10 minutes is not."""
    if new_log["event_id"] != EVENT_KERBEROS_TGS_REQUEST:
        return None

    message = (new_log.get("message") or "").lower()
    if "0x17" not in message and "rc4" not in message:
        return None  # AES-encrypted tickets (0x11/0x12) are the modern default and not roastable

    recent = db.get_logs_since(minutes=10)

    def is_weak_tgs_request(l):
        if l["event_id"] != EVENT_KERBEROS_TGS_REQUEST:
            return False
        m = (l.get("message") or "").lower()
        return "0x17" in m or "rc4" in m

    same_user = [l for l in recent if is_weak_tgs_request(l) and new_log["user"] and l["user"] == new_log["user"]]

    if len(same_user) >= 3:
        return {
            "rule_name": "Kerberoasting",
            "severity": "High",
            "description": f"{len(same_user)} RC4-encrypted Kerberos service ticket requests by "
                            f"'{new_log['user']}' within 10 minutes - consistent with SPN enumeration "
                            f"and offline ticket cracking (Kerberoasting).",
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1558.003",
            "mitre_technique": "Steal or Forge Kerberos Tickets: Kerberoasting",
        }
    return None


DISCOVERY_COMMANDS = [
    "whoami", "systeminfo", "net user", "net group", "net localgroup",
    "ipconfig /all", "tasklist", "nltest", "quser", "hostname",
    "net view", "net share", "arp -a", "route print", "wmic qfe",
]


def rule_discovery_burst(new_log: dict):
    """Individual discovery commands (whoami, systeminfo, etc.) are far
    too common in legitimate admin work to alert on one at a time - real
    attackers (and Atomic Red Team's Discovery-tactic tests) run several
    DIFFERENT recon commands back-to-back in a short window, automating
    what a human admin would do occasionally and slowly. Watching for a
    burst of distinct discovery commands catches that pattern without
    false-positiving on one IT admin running 'whoami' once."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    matched_command = next((c for c in DISCOVERY_COMMANDS if c in message), None)
    if not matched_command:
        return None

    recent = db.get_logs_since(minutes=5)

    def is_discovery_hit(l):
        if l["event_id"] != EVENT_PROCESS_CREATED:
            return False
        m = (l.get("message") or "").lower()
        return any(c in m for c in DISCOVERY_COMMANDS)

    same_user = [l for l in recent if is_discovery_hit(l) and new_log["user"] and l["user"] == new_log["user"]]
    distinct_commands = {next(c for c in DISCOVERY_COMMANDS if c in (l.get("message") or "").lower()) for l in same_user}

    if len(distinct_commands) >= 4:
        return {
            "rule_name": "Discovery Command Burst",
            "severity": "Medium",
            "description": f"{len(distinct_commands)} distinct system/network discovery commands run by "
                            f"'{new_log['user']}' within 5 minutes - consistent with automated "
                            f"reconnaissance rather than routine admin work.",
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1082",
            "mitre_technique": "System Information Discovery",
        }
    return None


LOLBIN_PATTERNS = {
    "rundll32.exe": ("T1218.011", "System Binary Proxy Execution: Rundll32"),
    "regsvr32.exe": ("T1218.010", "System Binary Proxy Execution: Regsvr32"),
    "mshta.exe": ("T1218.005", "System Binary Proxy Execution: Mshta"),
    "wmic process call create": ("T1047", "Windows Management Instrumentation"),
    "bitsadmin": ("T1197", "BITS Jobs"),
}


def rule_lolbin_abuse(new_log: dict):
    """'Living off the land' binaries - legitimate, signed Windows tools
    that attackers abuse to run malicious code while evading signature-
    based detection, since the binary itself is trusted. Common Atomic
    Red Team tests specifically target these (T1218 sub-techniques)."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    for pattern, (mitre_id, mitre_name) in LOLBIN_PATTERNS.items():
        if pattern in message:
            return {
                "rule_name": "Living-off-the-Land Binary Abuse",
                "severity": "High",
                "description": f"Execution via a living-off-the-land binary detected: '{pattern}' - "
                                f"a trusted Windows tool commonly abused to proxy malicious execution.",
                "related_user": new_log["user"],
                "related_ip": new_log["source_ip"],
                "mitre_id": mitre_id,
                "mitre_technique": mitre_name,
            }
    return None


def rule_registry_persistence(new_log: dict):
    """Registry Run/RunOnce keys are one of the most common persistence
    mechanisms - a program listed there launches every time the user (or
    system) logs in. Atomic Red Team's T1547.001 tests write to these
    keys directly via reg.exe or PowerShell."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    if "reg add" not in message and "set-itemproperty" not in message:
        return None
    if "\\run" not in message and "currentversion\\run" not in message:
        return None
    return {
        "rule_name": "Registry Run Key Persistence",
        "severity": "High",
        "description": "A Registry Run/RunOnce key was modified - a common technique for making a "
                        "program launch automatically at every logon.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1547.001",
        "mitre_technique": "Boot or Logon Autostart Execution: Registry Run Keys",
    }


def rule_indicator_removal(new_log: dict):
    """Beyond the existing 'audit log cleared' rule (which watches the
    dedicated 1102 event), attackers/testers also delete individual log
    files or forensic artifacts directly via command line - a different,
    narrower technique worth its own rule."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    patterns = ["wevtutil cl", "wevtutil clear-log", "del *.log", "remove-item *.log", "clear-eventlog"]
    matched = next((p for p in patterns if p in message), None)
    if not matched:
        return None
    return {
        "rule_name": "Indicator Removal - Log/Artifact Deletion",
        "severity": "Critical",
        "description": f"Command-line deletion of logs or forensic artifacts detected: '{matched}'.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1070.004",
        "mitre_technique": "Indicator Removal: File Deletion",
    }


def rule_remote_service_execution(new_log: dict):
    """PsExec and its equivalents (WMI process creation, sc.exe against a
    remote-looking target) are the classic way attackers move laterally
    once they've got credentials for a second machine - Atomic Red
    Team's lateral movement tests lean heavily on this pattern."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    patterns = ["psexec", "paexec", "\\\\admin$", "sc.exe \\\\", "sc \\\\"]
    matched = next((p for p in patterns if p in message), None)
    if not matched:
        return None
    return {
        "rule_name": "Remote Service Execution",
        "severity": "High",
        "description": f"Indicator of remote/lateral service execution detected: '{matched}' - "
                        f"consistent with PsExec-style lateral movement.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1021.002",
        "mitre_technique": "Remote Services: SMB/Windows Admin Shares",
    }


def rule_shadow_copy_deletion(new_log: dict):
    """A dedicated, clearly-labeled rule for shadow copy/backup deletion -
    previously only caught incidentally via the generic suspicious-tool
    list. Deleting shadow copies immediately before or after encrypting
    files is one of the most reliable ransomware indicators there is."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    patterns = ["vssadmin delete shadows", "wbadmin delete", "bcdedit /set", "wmic shadowcopy delete"]
    matched = next((p for p in patterns if p in message), None)
    if not matched:
        return None
    return {
        "rule_name": "Shadow Copy / Backup Deletion",
        "severity": "Critical",
        "description": f"Volume shadow copy or backup deletion detected: '{matched}' - a strong "
                        f"ransomware/anti-recovery indicator.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1490",
        "mitre_technique": "Inhibit System Recovery",
    }


def rule_unsecured_credential_search(new_log: dict):
    """Searching the filesystem or registry for stored/cached credentials
    - password files, cmdkey's saved credential list, unattended install
    answer files that sometimes contain plaintext passwords."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    patterns = ["cmdkey /list", "findstr /si password", "unattend.xml", "sysprep.inf", "findstr /spin password"]
    matched = next((p for p in patterns if p in message), None)
    if not matched:
        return None
    return {
        "rule_name": "Unsecured Credential Search",
        "severity": "Medium",
        "description": f"Search for stored/cached credentials detected: '{matched}'.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1552",
        "mitre_technique": "Unsecured Credentials",
    }


MASQUERADE_SYSTEM_NAMES = ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe"]


def rule_masquerading(new_log: dict):
    """A process named after a core Windows system binary but NOT running
    from its expected System32 location is a classic, high-confidence
    malware indicator - legitimate svchost.exe/lsass.exe/etc. only ever
    run from C:\\Windows\\System32, so a same-named process anywhere else
    is almost never legitimate."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    for name in MASQUERADE_SYSTEM_NAMES:
        if name in message and "system32" not in message:
            return {
                "rule_name": "Process Masquerading",
                "severity": "Critical",
                "description": f"A process named '{name}' was created outside of its expected "
                                f"C:\\Windows\\System32 location - legitimate Windows system binaries "
                                f"never run from anywhere else.",
                "related_user": new_log["user"],
                "related_ip": new_log["source_ip"],
                "mitre_id": "T1036.005",
                "mitre_technique": "Masquerading: Match Legitimate Name or Location",
            }
    return None


# -----------------------------------------------------------------------
# Advanced Sysmon / PowerShell rules
# -----------------------------------------------------------------------

OFFICE_PROCESSES = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "mspub.exe", "acrord32.exe"]
SHELL_PROCESSES = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"]


def rule_suspicious_parent_child(new_log: dict):
    """One of the highest-confidence detections in real SOC work: an
    Office application (or PDF reader) spawning a shell or scripting
    engine is almost never legitimate user behavior - it's the classic
    signature of a malicious macro or embedded object executing its
    payload the moment a document is opened. Needs both Image and
    ParentImage in the message, which the forwarder/collector already
    capture for every ProcessCreated event."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    child = next((c for c in SHELL_PROCESSES if c in message), None)
    if not child:
        return None
    # Capture everything after "parentimage=" up to the next field
    # delimiter (" | ") rather than the next whitespace character - real
    # Windows paths often contain spaces themselves (e.g. "C:\Program
    # Files\..."), so stopping at the first whitespace would cut the
    # value off before ever reaching the actual filename.
    parent_field = re.search(r"parentimage[:=]([^|]*)", message)
    if not parent_field or not any(p in parent_field.group(1) for p in OFFICE_PROCESSES):
        return None
    return {
        "rule_name": "Suspicious Parent-Child Process (Office -> Shell)",
        "severity": "Critical",
        "description": f"An Office/document application spawned '{child}' - the classic signature of "
                        f"a malicious macro or embedded object executing its payload.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1204.002",
        "mitre_technique": "User Execution: Malicious File",
    }


def rule_powershell_downgrade(new_log: dict):
    """Attackers deliberately force PowerShell to run in version 2 mode
    specifically because PSv2 predates AMSI (Antimalware Scan Interface)
    and modern script-block logging - it's a well-documented, deliberate
    evasion technique, not something that happens by accident."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    if "powershell" not in message:
        return None
    if not re.search(r"-version\s*2\b|-v\s*2\b", message):
        return None
    return {
        "rule_name": "PowerShell Downgrade Attack",
        "severity": "High",
        "description": "PowerShell was explicitly launched in version 2 mode - a deliberate technique "
                        "to bypass AMSI and modern script-block logging, which PSv2 predates.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1059.001",
        "mitre_technique": "Command and Scripting Interpreter: PowerShell",
    }


def rule_powershell_obfuscation(new_log: dict):
    """A lightweight obfuscation heuristic: real attacker PowerShell tends
    to be heavily obfuscated to dodge string-based signature detection -
    excessive backticks (character escaping), char-code array
    reconstruction, or string concatenation used to hide keywords like
    'IEX' or 'Invoke-Expression' from naive scanners. A few of these
    together, not just one, is what separates this from normal scripting."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = new_log.get("message") or ""
    if "powershell" not in message.lower():
        return None
    indicators = []
    if message.count("`") >= 3:
        indicators.append("excessive backtick escaping")
    if re.search(r"\[char\]\s*\d+", message, re.IGNORECASE):
        indicators.append("char-code reconstruction")
    if len(re.findall(r"'\s*\+\s*'", message)) >= 3:
        indicators.append("string concatenation obfuscation")
    if re.search(r"-join\s*\(", message, re.IGNORECASE) and "[char]" in message.lower():
        indicators.append("array-join reconstruction")
    if len(indicators) < 2:
        return None
    return {
        "rule_name": "PowerShell Obfuscation Indicators",
        "severity": "High",
        "description": f"Multiple obfuscation techniques detected in a PowerShell command line: "
                        f"{', '.join(indicators)}.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1027",
        "mitre_technique": "Obfuscated Files or Information",
    }


AMSI_BYPASS_PATTERNS = [
    "amsiinitfailed", "amsiscanbuffer", "amsiutils", "system.management.automation.amsiutils",
]


def rule_amsi_bypass(new_log: dict):
    """AMSI (Antimalware Scan Interface) is what lets Windows Defender and
    other AV inspect PowerShell/VBScript content before it runs. These
    specific strings are well-known, publicly documented AMSI bypass
    payloads - not generic suspicious activity, but a specific, named
    attempt to blind AV to whatever runs next."""
    if new_log["event_id"] != EVENT_PROCESS_CREATED:
        return None
    message = (new_log.get("message") or "").lower()
    matched = next((p for p in AMSI_BYPASS_PATTERNS if p in message), None)
    if not matched:
        return None
    return {
        "rule_name": "AMSI Bypass Attempt",
        "severity": "Critical",
        "description": f"A known AMSI bypass indicator was detected: '{matched}' - an attempt to "
                        f"blind antivirus/AMSI scanning before running further malicious code.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1562.001",
        "mitre_technique": "Impair Defenses: Disable or Modify Tools",
    }


# GrantedAccess masks real credential-dumping tools request against
# lsass.exe - these specific combinations of read/query rights are what
# Mimikatz, procdump, and similar tools ask for; ordinary processes
# essentially never request these exact rights against lsass.exe.
LSASS_SUSPICIOUS_ACCESS_MASKS = ["0x1010", "0x1410", "0x1438", "0x143a", "0x1418", "0x1fffff"]


def rule_lsass_access_suspicious(new_log: dict):
    """Upgrades the earlier message-content-only LSASS detection with a
    real access-mask check: Sysmon Event 10 (ProcessAccess) reports the
    exact Windows access rights requested. A process opening a handle to
    lsass.exe with one of these specific rights combinations is
    functionally certain to be a credential-dumping attempt, not a false
    positive from some unrelated tool that happens to touch lsass.exe."""
    if new_log.get("event_type") != "Sysmon_ProcessAccess":
        return None
    message = (new_log.get("message") or "").lower()
    if "lsass.exe" not in message:
        return None
    matched_mask = next((m for m in LSASS_SUSPICIOUS_ACCESS_MASKS if m in message), None)
    if not matched_mask:
        return None
    return {
        "rule_name": "Suspicious LSASS Access (Credential Dumping)",
        "severity": "Critical",
        "description": f"A process opened a handle to lsass.exe with access rights ({matched_mask}) "
                        f"consistent with credential-dumping tools (Mimikatz, procdump, etc.), not "
                        f"normal system activity.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1003.001",
        "mitre_technique": "OS Credential Dumping: LSASS Memory",
    }


def rule_process_injection(new_log: dict):
    """Sysmon Event 8 (CreateRemoteThread) fires when one process creates
    a thread inside another, running process - the mechanism behind
    classic process injection (DLL injection, reflective loading, process
    hollowing). Legitimate software essentially never does this; it's one
    of the strongest single-event indicators available."""
    if new_log.get("event_type") != "Sysmon_CreateRemoteThread":
        return None
    return {
        "rule_name": "Process Injection (CreateRemoteThread)",
        "severity": "Critical",
        "description": "A process created a remote thread inside another running process - the "
                        "mechanism behind DLL injection, reflective loading, and process hollowing. "
                        "Legitimate software essentially never does this.",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "T1055",
        "mitre_technique": "Process Injection",
    }


def rule_dns_tunneling(new_log: dict):
    """DNS tunneling (using DNS queries to exfiltrate data or maintain C2
    covertly) has a recognizable shape: either an unusually high volume
    of DNS queries from one host in a short window, or queries against
    unusually long, high-entropy-looking subdomains (the encoded
    data/commands). This checks both - either is suspicious on its own,
    but volume is the more reliable of the two for a first pass."""
    if new_log.get("event_type") != "Sysmon_DnsQuery":
        return None
    message = new_log.get("message") or ""

    query_match = re.search(r"queried\s+(\S+)", message)
    query_name = query_match.group(1) if query_match else ""
    longest_label = max((len(part) for part in query_name.split(".")), default=0)

    recent = db.get_logs_since(minutes=5)
    same_host_queries = [l for l in recent if l.get("event_type") == "Sysmon_DnsQuery" and l["host"] == new_log["host"]]

    if len(same_host_queries) >= 30:
        return {
            "rule_name": "DNS Tunneling - High Query Volume",
            "severity": "High",
            "description": f"{len(same_host_queries)} DNS queries from '{new_log['host']}' within 5 "
                            f"minutes - volume consistent with DNS tunneling rather than normal browsing.",
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1071.004",
            "mitre_technique": "Application Layer Protocol: DNS",
        }
    if longest_label >= 40:
        return {
            "rule_name": "DNS Tunneling - Suspicious Query Pattern",
            "severity": "Medium",
            "description": f"An unusually long DNS subdomain label ({longest_label} characters) was "
                            f"queried - consistent with data encoded into a DNS tunneling channel.",
            "related_user": new_log["user"],
            "related_ip": new_log["source_ip"],
            "mitre_id": "T1071.004",
            "mitre_technique": "Application Layer Protocol: DNS",
        }
    return None


def rule_ioc_match(new_log: dict):
    """Checks this event's IP, user, and message against the analyst-
    maintained IOC watchlist (Threat Hunting > IOC Watchlist page). This is
    what turns a static list of 'known bad' indicators into active
    detection - any new log touching a listed indicator becomes an alert
    immediately instead of needing someone to go looking for it."""
    iocs = db.get_all_ioc_values()
    if not iocs:
        return None

    message = (new_log.get("message") or "")
    matched_indicator = None
    matched_type = None

    for indicator, ioc in iocs.items():
        if not indicator:
            continue
        if (new_log.get("source_ip") and indicator == new_log["source_ip"]) or \
           (new_log.get("user") and indicator == new_log["user"]) or \
           (indicator in message):
            matched_indicator = indicator
            matched_type = ioc["ioc_type"]
            break

    if not matched_indicator:
        return None

    return {
        "rule_name": "IOC Watchlist Match",
        "severity": "Critical",
        "description": f"Event matched a known indicator of compromise: "
                        f"'{matched_indicator}' ({matched_type}).",
        "related_user": new_log["user"],
        "related_ip": new_log["source_ip"],
        "mitre_id": "TA0043",
        "mitre_technique": "Reconnaissance / Known-Bad Indicator",
    }


# Every active rule lives here. Add new functions above, then list them here.
# Anomaly-detection rules (behavioral baselining) live in anomaly.py, and
RULES = [
    rule_ioc_match,
    rule_brute_force,
    rule_password_spray,
    rule_account_lockout,
    rule_new_admin_account,
    rule_log_cleared,
    rule_suspicious_process,
    rule_suspicious_powershell,
    rule_siem_login_brute_force,
    rule_discovery_burst,
    rule_lolbin_abuse,
    rule_registry_persistence,
    rule_indicator_removal,
    rule_remote_service_execution,
    rule_shadow_copy_deletion,
    rule_unsecured_credential_search,
    rule_masquerading,
    rule_suspicious_parent_child,
    rule_powershell_downgrade,
    rule_powershell_obfuscation,
    rule_amsi_bypass,
    rule_lsass_access_suspicious,
    rule_process_injection,
    rule_dns_tunneling,
    rule_kerberoasting,
    rule_usb_device,
    rule_scheduled_task_created,
    rule_service_installed,
    anomaly.rule_unusual_login_hour,
    anomaly.rule_new_source_ip,
] + linux_rules.RULES + [sigma_rules.evaluate_sigma]


# Metadata catalog for the Rule Management page (name, typical severity,
# MITRE ID, MITRE technique) - keyed by function name so it survives
# reordering RULES above. Sigma isn't listed here since it already has
# its own management page (Sigma Rules) and represents many dynamic
# rules, not one - it doesn't fit the one-row-per-rule model here.
RULE_CATALOG = {
    "rule_ioc_match": ("IOC Watchlist Match", "Critical", "TA0043", "Reconnaissance / Known-Bad Indicator"),
    "rule_brute_force": ("Brute Force Detection", "High", "T1110", "Brute Force"),
    "rule_password_spray": ("Password Spraying", "High", "T1110.003", "Password Spraying"),
    "rule_account_lockout": ("Account Lockout", "Medium", "T1110", "Brute Force"),
    "rule_new_admin_account": ("New Local Admin", "Medium", "T1098", "Account Manipulation"),
    "rule_log_cleared": ("Audit Log Cleared", "Critical", "T1070.001", "Indicator Removal: Clear Windows Event Logs"),
    "rule_suspicious_process": ("Suspicious Process Execution", "High", "Varies", "Varies by tool"),
    "rule_suspicious_powershell": ("Suspicious PowerShell", "High", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "rule_siem_login_brute_force": ("SIEM Login Brute Force", "Critical", "T1110", "Brute Force"),
    "rule_discovery_burst": ("Discovery Command Burst", "Medium", "T1082", "System Information Discovery"),
    "rule_lolbin_abuse": ("Living-off-the-Land Binary Abuse", "High", "Varies", "System Binary Proxy Execution"),
    "rule_registry_persistence": ("Registry Run Key Persistence", "High", "T1547.001", "Boot or Logon Autostart Execution"),
    "rule_indicator_removal": ("Indicator Removal - Log/Artifact Deletion", "Critical", "T1070.004", "Indicator Removal: File Deletion"),
    "rule_remote_service_execution": ("Remote Service Execution", "High", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "rule_shadow_copy_deletion": ("Shadow Copy / Backup Deletion", "Critical", "T1490", "Inhibit System Recovery"),
    "rule_unsecured_credential_search": ("Unsecured Credential Search", "Medium", "T1552", "Unsecured Credentials"),
    "rule_masquerading": ("Process Masquerading", "Critical", "T1036.005", "Masquerading"),
    "rule_suspicious_parent_child": ("Suspicious Parent-Child Process", "Critical", "T1204.002", "User Execution: Malicious File"),
    "rule_powershell_downgrade": ("PowerShell Downgrade Attack", "High", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "rule_powershell_obfuscation": ("PowerShell Obfuscation Indicators", "High", "T1027", "Obfuscated Files or Information"),
    "rule_amsi_bypass": ("AMSI Bypass Attempt", "Critical", "T1562.001", "Impair Defenses"),
    "rule_lsass_access_suspicious": ("Suspicious LSASS Access", "Critical", "T1003.001", "OS Credential Dumping: LSASS Memory"),
    "rule_process_injection": ("Process Injection", "Critical", "T1055", "Process Injection"),
    "rule_dns_tunneling": ("DNS Tunneling", "High", "T1071.004", "Application Layer Protocol: DNS"),
    "rule_kerberoasting": ("Kerberoasting", "High", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    "rule_usb_device": ("USB Device Connected", "Low", "T1200", "Hardware Additions"),
    "rule_scheduled_task_created": ("New Scheduled Task", "Medium", "T1053.005", "Scheduled Task"),
    "rule_service_installed": ("New Service Installed", "Medium", "T1543.003", "Windows Service"),
    "rule_unusual_login_hour": ("Unusual Login Hour", "Medium", "T1078", "Valid Accounts"),
    "rule_new_source_ip": ("Login From New Source IP", "Medium", "T1078", "Valid Accounts"),
    "rule_ssh_brute_force": ("SSH Brute Force", "High", "T1110", "Brute Force"),
    "rule_linux_privilege_escalation": ("Linux Privilege Escalation", "Medium", "T1548", "Abuse Elevation Control Mechanism"),
    "rule_suspicious_sudo_command": ("Suspicious Sudo Command", "High", "Varies", "Varies by command"),
    "rule_linux_user_created": ("New Linux User Created", "Medium", "T1136.001", "Create Account: Local Account"),
    "rule_linux_user_added_to_privileged_group": ("Linux User Added to Privileged Group", "Critical", "T1098", "Account Manipulation"),
}


def register_all_rules():
    """Populates/refreshes the rule registry with every rule's metadata.
    Called once at app startup - safe to call repeatedly, never resets
    an existing rule's enabled state or hit history (see
    database.ensure_rule_registered)."""
    for rule_fn in RULES:
        key = rule_fn.__name__
        if key in RULE_CATALOG:
            display_name, severity, mitre_id, mitre_technique = RULE_CATALOG[key]
            db.ensure_rule_registered(key, display_name, severity, mitre_id, mitre_technique)


def evaluate(new_log: dict):
    """Run every rule against a freshly-inserted log. Insert any alerts raised.
    Rules disabled in the Rule Management registry are skipped entirely -
    not run, not counted - matching how enterprise SIEMs treat a disabled
    detection."""
    triggered = []
    for rule in RULES:
        rule_key = rule.__name__
        if rule_key in RULE_CATALOG and not db.is_rule_enabled(rule_key):
            continue
        result = rule(new_log)
        if result:
            result["timestamp"] = _now()
            result["log_id"] = new_log["id"]
            alert_id = db.insert_alert(result)
            result["id"] = alert_id
            if rule_key in RULE_CATALOG:
                db.record_rule_hit(rule_key, result["timestamp"])
            notifier.notify_if_needed(result)
            soar.check_playbooks(result)
            correlation.check_correlation(result)
            triggered.append(result)
    return triggered
