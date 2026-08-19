"""
collector.py
------------
Two ways to feed the SIEM:

1. collect_windows_events()  -> reads REAL logs from Windows Event Viewer.
   Only works when run on Windows, with pywin32 installed, ideally as
   Administrator (needed to read the Security log).

2. run_demo_generator()      -> makes up realistic-looking Windows-style
   events on any OS. Use this to see the dashboard working immediately,
   or to demo the project in an interview without needing a live attack.

Both funnel events through the same save_event() function, so the rest
of the system (database, rules, dashboard) doesn't care where a log came from.
"""

import time
import random
import re
import os
import platform
from datetime import datetime

import database as db
import rules

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    try:
        import win32evtlog  # from pywin32
        import win32evtlogutil
        import win32con
    except ImportError:
        IS_WINDOWS = False  # pywin32 not installed, fall back to demo mode


def save_event(source, event_id, event_type, user, source_ip, host, message, timestamp=None):
    """Insert a log, then immediately run detection rules against it.
    timestamp can be overridden (ISO string) to backdate demo events when
    building a realistic history for the anomaly-detection baseline."""
    entry = {
        "timestamp": timestamp or datetime.utcnow().isoformat(),
        "source": source,
        "event_id": event_id,
        "event_type": event_type,
        "user": user,
        "source_ip": source_ip,
        "host": host,
        "message": message,
    }
    log_id = db.insert_log(entry)
    entry["id"] = log_id
    triggered_alerts = rules.evaluate(entry)
    return entry, triggered_alerts


# -------------------------------------------------------------------
# REAL Windows Event Viewer collection
# -------------------------------------------------------------------

# Map raw Windows Event IDs to a friendly event_type label
EVENT_TYPE_MAP = {
    4624: "SuccessfulLogon",
    4625: "FailedLogon",
    4740: "AccountLockout",
    4720: "UserCreated",
    4732: "AddedToAdminGroup",
    4688: "ProcessCreated",
    1102: "LogCleared",
    6416: "USBDeviceInserted",
    4698: "ScheduledTaskCreated",
    7045: "ServiceInstalled",
    4768: "KerberosAuthTicketRequested",   # TGT request - relevant to Golden Ticket hunting
    4769: "KerberosServiceTicketRequested",  # TGS request - required for the Kerberoasting rule to fire
}


# Position of the "account name" field within StringInserts, per event ID.
# Windows uses a DIFFERENT template layout for every event ID, so a single
# fixed index (e.g. "always inserts[5]") is wrong for most events -
# this was a bug in the first version. These indices come from Microsoft's
# documented event schemas for each event ID below.
USER_INSERT_INDEX = {
    4624: 5,  # TargetUserName - successful logon
    4625: 5,  # TargetUserName - failed logon
    4720: 4,  # TargetUserName - new account created
    4732: 0,  # MemberName - account added to a group
    4740: 0,  # TargetUserName - account locked out
    4688: 1,  # SubjectUserName - who launched the new process
    1102: 1,  # SubjectUserName - who cleared the log
    6416: 1,  # SubjectUserName - who connected the device
    4698: 1,  # SubjectUserName - who created the scheduled task
    7045: 4,  # AccountName - the account context the new service runs as
    4768: 0,  # TargetUserName - who requested the TGT
    4769: 0,  # TargetUserName - who requested the TGS
}


# -------------------------------------------------------------------
# Sysmon support
# -------------------------------------------------------------------
# Sysmon logs to a completely separate channel from Security/System, with
# its own event ID scheme (low numbers, 1-29ish) that never collides with
# the 4-digit Windows Security IDs used elsewhere in this file. Tools like
# Atomic Red Team are typically paired with Sysmon rather than native
# Windows auditing, because Sysmon logs full command lines by default -
# native Windows process-creation auditing (event 4688) often does NOT
# include the command line unless a specific audit policy/GPO is turned
# on, which most machines don't have enabled out of the box.
#
# NOTE: this was built and reasoned through carefully against documented
# Sysmon behavior, but has not been verified against a real live Sysmon
# feed (no Windows+Sysmon environment available to test against here).
# If field extraction looks wrong on a real machine, _parse_sysmon_event's
# debug print (see below) will show the raw rendered text so the field
# names/regex can be adjusted to match what's actually coming through.

SYSMON_LOG_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

SYSMON_PROCESS_CREATE = 1
SYSMON_NETWORK_CONNECT = 3
SYSMON_CREATE_REMOTE_THREAD = 8   # process injection
SYSMON_PROCESS_ACCESS = 10   # relevant to LSASS credential-dumping detection
SYSMON_FILE_CREATE = 11
SYSMON_DNS_QUERY = 22

# Which Sysmon event IDs we actually collect - everything else gets
# skipped, same "only keep what we have rules/hunts for" philosophy as
# EVENT_TYPE_MAP for Security/System.
SYSMON_EVENT_IDS = {SYSMON_PROCESS_CREATE, SYSMON_PROCESS_ACCESS, SYSMON_CREATE_REMOTE_THREAD, SYSMON_DNS_QUERY}


def _extract_sysmon_field(rendered_message: str, field_name: str) -> str:
    """Sysmon's rendered event message is a consistent 'Label: value' line
    format (this is what you see in Event Viewer's General tab) - e.g. a
    line reading 'CommandLine: powershell.exe -enc ...'. Extracting named
    fields via regex from this RENDERED text is deliberately more robust
    than reading positional StringInserts indices: Sysmon publishes
    structured XML EventData rather than the classic positional insert
    array Security/System events use, so a hardcoded index would be
    fragile in a way a labeled-text match isn't."""
    match = re.search(rf"{re.escape(field_name)}:\s*(.+)", rendered_message)
    return match.group(1).strip() if match else ""


def _parse_sysmon_event(event, debug=False):
    """Sysmon events get parsed differently from Security/System events -
    see _extract_sysmon_field's docstring for why. Process Create (ID 1)
    events get deliberately remapped to look like a Windows 4688 event
    internally (same event_id, same event_type), so every existing rule
    that already looks for process creation (rule_suspicious_process,
    rule_suspicious_powershell) works against Sysmon data with ZERO
    changes needed - and gets a real command line to match against,
    fixing the actual gap that caused Atomic Red Team tests to go
    undetected in the first place."""
    event_id = event.EventID & 0xFFFF

    try:
        message = win32evtlogutil.SafeFormatMessage(event, SYSMON_LOG_CHANNEL)
    except Exception:
        message = ""
    message = message or ""

    if debug:
        print(f"[SYSMON DEBUG] Raw rendered message for event ID {event_id}:\n{message}\n---")

    user = _extract_sysmon_field(message, "User") or "UNKNOWN"
    # Sysmon sometimes renders this as DOMAIN\user - keep it as-is, it's
    # still a valid, matchable username for our rules.

    if event_id == SYSMON_PROCESS_CREATE:
        command_line = _extract_sysmon_field(message, "CommandLine")
        image = _extract_sysmon_field(message, "Image")
        # Reconstruct a message that puts the command line front and
        # center, since that's the text our detection rules pattern-match
        # against (mimikatz, -enc, DownloadString, etc.).
        readable = f"Sysmon ProcessCreate: {image} | CommandLine: {command_line}"
        return {
            "source": "Sysmon",
            "event_id": rules.EVENT_PROCESS_CREATED,   # 4688 - matches existing rules
            "event_type": "ProcessCreated",
            "user": user,
            "source_ip": "",
            "host": platform.node(),
            "message": readable[:500],
        }

    if event_id == SYSMON_PROCESS_ACCESS:
        target_image = _extract_sysmon_field(message, "TargetImage")
        source_image = _extract_sysmon_field(message, "SourceImage")
        granted_access = _extract_sysmon_field(message, "GrantedAccess")
        readable = f"Sysmon ProcessAccess: {source_image} accessed {target_image} | GrantedAccess: {granted_access}"
        return {
            "source": "Sysmon",
            "event_id": event_id,
            "event_type": "Sysmon_ProcessAccess",
            "user": user,
            "source_ip": "",
            "host": platform.node(),
            "message": readable[:500],
        }

    if event_id == SYSMON_CREATE_REMOTE_THREAD:
        source_image = _extract_sysmon_field(message, "SourceImage")
        target_image = _extract_sysmon_field(message, "TargetImage")
        start_address = _extract_sysmon_field(message, "StartAddress")
        readable = (f"Sysmon CreateRemoteThread: {source_image} injected into {target_image} "
                    f"| StartAddress: {start_address}")
        return {
            "source": "Sysmon",
            "event_id": event_id,
            "event_type": "Sysmon_CreateRemoteThread",
            "user": user,
            "source_ip": "",
            "host": platform.node(),
            "message": readable[:500],
        }

    if event_id == SYSMON_DNS_QUERY:
        query_name = _extract_sysmon_field(message, "QueryName")
        image = _extract_sysmon_field(message, "Image")
        readable = f"Sysmon DnsQuery: {image} queried {query_name}"
        return {
            "source": "Sysmon",
            "event_id": event_id,
            "event_type": "Sysmon_DnsQuery",
            "user": user,
            "source_ip": "",
            "host": platform.node(),
            "message": readable[:500],
        }

    return None


def _parse_event(event, log_type):
    """Pull the fields we care about out of a raw pywin32 event object."""
    event_id = event.EventID & 0xFFFF  # low 16 bits = the actual event id
    inserts = event.StringInserts or []

    idx = USER_INSERT_INDEX.get(event_id)
    user = inserts[idx] if idx is not None and idx < len(inserts) else "UNKNOWN"
    # 4732's MemberName sometimes comes back as "CN=John Doe,CN=Users,DC=corp"
    # instead of a plain username - trim it down to just the name.
    if event_id == 4732 and user.upper().startswith("CN="):
        user = user.split(",")[0][3:]

    def _looks_like_ip(s):
        parts = s.split(".")
        return len(parts) == 4 and all(p.isdigit() for p in parts)

    source_ip = next((i for i in inserts if _looks_like_ip(i)), "")

    # Use Windows' own message formatter for the human-readable text -
    # this is far more reliable than guessing which insert holds what,
    # and it's what lets rule_suspicious_process match command-line text.
    try:
        message = win32evtlogutil.SafeFormatMessage(event, log_type)
    except Exception:
        message = " | ".join(inserts) if inserts else ""

    return {
        "source": log_type,
        "event_id": event_id,
        "event_type": EVENT_TYPE_MAP.get(event_id, f"EventID_{event_id}"),
        "user": user,
        "source_ip": source_ip,
        "host": platform.node(),
        "message": (message or "")[:500],
    }


def _init_log_state(server, log_type):
    """Find where a log currently ends, so we start watching from 'now'
    instead of replaying its entire historical backlog on first run."""
    handle = win32evtlog.OpenEventLog(server, log_type)
    total = win32evtlog.GetNumberOfEventLogRecords(handle)
    oldest = win32evtlog.GetOldestEventLogRecord(handle)
    win32evtlog.CloseEventLog(handle)
    return (oldest + total - 1) if total else 0


def _poll_log(server, log_type, last_record, flags):
    """Reads every new record in one log channel since last_record, runs
    each through save_event, and returns the updated last_record."""
    handle = win32evtlog.OpenEventLog(server, log_type)

    # If the log was cleared since our last poll, Windows resets record
    # numbering - the highest record number now available can drop below
    # last_record. Without this check, the skip condition below would
    # wrongly stay true forever and we'd silently miss the clear event
    # itself, and everything logged after it.
    try:
        current_total = win32evtlog.GetNumberOfEventLogRecords(handle)
        current_oldest = win32evtlog.GetOldestEventLogRecord(handle)
        current_max = (current_oldest + current_total - 1) if current_total else current_oldest
        if current_max < last_record:
            print(f"[COLLECTOR] Detected '{log_type}' log reset (cleared) - resuming from the start of the new log.")
            last_record = current_oldest - 1
    except Exception:
        pass

    newest_seen = last_record
    try:
        while True:
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception:
                break  # reached end of log
            if not events:
                break
            for event in events:
                if event.RecordNumber <= last_record:
                    continue
                newest_seen = max(newest_seen, event.RecordNumber)

                parsed = _parse_event(event, log_type)
                if parsed["event_id"] not in EVENT_TYPE_MAP:
                    continue  # skip noise we don't have rules for

                entry, alerts = save_event(**parsed)
                print(f"[LOG:{log_type}] {entry['event_type']} user={entry['user']}")
                for a in alerts:
                    print(f"   -> ALERT [{a['severity']}] {a['rule_name']}: {a['description']}")
    finally:
        win32evtlog.CloseEventLog(handle)

    return newest_seen


def _poll_sysmon_log(server, last_record, flags, debug=False):
    """Same read-forward-from-last-record logic as _poll_log, but reading
    the Sysmon channel and using _parse_sysmon_event instead of
    _parse_event, since Sysmon's data needs different extraction (see
    _parse_sysmon_event's docstring)."""
    handle = win32evtlog.OpenEventLog(server, SYSMON_LOG_CHANNEL)

    try:
        current_total = win32evtlog.GetNumberOfEventLogRecords(handle)
        current_oldest = win32evtlog.GetOldestEventLogRecord(handle)
        current_max = (current_oldest + current_total - 1) if current_total else current_oldest
        if current_max < last_record:
            print("[COLLECTOR] Detected Sysmon log reset (cleared) - resuming from the start of the new log.")
            last_record = current_oldest - 1
    except Exception:
        pass

    newest_seen = last_record
    try:
        while True:
            try:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
            except Exception:
                break
            if not events:
                break
            for event in events:
                if event.RecordNumber <= last_record:
                    continue
                newest_seen = max(newest_seen, event.RecordNumber)

                event_id = event.EventID & 0xFFFF
                if event_id not in SYSMON_EVENT_IDS:
                    continue

                parsed = _parse_sysmon_event(event, debug=debug)
                if parsed is None:
                    continue

                entry, alerts = save_event(**parsed)
                print(f"[SYSMON] {entry['event_type']} user={entry['user']}")
                for a in alerts:
                    print(f"   -> ALERT [{a['severity']}] {a['rule_name']}: {a['description']}")
    finally:
        win32evtlog.CloseEventLog(handle)

    return newest_seen


def collect_windows_events(log_types=("Security", "System"), poll_seconds=10):
    """
    Continuously polls one or more Windows event logs and feeds new events
    into the SIEM. Security holds logons/lockouts/user changes; System
    holds service installs. Each log channel tracks its own read position
    independently.

    Run this as Administrator: `python collector.py` on Windows.
    """
    if not IS_WINDOWS:
        print("Not running on Windows (or pywin32 missing) - switching to demo mode.")
        run_demo_generator()
        return

    if isinstance(log_types, str):
        log_types = (log_types,)

    server = "localhost"
    print(f"Collecting from Windows log(s): {', '.join(log_types)}. Polling every {poll_seconds}s. Ctrl+C to stop.")

    # IMPORTANT: EVENTLOG_FORWARDS_READ + a fresh handle each poll always
    # starts reading from the oldest record still in the log. We rely on
    # skipping anything <= last_record to only process genuinely new events.
    # (An earlier version of this used EVENTLOG_BACKWARDS_READ on a single
    # reused handle, which walks further back into history on every poll
    # instead of forward toward new events - that was a bug, fixed since.)
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    last_record = {lt: _init_log_state(server, lt) for lt in log_types}

    # Sysmon is optional - not every machine has it installed. Try to open
    # its channel once up front; if that fails, log it clearly and just
    # skip Sysmon collection entirely rather than crashing the whole
    # collector over one missing, optional log source.
    sysmon_enabled = False
    sysmon_last_record = 0
    try:
        sysmon_last_record = _init_log_state(server, SYSMON_LOG_CHANNEL)
        sysmon_enabled = True
        print(f"Sysmon detected - also collecting from '{SYSMON_LOG_CHANNEL}'.")
    except Exception as e:
        print(f"Sysmon channel not found or inaccessible ({e}) - skipping Sysmon collection. "
              f"Native Windows auditing only will be used.")

    while True:
        for lt in log_types:
            last_record[lt] = _poll_log(server, lt, last_record[lt], flags)
        if sysmon_enabled:
            try:
                sysmon_last_record = _poll_sysmon_log(
                    server, sysmon_last_record, flags,
                    debug=(os.environ.get("SIEM_SYSMON_DEBUG") == "1")
                )
            except Exception as e:
                print(f"[SYSMON] Poll error (will retry next cycle): {e}")
        time.sleep(poll_seconds)


# -------------------------------------------------------------------
# DEMO generator - realistic fake events, works on any OS
# -------------------------------------------------------------------

DEMO_USERS = ["jdoe", "asmith", "svc_backup", "admin", "guest", "mrogers"]
DEMO_IPS = ["10.0.0.14", "10.0.0.22", "192.168.1.101", "203.0.113.55", "198.51.100.7"]
DEMO_HOST = "WORKSTATION-07"


def _random_normal_event():
    choice = random.choice([
        (4624, "SuccessfulLogon"),
        (4688, "ProcessCreated"),
    ])
    return {
        "source": "Security",
        "event_id": choice[0],
        "event_type": choice[1],
        "user": random.choice(DEMO_USERS),
        "source_ip": random.choice(DEMO_IPS),
        "host": DEMO_HOST,
        "message": "notepad.exe" if choice[0] == 4688 else "Interactive logon",
    }


def _brute_force_burst():
    """Fire 6 failed logons fast, from one IP -> should trip the brute force rule."""
    target_user = random.choice(DEMO_USERS)
    attacker_ip = random.choice(DEMO_IPS)
    events = []
    for _ in range(6):
        events.append({
            "source": "Security",
            "event_id": 4625,
            "event_type": "FailedLogon",
            "user": target_user,
            "source_ip": attacker_ip,
            "host": DEMO_HOST,
            "message": "Unknown username or bad password",
        })
    return events


def _privilege_escalation_sequence():
    """New user created, then immediately added to Administrators."""
    new_user = "svc_temp" + str(random.randint(100, 999))
    return [
        {"source": "Security", "event_id": 4720, "event_type": "UserCreated",
         "user": new_user, "source_ip": "", "host": DEMO_HOST, "message": "New local account created"},
        {"source": "Security", "event_id": 4732, "event_type": "AddedToAdminGroup",
         "user": new_user, "source_ip": "", "host": DEMO_HOST, "message": "Added to Administrators group"},
    ]


def _log_cleared_event():
    return [{
        "source": "Security", "event_id": 1102, "event_type": "LogCleared",
        "user": random.choice(DEMO_USERS), "source_ip": "", "host": DEMO_HOST,
        "message": "The audit log was cleared",
    }]


def _password_spray_burst():
    """One attacker IP tries a handful of DIFFERENT accounts -> password spray,
    not brute force (which is many attempts against ONE account)."""
    attacker_ip = random.choice(DEMO_IPS)
    targets = random.sample(DEMO_USERS, k=4)
    return [
        {"source": "Security", "event_id": 4625, "event_type": "FailedLogon",
         "user": u, "source_ip": attacker_ip, "host": DEMO_HOST,
         "message": "Unknown username or bad password"}
        for u in targets
    ]


def _usb_device_event():
    return [{
        "source": "Security", "event_id": 6416, "event_type": "USBDeviceInserted",
        "user": random.choice(DEMO_USERS), "source_ip": "", "host": DEMO_HOST,
        "message": "USB Mass Storage Device recognized",
    }]


def _scheduled_task_event():
    return [{
        "source": "Security", "event_id": 4698, "event_type": "ScheduledTaskCreated",
        "user": random.choice(DEMO_USERS), "source_ip": "", "host": DEMO_HOST,
        "message": "New scheduled task 'UpdateChecker' created",
    }]


def _service_installed_event():
    suspicious = random.random() < 0.4
    message = ("Service binary path: cmd.exe /c powershell -enc <base64>"
               if suspicious else "Service binary path: C:\\Program Files\\Backup\\backupsvc.exe")
    return [{
        "source": "System", "event_id": 7045, "event_type": "ServiceInstalled",
        "user": random.choice(DEMO_USERS), "source_ip": "", "host": DEMO_HOST,
        "message": message,
    }]


ANOMALY_USER = "asmith"
ANOMALY_BASELINE_IPS = ["10.0.0.22", "10.0.0.23"]


def seed_anomaly_baseline():
    """Backdates ~10 'normal' 9am-5pm logons for one user from their usual
    IPs, so the anomaly rules have a believable baseline to compare against.
    Called once at startup - without this, the anomaly rules would need
    days of real usage before they had enough history to ever fire."""
    from datetime import timedelta
    for days_ago in range(10, 0, -1):
        ts = (datetime.utcnow() - timedelta(days=days_ago)).replace(
            hour=random.randint(9, 17), minute=random.randint(0, 59), second=0, microsecond=0
        )
        save_event(
            source="Security", event_id=4624, event_type="SuccessfulLogon",
            user=ANOMALY_USER, source_ip=random.choice(ANOMALY_BASELINE_IPS),
            host=DEMO_HOST, message="Interactive logon", timestamp=ts.isoformat(),
        )


def _anomalous_logon():
    """A logon that breaks the baseline: 3 AM, from an IP never seen before.
    Should trip BOTH anomaly rules at once."""
    ts = datetime.utcnow().replace(hour=3, minute=random.randint(0, 59))
    return [{
        "source": "Security", "event_id": 4624, "event_type": "SuccessfulLogon",
        "user": ANOMALY_USER, "source_ip": "185.220.101.7",  # unfamiliar IP
        "host": DEMO_HOST, "message": "Interactive logon",
        "timestamp": ts.isoformat(),
    }]


def run_demo_generator(interval_seconds=2, iterations=None):
    """
    Generates a steady stream of realistic events, occasionally injecting
    an attack pattern so the dashboard has real alerts to show.
    Run with `python collector.py demo`.
    """
    print("Seeding a 10-day baseline of normal logons for the anomaly demo...")
    seed_anomaly_baseline()

    print(f"Demo mode: generating simulated events every {interval_seconds}s. Ctrl+C to stop.")
    count = 0
    while iterations is None or count < iterations:
        roll = random.random()
        if roll < 0.06:
            batch = _brute_force_burst()
        elif roll < 0.11:
            batch = _password_spray_burst()
        elif roll < 0.15:
            batch = _privilege_escalation_sequence()
        elif roll < 0.17:
            batch = _log_cleared_event()
        elif roll < 0.20:
            batch = _anomalous_logon()
        elif roll < 0.24:
            batch = _usb_device_event()
        elif roll < 0.27:
            batch = _scheduled_task_event()
        elif roll < 0.30:
            batch = _service_installed_event()
        else:
            batch = [_random_normal_event()]

        for event in batch:
            entry, alerts = save_event(**event)
            print(f"[LOG] {entry['event_type']} user={entry['user']}")
            for a in alerts:
                print(f"   -> ALERT [{a['severity']}] {a['rule_name']}: {a['description']}")

        count += 1
        time.sleep(interval_seconds)


if __name__ == "__main__":
    import sys
    db.init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        run_demo_generator()
    else:
        collect_windows_events()
