"""
forwarder.py
------------
Runs ON a remote Windows machine (your Server 2022 VM, Windows Enterprise
VM, etc.) - NOT on your main SIEM machine. Reads that machine's own
Windows Event Log (Security, System, and Sysmon's Operational channel)
and forwards each event over HTTP to your main SIEM's ingest endpoint,
where it goes through the exact same detection pipeline as locally-
collected events.

This is a single, standalone file on purpose - copy just this one file to
each VM. It doesn't need the rest of the SIEM project there.

SETUP ON EACH REMOTE WINDOWS MACHINE:
  1. Install Python 3.10+ if not already there.
  2. pip install requests   (pywin32 not required - this uses PowerShell)
  3. Set two environment variables (get the key from your main SIEM's
     startup log, or ingest_key.txt in its project folder):

       set SIEM_URL=http://<your-main-windows-IP>:5000
       set SIEM_INGEST_KEY=<the key from ingest_key.txt>

  4. Run as Administrator (needed to read the Security log):
       python forwarder.py

  5. Watch the console - it prints every event it sends and the SIEM's
     response, so you can immediately see if forwarding is working.

CRITICAL DESIGN NOTE - SYSMON EVENT ID REMAPPING:
Sysmon uses its own event numbering scheme (1-25ish) that's completely
separate from Windows' native Security/System event IDs. But every
process-related detection rule on the SIEM side (rule_suspicious_process,
rule_suspicious_powershell - the exact rules that catch Atomic Red Team
process-execution tests) is written to check for event_id == 4688, the
native Windows "a process was created" ID. If Sysmon's ProcessCreate
(raw ID 1) gets forwarded as-is, those rules silently never match it -
not because the detection logic is wrong, but because the event never
even reaches it under an ID it recognizes. This was a real, confirmed
bug in an earlier version of this file: logs arrived and stored
correctly, message text had the exact attack pattern in it, and
alerts_triggered still came back 0 every time, purely because of this
ID mismatch.

The fix: Sysmon Event ID 1 (ProcessCreate) gets deliberately remapped to
event_id 4688 / event_type "ProcessCreated" before sending - matching the
exact same convention used by this project's local collector.py for
Sysmon collection, so forwarded and locally-collected Sysmon data behave
identically once they reach the SIEM.

WHY EVERYTHING GOES THROUGH POWERSHELL / Get-WinEvent:
Get-WinEvent's raw XML, parsed field-by-field, reliably hands back exact
named field values (CommandLine, TargetUserName, etc.) for every event
source - including modern manifest-based events like Security-Auditing
4688 with command-line auditing enabled, and Sysmon's structured
EventData. This avoids needing pywin32 at all.

To test connectivity BEFORE setting up continuous forwarding, this script
pings the SIEM's /api/ingest/ping endpoint first and tells you clearly if
it can't reach it or the key is wrong.
"""

import os
import sys
import json
import time
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import requests

SIEM_URL = os.environ.get("SIEM_URL", "").rstrip("/")
INGEST_KEY = os.environ.get("SIEM_INGEST_KEY", "")
POLL_SECONDS = int(os.environ.get("SIEM_POLL_SECONDS", "10"))

# Each entry: (friendly log name, actual channel name as Get-WinEvent expects it)
LOG_SOURCES = [
    ("Security", "Security"),
    ("System", "System"),
    ("Sysmon", "Microsoft-Windows-Sysmon/Operational"),
]

# Event IDs we actually care about, and a friendly name for each - shared
# across Security/System/Sysmon since the IDs don't collide in practice
# (Sysmon's own 1-25 range vs. Security/System's 4-and-6-digit IDs).
#
# NOTE: Sysmon ID 1 (ProcessCreate) is intentionally NOT given a
# "SysmonProcessCreate" label here - see SYSMON_REMAP below. It's handled
# as a special case so it reaches the SIEM as event_id 4688, matching
# what rule_suspicious_process / rule_suspicious_powershell check for.
EVENT_TYPE_MAP = {
    # Security / System (classic Windows auditing)
    4624: "SuccessfulLogon", 4625: "FailedLogon", 4740: "AccountLockout",
    4720: "UserCreated", 4732: "AddedToAdminGroup", 4688: "ProcessCreated",
    1102: "LogCleared", 6416: "USBDeviceInserted", 4698: "ScheduledTaskCreated",
    7045: "ServiceInstalled", 4768: "KerberosAuthTicketRequested", 4769: "KerberosServiceTicketRequested",
    # Sysmon Operational (ID 1 handled separately - see SYSMON_REMAP)
    2: "SysmonFileCreateTime", 3: "SysmonNetworkConnect",
    5: "SysmonProcessTerminate", 6: "SysmonDriverLoad", 7: "SysmonImageLoad",
    8: "SysmonCreateRemoteThread", 9: "SysmonRawAccessRead", 10: "SysmonProcessAccess",
    11: "SysmonFileCreate", 12: "SysmonRegistryCreateDelete", 13: "SysmonRegistryValueSet",
    14: "SysmonRegistryRename", 15: "SysmonFileCreateStreamHash", 17: "SysmonPipeCreated",
    18: "SysmonPipeConnected", 22: "SysmonDnsQuery", 23: "SysmonFileDelete",
    24: "SysmonClipboardChange", 25: "SysmonProcessTampering",
}

# Sysmon event IDs that get remapped to a Windows-native equivalent ID
# before being sent, so existing detection rules (written against native
# Windows event IDs) fire against Sysmon-sourced data without needing
# their own Sysmon-specific copy of every rule. Currently just
# ProcessCreate -> 4688 (ProcessCreated), since that's what
# rule_suspicious_process/rule_suspicious_powershell key off of, and it's
# the one that matters most for Atomic Red Team-style process execution
# tests. (Sysmon 10/ProcessAccess is deliberately NOT remapped here - see
# EVENT_TYPE_MAP above - since "a process accessed another process" is a
# conceptually different event from "a process was created", and the
# LSASS Access hunt query already finds it fine via message content.)
SYSMON_REMAP = {
    1: (4688, "ProcessCreated"),   # Sysmon ProcessCreate -> Windows-native ProcessCreated
}

# Candidate XML field names to try, in priority order, for each output
# field we send to the SIEM. Named EventData fields differ by event type,
# so we just take the first one that's actually present on this event.
USER_FIELD_CANDIDATES = [
    "TargetUserName", "SubjectUserName", "AccountName", "MemberName", "User", "UserName",
]
IP_FIELD_CANDIDATES = ["IpAddress", "SourceIp", "DestinationIp", "SourceAddress"]

# Fields worth surfacing in the human-readable "message" string when
# present - this is what detection rules' substring matching (mimikatz,
# -enc, etc.) actually searches, so the more of these we include, the
# more real detection content is available to match against.
MESSAGE_FIELD_CANDIDATES = [
    "CommandLine", "NewProcessName", "ProcessName", "Image", "ParentImage",
    "TargetFilename", "ObjectName", "ServiceFileName", "ServiceName",
    "TaskName", "DestinationIp", "DestinationPort", "QueryName",
    "TargetUserName", "SubjectUserName", "ShareName", "RelativeTargetName",
    "GrantedAccess", "TargetImage", "SourceImage", "StartAddress",
]

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _extract_fields(xml_text):
    """Pull every <Data Name=...>value</Data> field out of an event's XML
    into a plain dict, e.g. {'CommandLine': '...', 'TargetUserName': '...'}."""
    fields = {}
    try:
        root = ET.fromstring(xml_text)
        event_data = root.find(f"{_NS}EventData")
        if event_data is not None:
            for data in event_data.findall(f"{_NS}Data"):
                name = data.get("Name")
                if name:
                    fields[name] = (data.text or "").strip()
    except ET.ParseError:
        pass
    return fields


def _first_present(fields, candidates):
    for name in candidates:
        val = fields.get(name)
        if val and val != "-":
            return val
    return ""


def _build_message(fields):
    bits = []
    for name in MESSAGE_FIELD_CANDIDATES:
        val = fields.get(name)
        if val and val != "-":
            bits.append(f"{name}={val}")
    return " | ".join(bits) if bits else "(no structured fields on this event)"


def send_event(payload):
    try:
        r = requests.post(
            f"{SIEM_URL}/api/ingest/event",
            headers={"X-SIEM-Key": INGEST_KEY, "Content-Type": "application/json"},
            json=payload, timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            print(f"[SENT] {payload['event_type']} (id={payload['event_id']}) user={payload['user']} "
                  f"-> log_id={data['log_id']}, alerts={data['alerts_triggered']}")
        else:
            print(f"[REJECTED by SIEM] {r.status_code}: {r.text[:200]}")
    except requests.RequestException as e:
        print(f"[NETWORK ERROR] Couldn't reach {SIEM_URL}: {e}")


def check_connectivity():
    print(f"Checking connectivity to {SIEM_URL} ...")
    try:
        r = requests.get(f"{SIEM_URL}/api/ingest/ping", headers={"X-SIEM-Key": INGEST_KEY}, timeout=10)
        if r.status_code == 200:
            print("Connected. Key accepted. Starting forwarding.\n")
            return True
        elif r.status_code == 401:
            print("Reached the SIEM, but the key was rejected. Check SIEM_INGEST_KEY matches "
                  "ingest_key.txt on the SIEM machine exactly.")
        else:
            print(f"Unexpected response: {r.status_code} {r.text[:200]}")
    except requests.RequestException as e:
        print(f"Could not reach {SIEM_URL} at all: {e}")
        print("Check: is the SIEM running with host='0.0.0.0'? Is Windows Firewall on the "
              "SIEM machine allowing port 5000? Can this VM even ping the SIEM machine's IP?")
    return False


# --- Polling via PowerShell / Get-WinEvent, used for ALL log sources -------

_PS_TEMPLATE = (
    "$ErrorActionPreference='SilentlyContinue'; "
    "$events = Get-WinEvent -FilterHashtable @{{LogName='{channel}'; StartTime='{start}'}}; "
    "$events | ForEach-Object {{ [PSCustomObject]@{{ RecordId=$_.RecordId; Id=$_.Id; "
    "TimeCreated=$_.TimeCreated.ToString('o'); Xml=$_.ToXml() }} }} | ConvertTo-Json -Compress -Depth 3"
)


def _run_powershell_json(command):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, timeout=30,
    )
    out = (result.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data


def _init_state():
    # Start from "now" (in LOCAL time, not UTC - see note in _poll_channel)
    # so we only forward events from this point onward.
    return datetime.now().astimezone().isoformat(), 0


def _poll_channel(friendly_name, channel, last_start_iso, last_max_record_id):
    command = _PS_TEMPLATE.format(channel=channel, start=last_start_iso)
    try:
        events = _run_powershell_json(command)
    except Exception as e:
        print(f"[{friendly_name} POLL ERROR] {e}")
        return last_start_iso, last_max_record_id

    if not events:
        return last_start_iso, last_max_record_id

    newest_time = last_start_iso
    newest_record = last_max_record_id

    # Get-WinEvent returns newest-first by default; process oldest-first so
    # log_id ordering in the SIEM roughly matches real chronology.
    for ev in reversed(events):
        record_id = ev.get("RecordId") or 0
        if record_id and record_id <= last_max_record_id:
            continue

        event_id = ev.get("Id")
        time_created = ev.get("TimeCreated") or newest_time

        # Sysmon events needing remapping to a Windows-native ID (see
        # SYSMON_REMAP docstring above) get checked first, since they
        # wouldn't otherwise be found in EVENT_TYPE_MAP under their raw
        # Sysmon ID at all.
        if friendly_name == "Sysmon" and event_id in SYSMON_REMAP:
            out_event_id, out_event_type = SYSMON_REMAP[event_id]
        elif event_id in EVENT_TYPE_MAP:
            out_event_id, out_event_type = event_id, EVENT_TYPE_MAP[event_id]
        else:
            if record_id:
                newest_record = max(newest_record, record_id)
            newest_time = time_created
            continue

        fields = _extract_fields(ev.get("Xml", ""))

        payload = {
            "source": friendly_name,
            "event_id": out_event_id,
            "event_type": out_event_type,
            "user": _first_present(fields, USER_FIELD_CANDIDATES),
            "source_ip": _first_present(fields, IP_FIELD_CANDIDATES),
            "host": platform.node(),
            "message": _build_message(fields)[:500],
        }
        send_event(payload)

        if record_id:
            newest_record = max(newest_record, record_id)
        newest_time = time_created

    return newest_time, newest_record


def main():
    if not SIEM_URL or not INGEST_KEY:
        print("Set SIEM_URL and SIEM_INGEST_KEY environment variables first. See the docstring "
              "at the top of this file for exact commands.")
        sys.exit(1)

    if not check_connectivity():
        sys.exit(1)

    state = {friendly: _init_state() for friendly, _ in LOG_SOURCES}

    print(f"Forwarding from {platform.node()} to {SIEM_URL} "
          f"({', '.join(f for f, _ in LOG_SOURCES)}) - polling every {POLL_SECONDS}s. Ctrl+C to stop.")
    while True:
        for friendly, channel in LOG_SOURCES:
            last_time, last_record = state[friendly]
            state[friendly] = _poll_channel(friendly, channel, last_time, last_record)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
