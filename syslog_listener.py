"""
syslog_listener.py
-------------------
A minimal UDP syslog receiver (RFC 3164 style, which is what most Linux
daemons, routers, and firewalls send by default). This is what makes the
SIEM multi-source instead of Windows-only - point any device's syslog
target at this machine and its logs start flowing into the same pipeline,
same detection rules, same dashboard.

Binds to port 5514 by default, NOT the standard 514 - port 514 is a
"privileged" port below 1024, and binding it requires Administrator/root.
Using 5514 means this runs fine as a normal user. If you control the
sending device, point it at 5514. If you need to receive on the real
default port 514, run this specific process elevated and change the port.

Run standalone: python syslog_listener.py
Or launched automatically by app.py in a background thread.
"""

import socket
import re
import threading
from datetime import datetime

import database as db
import rules
import linux_rules

DEFAULT_PORT = 5514

# Loose RFC3164 parser: "<PRI>Mmm dd hh:mm:ss host tag[pid]: message"
SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^\s:\[]+)(?:\[\d+\])?:\s*"
    r"(?P<message>.*)$"
)

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
USER_RE = re.compile(r"\buser[= ]([\w.\-]+)", re.IGNORECASE)


def _parse_syslog_line(raw: str, sender_ip: str):
    raw = raw.strip()
    match = SYSLOG_RE.match(raw)

    if match:
        host = match.group("host")
        tag = match.group("tag")
        message = match.group("message")
    else:
        # Not standard RFC3164 (some devices send non-conformant text) -
        # fall back to storing the raw line so nothing gets silently dropped.
        host = sender_ip
        tag = "raw"
        message = raw

    ip_match = IP_RE.search(message)
    user_match = USER_RE.search(message)
    generic_user = user_match.group(1) if user_match else ""
    generic_ip = ip_match.group(1) if ip_match else sender_ip

    # No numeric Windows-style event ID exists for syslog - use a
    # consistent synthetic one so it still flows through the same pipeline.
    event_type = f"Syslog:{tag}"

    # Re-parse with daemon-specific patterns (sshd/sudo/su log lines don't
    # match the generic "user=X" regex above at all) - this is what makes
    # the Linux detection rules in linux_rules.py actually able to match.
    refined_user, refined_ip = linux_rules.refine_linux_fields(tag, message, generic_user, generic_ip)

    return {
        "source": "Syslog",
        "event_id": 0,
        "event_type": event_type,
        "user": refined_user,
        "source_ip": refined_ip,
        "host": host,
        "message": message[:500],
        "timestamp": datetime.utcnow().isoformat(),
    }


def _save_syslog_event(parsed):
    log_id = db.insert_log(parsed)
    parsed["id"] = log_id
    alerts = rules.evaluate(parsed)
    print(f"[SYSLOG] {parsed['host']} {parsed['event_type']}: {parsed['message'][:80]}")
    for a in alerts:
        print(f"   -> ALERT [{a['severity']}] {a['rule_name']}: {a['description']}")


def run_syslog_listener(port=DEFAULT_PORT, bind_addr="0.0.0.0"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((bind_addr, port))
    except OSError as e:
        print(f"[SYSLOG] Could not bind UDP port {port}: {e}")
        print("[SYSLOG] Syslog ingestion disabled for this run.")
        return

    print(f"[SYSLOG] Listening for syslog messages on UDP {bind_addr}:{port}")
    while True:
        try:
            data, addr = sock.recvfrom(8192)
            raw = data.decode("utf-8", errors="replace")
            parsed = _parse_syslog_line(raw, addr[0])
            _save_syslog_event(parsed)
        except Exception as e:
            print(f"[SYSLOG] Error handling packet: {e}")


def start_syslog_listener_thread(port=DEFAULT_PORT):
    thread = threading.Thread(target=run_syslog_listener, kwargs={"port": port}, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    import sys
    db.init_db()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    run_syslog_listener(port=port)
