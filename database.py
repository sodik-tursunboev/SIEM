"""
database.py
------------
Handles all storage for the mini SIEM using SQLite (a single file database,
zero configuration needed). Two tables:
  - logs:   every raw event we collected
  - alerts: anything our detection rules flagged as suspicious
"""

import sqlite3
import os
from datetime import datetime, timedelta

import paths
DB_PATH = paths.data_path("siem.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


def init_db():
    """Create tables if they don't already exist. Safe to call every startup."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS bas_test_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id TEXT NOT NULL,
            technique_name TEXT,
            atomic_test_name TEXT,
            atomic_test_guid TEXT,
            host TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            status TEXT DEFAULT 'Running',
            matched_alert_id INTEGER,
            detected_at TEXT,
            detection_latency_seconds INTEGER,
            notes TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,        -- e.g. Security, System, Application
            event_id INTEGER,
            event_type TEXT,             -- e.g. FailedLogon, ProcessCreated
            user TEXT,
            source_ip TEXT,
            host TEXT,
            message TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,      -- Low, Medium, High, Critical
            description TEXT,
            related_user TEXT,
            related_ip TEXT,
            log_id INTEGER,
            mitre_id TEXT,                -- e.g. "T1110"
            mitre_technique TEXT,         -- e.g. "Brute Force"
            status TEXT DEFAULT 'New',    -- New, Acknowledged, Resolved
            FOREIGN KEY (log_id) REFERENCES logs (id)
        )
    """)

    # Migration: if someone already has an older siem.db from before MITRE
    # tagging / status tracking was added, add the missing columns instead
    # of erroring out.
    existing_cols = {row["name"] for row in cur.execute("PRAGMA table_info(alerts)")}
    if "mitre_id" not in existing_cols:
        cur.execute("ALTER TABLE alerts ADD COLUMN mitre_id TEXT")
    if "mitre_technique" not in existing_cols:
        cur.execute("ALTER TABLE alerts ADD COLUMN mitre_technique TEXT")
    if "status" not in existing_cols:
        cur.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'New'")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS soar_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_id INTEGER,
            rule_name TEXT,
            action_type TEXT NOT NULL,     -- block_ip, disable_user
            target TEXT NOT NULL,          -- the IP or username
            status TEXT NOT NULL,          -- Pending, Executed, Failed, Rejected, Blocked
            reason TEXT,
            executed_by TEXT,
            executed_at TEXT,
            result_message TEXT,
            FOREIGN KEY (alert_id) REFERENCES alerts (id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS rule_registry (
            rule_key TEXT PRIMARY KEY,     -- stable id, matches the Python function name
            display_name TEXT NOT NULL,
            severity TEXT NOT NULL,        -- typical/default severity (some rules vary per-hit)
            mitre_id TEXT,
            mitre_technique TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            hit_count INTEGER NOT NULL DEFAULT 0,
            last_triggered TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT NOT NULL,      -- 'user' or 'ip'
            entity_value TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            alert_count INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Active',   -- Active, Reviewed, Dismissed
            case_number TEXT                          -- set once a case is created from this chain
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chain_alerts (
            chain_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            PRIMARY KEY (chain_id, alert_id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip TEXT,
            success INTEGER NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS saved_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            query_text TEXT NOT NULL,
            is_builtin INTEGER NOT NULL DEFAULT 0,
            created_by TEXT,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE,        -- "INC-001" - set right after insert, from id
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'Open',       -- Open, In Progress, Resolved, Closed
            priority TEXT NOT NULL DEFAULT 'Medium',   -- Low, Medium, High, Critical
            assigned_to TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolution TEXT,
            resolved_at TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            note_text TEXT NOT NULL,
            author TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases (id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS case_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_type TEXT NOT NULL,   -- alert, log, note
            reference_id INTEGER,          -- alert_id or log_id, when applicable
            description TEXT NOT NULL,
            added_by TEXT,
            added_at TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases (id)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Viewer',   -- Admin, Analyst, Viewer
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT NOT NULL,        -- the IP / domain / username / hash itself
            ioc_type TEXT NOT NULL,         -- ip, domain, user, hash
            description TEXT,
            added_by TEXT,
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS asset_meta (
            hostname TEXT PRIMARY KEY,
            criticality TEXT DEFAULT 'Medium',   -- Low, Medium, High, Critical
            owner TEXT,
            notes TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_log(entry: dict) -> int:
    """Insert one collected log event. Returns the new row's id."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO logs (timestamp, source, event_id, event_type, user, source_ip, host, message)
        VALUES (:timestamp, :source, :event_id, :event_type, :user, :source_ip, :host, :message)
    """, entry)
    conn.commit()
    log_id = cur.lastrowid
    conn.close()
    return log_id


def insert_alert(entry: dict) -> int:
    entry = {
        "mitre_id": None,
        "mitre_technique": None,
        **entry,  # entry's own values win if present
    }
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO alerts (timestamp, rule_name, severity, description, related_user,
                             related_ip, log_id, mitre_id, mitre_technique)
        VALUES (:timestamp, :rule_name, :severity, :description, :related_user,
                :related_ip, :log_id, :mitre_id, :mitre_technique)
    """, entry)
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()
    return alert_id


def get_recent_logs(limit=50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(limit=50):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_alert_status(alert_id: int, status: str):
    if status not in ("New", "Acknowledged", "Resolved"):
        raise ValueError(f"Invalid status: {status}")
    conn = get_connection()
    conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    conn.commit()
    conn.close()


def insert_soar_action(entry: dict) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO soar_actions (timestamp, alert_id, rule_name, action_type, target,
                                   status, reason, executed_by, executed_at, result_message)
        VALUES (:timestamp, :alert_id, :rule_name, :action_type, :target,
                :status, :reason, :executed_by, :executed_at, :result_message)
    """, entry)
    conn.commit()
    action_id = cur.lastrowid
    conn.close()
    return action_id


def get_soar_action(action_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM soar_actions WHERE id = ?", (action_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_soar_action(action_id: int, fields: dict):
    conn = get_connection()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE soar_actions SET {set_clause} WHERE id = ?", (*fields.values(), action_id))
    conn.commit()
    conn.close()


def list_soar_actions(limit: int = 100):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM soar_actions ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def ensure_rule_registered(rule_key, display_name, severity, mitre_id, mitre_technique):
    """Upserts a rule's metadata into the registry, WITHOUT touching its
    enabled/hit_count/last_triggered if it already exists - this is called
    on every startup for every known rule, so it must be safe to call
    repeatedly without resetting an analyst's enable/disable choice or
    hit history."""
    conn = get_connection()
    existing = conn.execute("SELECT rule_key FROM rule_registry WHERE rule_key = ?", (rule_key,)).fetchone()
    if existing:
        conn.execute(
            "UPDATE rule_registry SET display_name=?, severity=?, mitre_id=?, mitre_technique=? WHERE rule_key=?",
            (display_name, severity, mitre_id, mitre_technique, rule_key)
        )
    else:
        conn.execute(
            "INSERT INTO rule_registry (rule_key, display_name, severity, mitre_id, mitre_technique, enabled, hit_count) "
            "VALUES (?, ?, ?, ?, ?, 1, 0)",
            (rule_key, display_name, severity, mitre_id, mitre_technique)
        )
    conn.commit()
    conn.close()


def is_rule_enabled(rule_key: str) -> bool:
    """Defaults to True (enabled) if the rule isn't in the registry yet -
    a rule should never silently stop firing just because it hasn't been
    registered, e.g. on a fresh database before startup registration runs."""
    conn = get_connection()
    row = conn.execute("SELECT enabled FROM rule_registry WHERE rule_key = ?", (rule_key,)).fetchone()
    conn.close()
    if row is None:
        return True
    return bool(row["enabled"])


def set_rule_enabled(rule_key: str, enabled: bool):
    conn = get_connection()
    conn.execute("UPDATE rule_registry SET enabled = ? WHERE rule_key = ?", (1 if enabled else 0, rule_key))
    conn.commit()
    conn.close()


def record_rule_hit(rule_key: str, timestamp: str):
    conn = get_connection()
    conn.execute(
        "UPDATE rule_registry SET hit_count = hit_count + 1, last_triggered = ? WHERE rule_key = ?",
        (timestamp, rule_key)
    )
    conn.commit()
    conn.close()


def list_rule_registry():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM rule_registry ORDER BY display_name ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------
# Case Management
# ---------------------------------------------------------------------

def create_case(title, description, priority, assigned_to, created_by):
    """Case numbers (INC-001, INC-002...) are derived from the row's own
    autoincrement id, set right after insert - this guarantees uniqueness
    and a monotonically increasing sequence without a separate counter
    table or race conditions, even if a case is later deleted."""
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO cases (title, description, status, priority, assigned_to, created_by, created_at, updated_at)
        VALUES (?, ?, 'Open', ?, ?, ?, ?, ?)
    """, (title, description, priority, assigned_to, created_by, now, now))
    case_id = cur.lastrowid
    case_number = f"INC-{case_id:03d}"
    cur.execute("UPDATE cases SET case_number = ? WHERE id = ?", (case_number, case_id))
    conn.commit()
    conn.close()
    return case_id, case_number


def list_cases(status=None, priority=None, assigned_to=None):
    conditions = []
    params = []
    if status:
        conditions.append("status = ?")
        params.append(status)
    if priority:
        conditions.append("priority = ?")
        params.append(priority)
    if assigned_to:
        conditions.append("assigned_to = ?")
        params.append(assigned_to)
    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = get_connection()
    rows = conn.execute(f"SELECT * FROM cases {where_clause} ORDER BY id DESC", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_case(case_number: str):
    conn = get_connection()
    row = conn.execute("SELECT * FROM cases WHERE case_number = ?", (case_number,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_case_by_id(case_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_case(case_id: int, fields: dict):
    """fields can include: status, priority, assigned_to, resolution.
    updated_at is always bumped; resolved_at is set automatically the
    first time status moves to Resolved or Closed."""
    fields = dict(fields)
    fields["updated_at"] = datetime.utcnow().isoformat()

    if fields.get("status") in ("Resolved", "Closed"):
        current = get_case_by_id(case_id)
        if current and not current.get("resolved_at"):
            fields["resolved_at"] = datetime.utcnow().isoformat()

    conn = get_connection()
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    conn.execute(f"UPDATE cases SET {set_clause} WHERE id = ?", (*fields.values(), case_id))
    conn.commit()
    conn.close()


def add_case_note(case_id: int, note_text: str, author: str):
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    conn.execute(
        "INSERT INTO case_notes (case_id, note_text, author, created_at) VALUES (?, ?, ?, ?)",
        (case_id, note_text, author, now)
    )
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
    conn.commit()
    conn.close()


def list_case_notes(case_id: int):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM case_notes WHERE case_id = ? ORDER BY id ASC", (case_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_case_evidence(case_id: int, evidence_type: str, reference_id, description: str, added_by: str):
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    conn.execute(
        "INSERT INTO case_evidence (case_id, evidence_type, reference_id, description, added_by, added_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, evidence_type, reference_id, description, added_by, now)
    )
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
    conn.commit()
    conn.close()


def list_case_evidence(case_id: int):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM case_evidence WHERE case_id = ? ORDER BY id ASC", (case_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------
# Login brute-force protection
# ---------------------------------------------------------------------

LOGIN_LOCKOUT_THRESHOLD = 5     # failed attempts...
LOGIN_LOCKOUT_WINDOW_MINUTES = 15   # ...within this many minutes...
LOGIN_LOCKOUT_DURATION_MINUTES = 15  # ...locks the username for this long

# Per-SOURCE-IP limit, deliberately separate from the per-username lockout
# above. They defend against different attacks and neither substitutes for
# the other:
#
#   Per-username lockout stops BRUTE FORCE - many passwords against one
#   account. It is useless against password spraying, where an attacker
#   tries ONE common password against hundreds of usernames: no single
#   account ever reaches 5 failures, so nothing ever locks, and the
#   attacker walks through the whole user list unimpeded.
#
#   Per-IP limiting stops SPRAYING - many accounts from one source. It
#   counts failures by origin regardless of which username was targeted.
#
# The IP threshold is set higher than the username one on purpose. Several
# legitimate users can share one address behind NAT or a corporate egress,
# and a handful of genuine typos between them should not lock out the
# building.
LOGIN_IP_THRESHOLD = 15
LOGIN_IP_WINDOW_MINUTES = 15


def get_recent_failed_login_count_by_ip(ip: str, minutes: int = LOGIN_IP_WINDOW_MINUTES) -> int:
    """Failed attempts from one source address, across ALL usernames."""
    if not ip:
        return 0
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) c FROM login_attempts WHERE ip = ? AND success = 0 AND timestamp >= ?",
        (ip, since)
    ).fetchone()
    conn.close()
    return row["c"]


def is_ip_rate_limited(ip: str) -> bool:
    """Sliding window, self-healing exactly like the username lockout:
    once enough time passes for old failures to fall out of the window,
    the address is allowed again with no manual unlock."""
    return get_recent_failed_login_count_by_ip(ip) >= LOGIN_IP_THRESHOLD

def record_login_attempt(username: str, ip: str, success: bool):
    conn = get_connection()
    conn.execute(
        "INSERT INTO login_attempts (username, ip, success, timestamp) VALUES (?, ?, ?, ?)",
        (username, ip, 1 if success else 0, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def get_recent_failed_login_count(username: str, minutes: int = LOGIN_LOCKOUT_WINDOW_MINUTES) -> int:
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) c FROM login_attempts WHERE username = ? AND success = 0 AND timestamp >= ?",
        (username, since)
    ).fetchone()
    conn.close()
    return row["c"]


def is_username_locked(username: str) -> bool:
    """Sliding-window lockout: once LOGIN_LOCKOUT_THRESHOLD failures happen
    within LOGIN_LOCKOUT_WINDOW_MINUTES, the username is locked - and
    stays locked as long as that many failures remain within the window.
    No separate 'unlock' step needed: it self-heals once enough time
    passes for the failure count to naturally drop below the threshold.

    Known, accepted tradeoff (shared by real account-lockout policies,
    not unique to this implementation): an attacker who knows a valid
    username can deliberately lock it out as a denial-of-service against
    the legitimate user. Mitigating that fully (e.g. smart lockout that
    distinguishes the real user's usual devices/locations) is out of
    scope for this project.
    """
    return get_recent_failed_login_count(username) >= LOGIN_LOCKOUT_THRESHOLD


# ---------------------------------------------------------------------
# Attack Chain Correlation
# ---------------------------------------------------------------------

CHAIN_CORRELATION_WINDOW_MINUTES = 60
CHAIN_CORRELATION_THRESHOLD = 3   # distinct rule_names for one entity = a chain

def get_alerts_for_entity(entity_type: str, entity_value: str, since: str):
    """All alerts touching this user or IP since the given ISO timestamp -
    the raw material correlation checks against to decide if multiple
    alerts add up to one coordinated attack."""
    column = "related_user" if entity_type == "user" else "related_ip"
    conn = get_connection()
    rows = conn.execute(
        f"SELECT * FROM alerts WHERE {column} = ? AND timestamp >= ? ORDER BY timestamp ASC",
        (entity_value, since)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def find_active_chain(entity_type: str, entity_value: str, since: str):
    """An 'active' chain for correlation purposes is one that's still
    recent - last_seen within the correlation window - so a brand new
    burst of activity doesn't get silently glued onto a stale chain from
    days ago just because it's technically still marked 'Active'."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM attack_chains WHERE entity_type = ? AND entity_value = ? "
        "AND status = 'Active' AND last_seen >= ? ORDER BY id DESC LIMIT 1",
        (entity_type, entity_value, since)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def create_chain(entity_type: str, entity_value: str, first_seen: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO attack_chains (entity_type, entity_value, first_seen, last_seen, alert_count, status) "
        "VALUES (?, ?, ?, ?, 0, 'Active')",
        (entity_type, entity_value, first_seen, first_seen)
    )
    chain_id = cur.lastrowid
    conn.commit()
    conn.close()
    return chain_id


def add_alert_to_chain(chain_id: int, alert_id: int, timestamp: str):
    conn = get_connection()
    # INSERT OR IGNORE: the composite primary key (chain_id, alert_id)
    # means re-linking an alert that's already part of this chain is a
    # harmless no-op instead of a crash - correlation checks can run
    # against overlapping alert sets without needing to pre-check first.
    cur = conn.execute("INSERT OR IGNORE INTO chain_alerts (chain_id, alert_id) VALUES (?, ?)", (chain_id, alert_id))
    if cur.rowcount > 0:
        conn.execute(
            "UPDATE attack_chains SET last_seen = ?, alert_count = alert_count + 1 WHERE id = ?",
            (timestamp, chain_id)
        )
    conn.commit()
    conn.close()


def list_chains(status: str = None):
    conditions = []
    params = []
    if status:
        conditions.append("status = ?")
        params.append(status)
    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    conn = get_connection()
    rows = conn.execute(f"SELECT * FROM attack_chains {where_clause} ORDER BY last_seen DESC", params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_chain(chain_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM attack_chains WHERE id = ?", (chain_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_chain_alerts(chain_id: int):
    """The actual alerts in a chain, joined from the linking table,
    ordered chronologically - showing an attack's real progression."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT alerts.* FROM alerts
        JOIN chain_alerts ON chain_alerts.alert_id = alerts.id
        WHERE chain_alerts.chain_id = ?
        ORDER BY alerts.timestamp ASC
    """, (chain_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_chain_status(chain_id: int, status: str, case_number: str = None):
    conn = get_connection()
    if case_number:
        conn.execute("UPDATE attack_chains SET status = ?, case_number = ? WHERE id = ?", (status, case_number, chain_id))
    else:
        conn.execute("UPDATE attack_chains SET status = ? WHERE id = ?", (status, chain_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------
# Saved Hunt Queries - like Elastic Discover's saved searches. A fixed
# set of built-ins gets seeded on startup (see ensure_builtin_queries,
# called from app.py), and analysts can save their own on top of those.
# ---------------------------------------------------------------------

def ensure_builtin_query(name: str, query_text: str):
    """Seeds one built-in saved query if a query with this exact name
    doesn't already exist - safe to call every startup without creating
    duplicates or overwriting a user's edits to their own same-named query."""
    conn = get_connection()
    existing = conn.execute(
        "SELECT id FROM saved_queries WHERE name = ? AND is_builtin = 1", (name,)
    ).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO saved_queries (name, query_text, is_builtin, created_by, created_at) "
            "VALUES (?, ?, 1, 'system', ?)",
            (name, query_text, datetime.utcnow().isoformat())
        )
        conn.commit()
    conn.close()


def list_saved_queries():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM saved_queries ORDER BY is_builtin DESC, name ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def create_saved_query(name: str, query_text: str, created_by: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO saved_queries (name, query_text, is_builtin, created_by, created_at) VALUES (?, ?, 0, ?, ?)",
        (name, query_text, created_by, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()


def get_saved_query(query_id: int):
    conn = get_connection()
    row = conn.execute("SELECT * FROM saved_queries WHERE id = ?", (query_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_saved_query(query_id: int):
    conn = get_connection()
    conn.execute("DELETE FROM saved_queries WHERE id = ?", (query_id,))
    conn.commit()
    conn.close()


def search_alerts(severity=None, status=None, mitre_id=None, search=None,
                   related_user=None, related_ip=None,
                   date_from=None, date_to=None, query=None, limit=50, offset=0):
    """
    Filtered + searchable alert lookup for the dashboard's filter bar and
    CSV export. All filters are optional and combine with AND.
    `query` is an optional KQL-style string (see query_lang.py) that gets
    combined with all the other filters via AND.
    Returns (rows, total_matching_count) - the total is needed so the UI
    can show "showing 50 of 214" even though only a page is returned.
    """
    conditions = []
    params = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if status:
        conditions.append("status = ?")
        params.append(status)
    if mitre_id:
        conditions.append("mitre_id = ?")
        params.append(mitre_id)
    if related_user:
        conditions.append("related_user = ?")
        params.append(related_user)
    if related_ip:
        conditions.append("related_ip = ?")
        params.append(related_ip)
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to)
    if search:
        conditions.append(
            "(rule_name LIKE ? OR description LIKE ? OR related_user LIKE ? OR related_ip LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like])
    if query:
        import query_lang
        q_sql, q_params = query_lang.parse_query(query, query_lang.ALERT_FIELDS)
        conditions.append(f"({q_sql})")
        params.extend(q_params)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = get_connection()
    total = conn.execute(f"SELECT COUNT(*) c FROM alerts {where_clause}", params).fetchone()["c"]
    rows = conn.execute(
        f"SELECT * FROM alerts {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def search_logs(source=None, event_type=None, search=None,
                 host=None, user=None, source_ip=None,
                 date_from=None, date_to=None, query=None, limit=50, offset=0):
    """Filtered + searchable log lookup, same shape as search_alerts.
    `query` is an optional KQL-style string combined via AND with the rest."""
    conditions = []
    params = []

    if source:
        conditions.append("source = ?")
        params.append(source)
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if host:
        conditions.append("host = ?")
        params.append(host)
    if user:
        conditions.append("user = ?")
        params.append(user)
    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to)
    if search:
        conditions.append(
            "(event_type LIKE ? OR user LIKE ? OR host LIKE ? OR source_ip LIKE ? OR message LIKE ?)"
        )
        like = f"%{search}%"
        params.extend([like, like, like, like, like])
    if query:
        import query_lang
        q_sql, q_params = query_lang.parse_query(query, query_lang.LOG_FIELDS)
        conditions.append(f"({q_sql})")
        params.extend(q_params)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    conn = get_connection()
    total = conn.execute(f"SELECT COUNT(*) c FROM logs {where_clause}", params).fetchone()["c"]
    rows = conn.execute(
        f"SELECT * FROM logs {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def get_logs_since(minutes: int):
    conn = get_connection()
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    rows = conn.execute("SELECT * FROM logs WHERE timestamp >= ? ORDER BY id ASC", (since,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_logon_history(user: str, event_id: int, before_log_id: int, limit: int = 200):
    """Past logons (by event type) for a specific user, used as the 'normal
    behavior' baseline for anomaly detection. Excludes the current event
    itself (before_log_id) so we're always comparing against history only."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM logs
        WHERE user = ? AND event_id = ? AND id < ?
        ORDER BY id DESC LIMIT ?
    """, (user, event_id, before_log_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerts_between(start_iso: str, end_iso: str):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp ASC",
        (start_iso, end_iso)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_logs_between(start_iso: str, end_iso: str):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM logs WHERE timestamp >= ? AND timestamp < ? ORDER BY timestamp ASC",
        (start_iso, end_iso)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    """Numbers the dashboard needs: totals, alert rate, severity breakdown."""
    conn = get_connection()
    total_logs = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    total_alerts = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"]

    one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    alerts_last_hour = conn.execute(
        "SELECT COUNT(*) c FROM alerts WHERE timestamp >= ?", (one_hour_ago,)
    ).fetchone()["c"]

    severity_rows = conn.execute(
        "SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"
    ).fetchall()
    severity_breakdown = {row["severity"]: row["c"] for row in severity_rows}

    # alert rate per 10-minute bucket for the last 2 hours (for the trend chart)
    since = (datetime.utcnow() - timedelta(hours=2)).isoformat()
    bucket_rows = conn.execute(
        "SELECT timestamp FROM alerts WHERE timestamp >= ? ORDER BY timestamp ASC", (since,)
    ).fetchall()
    conn.close()

    buckets = {}
    for row in bucket_rows:
        ts = datetime.fromisoformat(row["timestamp"])
        bucket_key = ts.strftime("%H:%M")[:4] + "0"  # round to 10-min bucket
        buckets[bucket_key] = buckets.get(bucket_key, 0) + 1

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "alerts_last_hour": alerts_last_hour,
        "severity_breakdown": severity_breakdown,
        "alert_rate_trend": buckets,
    }


# ---------------------------------------------------------------------
# Users / authentication / RBAC
# ---------------------------------------------------------------------

def create_user(username, password_hash, role="Viewer"):
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, password_hash, role, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def list_users():
    conn = get_connection()
    rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def count_users():
    conn = get_connection()
    c = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    conn.close()
    return c


def delete_user(user_id):
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def update_user_password(user_id, password_hash):
    conn = get_connection()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------
# IOC watchlist
# ---------------------------------------------------------------------

def add_ioc(indicator, ioc_type, description, added_by):
    conn = get_connection()
    conn.execute(
        "INSERT INTO iocs (indicator, ioc_type, description, added_by, created_at) VALUES (?, ?, ?, ?, ?)",
        (indicator, ioc_type, description, added_by, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def list_iocs():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM iocs ORDER BY id DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_ioc(ioc_id):
    conn = get_connection()
    conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    conn.commit()
    conn.close()


def get_all_ioc_values():
    """Flat {indicator: ioc_row} map, cheap to check new events against."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM iocs").fetchall()
    conn.close()
    return {r["indicator"]: dict(r) for r in rows}


def search_iocs_in_logs(indicator, limit=200):
    """Threat-hunting helper: find every log where this indicator shows up
    anywhere relevant (source IP, user, or message text)."""
    conn = get_connection()
    like = f"%{indicator}%"
    rows = conn.execute("""
        SELECT * FROM logs
        WHERE source_ip = ? OR user = ? OR host = ? OR message LIKE ?
        ORDER BY id DESC LIMIT ?
    """, (indicator, indicator, indicator, like, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------
# Asset inventory
# ---------------------------------------------------------------------

def get_assets_summary():
    """Every host we've ever seen logs from, with activity counts and
    editable metadata (criticality/owner/notes) joined in."""
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            l.host AS hostname,
            COUNT(*) AS log_count,
            MIN(l.timestamp) AS first_seen,
            MAX(l.timestamp) AS last_seen,
            COUNT(DISTINCT l.user) AS distinct_users
        FROM logs l
        WHERE l.host IS NOT NULL AND l.host != ''
        GROUP BY l.host
        ORDER BY last_seen DESC
    """).fetchall()

    alert_counts = {r["hostname"]: r["c"] for r in conn.execute("""
        SELECT l.host AS hostname, COUNT(*) c
        FROM alerts a JOIN logs l ON a.log_id = l.id
        WHERE l.host IS NOT NULL AND l.host != ''
        GROUP BY l.host
    """).fetchall()}

    meta_rows = {r["hostname"]: dict(r) for r in conn.execute("SELECT * FROM asset_meta").fetchall()}
    conn.close()

    assets = []
    for r in rows:
        d = dict(r)
        d["alert_count"] = alert_counts.get(d["hostname"], 0)
        meta = meta_rows.get(d["hostname"], {})
        d["criticality"] = meta.get("criticality", "Medium")
        d["owner"] = meta.get("owner", "")
        d["notes"] = meta.get("notes", "")
        assets.append(d)
    return assets


def upsert_asset_meta(hostname, criticality, owner, notes):
    conn = get_connection()
    conn.execute("""
        INSERT INTO asset_meta (hostname, criticality, owner, notes) VALUES (?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET criticality=excluded.criticality,
            owner=excluded.owner, notes=excluded.notes
    """, (hostname, criticality, owner, notes))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------

SEVERITY_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}


def get_risk_scores(days=7, top_n=15):
    """Simple, explainable risk score: sum of severity-weighted alerts in
    the last N days, per user and per host. Not a sophisticated model -
    just weighted frequency - but transparent enough to defend in an
    interview, which matters more for a portfolio piece than sophistication."""
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    conn = get_connection()

    user_rows = conn.execute("""
        SELECT related_user AS entity, severity, COUNT(*) c
        FROM alerts
        WHERE timestamp >= ? AND related_user IS NOT NULL AND related_user != '' AND related_user != 'UNKNOWN'
        GROUP BY related_user, severity
    """, (since,)).fetchall()

    host_rows = conn.execute("""
        SELECT l.host AS entity, a.severity AS severity, COUNT(*) c
        FROM alerts a JOIN logs l ON a.log_id = l.id
        WHERE a.timestamp >= ? AND l.host IS NOT NULL AND l.host != ''
        GROUP BY l.host, a.severity
    """, (since,)).fetchall()
    conn.close()

    def _score(rows):
        scores = {}
        breakdown = {}
        for r in rows:
            weight = SEVERITY_WEIGHT.get(r["severity"], 0) * r["c"]
            scores[r["entity"]] = scores.get(r["entity"], 0) + weight
            breakdown.setdefault(r["entity"], {}).setdefault(r["severity"], 0)
            breakdown[r["entity"]][r["severity"]] += r["c"]
        ranked = sorted(scores.items(), key=lambda x: -x[1])[:top_n]
        return [{"entity": e, "score": s, "breakdown": breakdown[e]} for e, s in ranked]

    return {"users": _score(user_rows), "hosts": _score(host_rows)}


# ---------------------------------------------------------------------
# Attack timeline (chronological view for one user or host)
# ---------------------------------------------------------------------

def get_timeline(entity_type, entity_value, limit=300):
    """Merged, chronological logs + alerts for one user or host - the
    'what actually happened, in order' view used for incident reconstruction."""
    conn = get_connection()
    if entity_type == "user":
        logs = conn.execute(
            "SELECT * FROM logs WHERE user = ? ORDER BY id DESC LIMIT ?", (entity_value, limit)
        ).fetchall()
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE related_user = ? ORDER BY id DESC LIMIT ?", (entity_value, limit)
        ).fetchall()
    else:  # host
        logs = conn.execute(
            "SELECT * FROM logs WHERE host = ? ORDER BY id DESC LIMIT ?", (entity_value, limit)
        ).fetchall()
        alerts = conn.execute("""
            SELECT a.* FROM alerts a JOIN logs l ON a.log_id = l.id
            WHERE l.host = ? ORDER BY a.id DESC LIMIT ?
        """, (entity_value, limit)).fetchall()
    conn.close()

    events = []
    for l in logs:
        d = dict(l)
        d["_kind"] = "log"
        events.append(d)
    for a in alerts:
        d = dict(a)
        d["_kind"] = "alert"
        events.append(d)
    events.sort(key=lambda e: e["timestamp"])
    return events


# ---------------------------------------------------------------------
# MITRE ATT&CK heatmap
# ---------------------------------------------------------------------

# Coarse tactic grouping for the technique IDs this project actually uses -
# not the full official ATT&CK matrix (that's ~14 tactics x 200+ techniques),
# just enough structure to make a meaningful heatmap out of what we detect.
MITRE_TACTIC_MAP = {
    "T1110": "Credential Access", "T1110.003": "Credential Access",
    "T1098": "Persistence", "T1136.001": "Persistence",
    "T1070.001": "Defense Evasion",
    "T1003": "Credential Access", "T1570": "Lateral Movement",
    "T1059.001": "Execution", "T1105": "Command and Control",
    "T1033": "Discovery",
    "T1200": "Initial Access",
    "T1053.005": "Persistence", "T1543.003": "Persistence",
    "T1490": "Impact",
    "T1078": "Defense Evasion",
    "T1548": "Privilege Escalation",
    "T1558.003": "Credential Access",
    "TA0043": "Reconnaissance",
}


def get_mitre_matrix():
    conn = get_connection()
    rows = conn.execute("""
        SELECT mitre_id, mitre_technique, COUNT(*) c
        FROM alerts WHERE mitre_id IS NOT NULL
        GROUP BY mitre_id, mitre_technique
    """).fetchall()
    conn.close()

    matrix = {}
    for r in rows:
        tactic = MITRE_TACTIC_MAP.get(r["mitre_id"], "Other")
        matrix.setdefault(tactic, []).append({
            "mitre_id": r["mitre_id"], "mitre_technique": r["mitre_technique"], "count": r["c"],
        })
    return matrix


# ---------------------------------------------------------------------
# BAS Detection Validation Engine
# ---------------------------------------------------------------------
# The core idea: every Atomic Red Team test run gets logged with a start
# and end time. After it ends, we look for an alert that (a) matches the
# same MITRE technique, on a hierarchy-aware basis so a test for T1003
# also credits an alert tagged T1003.001, (b) happened on the same host,
# and (c) landed within a reasonable window after the test ran. That's
# what turns "I ran some attacks" into an actual measured coverage
# report instead of a manual, error-prone eyeball check.

BAS_FAST_THRESHOLD_SECONDS = 60     # alert within this long after test end = "Detected"
BAS_GRACE_WINDOW_SECONDS = 300      # alert within this long = "Delayed"; nothing by then = eligible for "Missed"


def create_bas_test_run(technique_id: str, technique_name: str, atomic_test_name: str,
                         atomic_test_guid: str, host: str) -> int:
    conn = get_connection()
    cur = conn.cursor()
    started_at = datetime.utcnow().isoformat()
    cur.execute(
        "INSERT INTO bas_test_runs (technique_id, technique_name, atomic_test_name, atomic_test_guid, "
        "host, started_at, status) VALUES (?, ?, ?, ?, ?, ?, 'Running')",
        (technique_id, technique_name, atomic_test_name, atomic_test_guid, host, started_at)
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def end_bas_test_run(run_id: int):
    conn = get_connection()
    conn.execute(
        "UPDATE bas_test_runs SET ended_at = ?, status = 'Pending' WHERE id = ?",
        (datetime.utcnow().isoformat(), run_id)
    )
    conn.commit()
    conn.close()


def _technique_matches(alert_mitre_id: str, test_technique_id: str) -> bool:
    """Hierarchy-aware match: a test for the base technique (T1003) should
    credit an alert tagged with any of its sub-techniques (T1003.001), and
    vice versa - a test for a specific sub-technique should credit an
    alert tagged with just the base ID, since not every rule bothers
    tagging sub-technique granularity."""
    if not alert_mitre_id or not test_technique_id:
        return False
    a, t = alert_mitre_id.upper(), test_technique_id.upper()
    return a == t or a.startswith(t + ".") or t.startswith(a + ".")


def score_bas_test_run(run_id: int) -> dict:
    """Looks for a matching alert for one test run and updates its status.
    Safe to call multiple times - e.g. once right after the test ends
    (catches fast detections immediately) and again later via rescore
    (catches delayed ones, or finalizes a Missed verdict once the grace
    window has actually elapsed)."""
    conn = get_connection()
    run = conn.execute("SELECT * FROM bas_test_runs WHERE id = ?", (run_id,)).fetchone()
    if not run:
        conn.close()
        return {"error": "Test run not found"}
    run = dict(run)

    if run["status"] in ("Detected", "Delayed", "Missed"):
        conn.close()
        return run  # already finalized, nothing to do

    if not run["ended_at"]:
        conn.close()
        return run  # still running, nothing to score yet

    ended_at = datetime.fromisoformat(run["ended_at"])
    window_end = (ended_at + timedelta(seconds=BAS_GRACE_WINDOW_SECONDS)).isoformat()

    # Join to logs to scope the match to the same host the test actually ran on -
    # otherwise an unrelated alert elsewhere in the lab could falsely count as a hit.
    candidates = conn.execute("""
        SELECT alerts.* FROM alerts
        JOIN logs ON logs.id = alerts.log_id
        WHERE alerts.mitre_id IS NOT NULL
          AND alerts.timestamp >= ?
          AND alerts.timestamp <= ?
          AND logs.host = ?
        ORDER BY alerts.timestamp ASC
    """, (run["started_at"], window_end, run["host"])).fetchall()

    match = next((dict(a) for a in candidates if _technique_matches(a["mitre_id"], run["technique_id"])), None)

    if match:
        detected_at = datetime.fromisoformat(match["timestamp"])
        latency = (detected_at - ended_at).total_seconds()
        status = "Detected" if latency <= BAS_FAST_THRESHOLD_SECONDS else "Delayed"
        conn.execute(
            "UPDATE bas_test_runs SET status = ?, matched_alert_id = ?, detected_at = ?, "
            "detection_latency_seconds = ? WHERE id = ?",
            (status, match["id"], match["timestamp"], max(0, int(latency)), run_id)
        )
        conn.commit()
        run["status"] = status
        run["matched_alert_id"] = match["id"]
        run["detected_at"] = match["timestamp"]
        run["detection_latency_seconds"] = max(0, int(latency))
    elif datetime.utcnow().isoformat() > window_end:
        # Grace window has genuinely elapsed in real time with nothing found -
        # only now is it fair to call this a real miss, not a "haven't checked yet."
        conn.execute("UPDATE bas_test_runs SET status = 'Missed' WHERE id = ?", (run_id,))
        conn.commit()
        run["status"] = "Missed"
    # else: still within the grace window, stays "Pending" - too early to call it either way

    conn.close()
    return run


def rescore_pending_bas_runs():
    """Call periodically (or via a manual 'Rescore' button) to catch
    delayed detections and finalize misses once their grace window has
    actually passed - a single scoring pass right at test-end can't see
    either of those, since they both depend on time actually elapsing."""
    conn = get_connection()
    pending = conn.execute("SELECT id FROM bas_test_runs WHERE status = 'Pending'").fetchall()
    conn.close()
    return [score_bas_test_run(row["id"]) for row in pending]


def list_bas_test_runs(status: str = None):
    conditions, params = [], []
    if status:
        conditions.append("status = ?")
        params.append(status)
    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    conn = get_connection()
    rows = conn.execute(
        f"SELECT * FROM bas_test_runs {where_clause} ORDER BY started_at DESC", params
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_bas_coverage_summary():
    conn = get_connection()
    rows = conn.execute("SELECT status, COUNT(*) c FROM bas_test_runs GROUP BY status").fetchall()
    conn.close()
    counts = {r["status"]: r["c"] for r in rows}
    scored = counts.get("Detected", 0) + counts.get("Delayed", 0) + counts.get("Missed", 0)
    detected_total = counts.get("Detected", 0) + counts.get("Delayed", 0)
    coverage_pct = round((detected_total / scored) * 100, 1) if scored else None
    return {
        "detected": counts.get("Detected", 0),
        "delayed": counts.get("Delayed", 0),
        "missed": counts.get("Missed", 0),
        "pending": counts.get("Pending", 0),
        "running": counts.get("Running", 0),
        "coverage_pct": coverage_pct,
    }
