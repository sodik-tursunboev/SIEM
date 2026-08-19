"""
query_lang.py
-------------
A small, purpose-built query language for searching logs and alerts,
inspired by Elastic's KQL - not a full implementation of it, just the
part that's actually useful here: field:value pairs joined with AND/OR.

Supported syntax:
    eventid:4625
    username:administrator
    severity:Critical
    ip:192.168.1.5
    hostname:DC01
    eventid:4625 AND username:Administrator
    severity:Critical OR severity:High
    host:DC* (wildcard - matches DC01, DC02, etc.)
    username:"j doe" (quoted value for anything with spaces)

Deliberately NOT supported (kept simple on purpose): parentheses/nested
grouping, NOT/negation, range queries, regex. AND is evaluated with
higher precedence than OR if both appear, matching how SQL (and KQL)
naturally handles it - this is standard query-language behavior, not a
shortcut.

Two field maps exist because "the same word means a different column"
depending on what you're searching - severity only exists on alerts,
eventid only exists on logs, but username/ip apply to both (against a
different underlying column each).
"""

import re

LOG_FIELDS = {
    "eventid": "event_id", "event_id": "event_id",
    "username": "user", "user": "user",
    "ip": "source_ip", "source_ip": "source_ip",
    "hostname": "host", "host": "host",
    "source": "source",
    "eventtype": "event_type", "event_type": "event_type",
    "message": "message",
}

ALERT_FIELDS = {
    "severity": "severity",
    "username": "related_user", "user": "related_user",
    "ip": "related_ip", "source_ip": "related_ip",
    "rule": "rule_name", "rulename": "rule_name",
    "mitre": "mitre_id", "mitre_id": "mitre_id",
    "status": "status",
}

NUMERIC_FIELDS = {"event_id"}

_TOKEN_RE = re.compile(r'\S+:"[^"]*"|"[^"]*"|\S+')


class QueryError(ValueError):
    """Raised for anything the user typed that we can't turn into a query -
    caught by the API layer and returned as a clear 400 error message
    instead of silently doing the wrong thing."""
    pass


def parse_query(query_string: str, field_map: dict):
    """Returns (sql_where_fragment, params_list). Raises QueryError on
    anything malformed, with a message specific enough to actually help
    someone fix their query."""
    tokens = _TOKEN_RE.findall(query_string.strip())
    if not tokens:
        raise QueryError("Empty query.")

    sql_parts = []
    params = []
    expect_condition = True  # alternates: condition, connector, condition, ...

    for tok in tokens:
        if expect_condition:
            field_col, value = _parse_condition(tok, field_map)
            if field_col in NUMERIC_FIELDS:
                try:
                    params.append(int(value))
                except ValueError:
                    raise QueryError(f"'{value}' isn't a valid number for field '{tok.split(':')[0]}'.")
                sql_parts.append(f"{field_col} = ?")
            elif "*" in value:
                params.append(value.replace("*", "%"))
                sql_parts.append(f"LOWER({field_col}) LIKE LOWER(?)")
            else:
                params.append(value)
                sql_parts.append(f"LOWER({field_col}) = LOWER(?)")
            expect_condition = False
        else:
            connector = tok.upper()
            if connector not in ("AND", "OR"):
                raise QueryError(
                    f"Expected AND or OR between conditions, got '{tok}'. "
                    f"Example: eventid:4625 AND username:Administrator"
                )
            sql_parts.append(connector)
            expect_condition = True

    if expect_condition:
        raise QueryError("Query ends with a dangling AND/OR - remove the trailing connector.")

    return " ".join(sql_parts), params


def _parse_condition(token: str, field_map: dict):
    if ":" not in token:
        raise QueryError(
            f"'{token}' isn't a valid condition - expected field:value, e.g. eventid:4625. "
            f"Valid fields here: {', '.join(sorted(set(field_map.keys())))}"
        )
    field, _, value = token.partition(":")
    field = field.strip().lower()
    value = value.strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value:
        raise QueryError(f"'{token}' is missing a value after the colon.")
    if field not in field_map:
        raise QueryError(
            f"Unknown field '{field}'. Valid fields here: {', '.join(sorted(set(field_map.keys())))}"
        )
    return field_map[field], value
