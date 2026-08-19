"""
sigma_rules.py
--------------
Support for Sigma rules - the open, YAML-based, vendor-neutral detection
rule format used across the real SIEM industry (Splunk, Elastic, Sentinel,
Wazuh, Chronicle all support importing Sigma rules). Being able to say
"my SIEM supports Sigma" is a genuinely valuable line for a resume/interview
because it's a real, widely-recognized standard - not something invented
for this project.

This is a SIMPLIFIED Sigma interpreter, not a full implementation of the
spec (the full spec supports far more condition logic, aggregations, and
field modifiers than we need here). It supports the part of Sigma that
covers the vast majority of real-world detection rules:

    title: Some Detection Name
    id: <uuid>
    status: stable
    description: What this catches and why it matters
    logsource:
        category: authentication      # loosely matched against our event_type
    detection:
        selection:
            EventID: 4625
            field2: value2
        condition: selection
    level: high
    tags:
        - attack.credential_access
        - attack.t1110

Rules live as .yml files in the sigma_rules/ folder. Anything dropped in
there (by hand, or through the Sigma Rules page in the app) gets picked
up automatically - no code changes needed to add a new rule.
"""

import os
import glob
import yaml

import paths
RULES_DIR = paths.resource_path("sigma_rules")

# Maps a Sigma field name -> the matching key on our own log dict, since
# Sigma rules are usually written against raw Windows field names.
FIELD_ALIASES = {
    "EventID": "event_id",
    "TargetUserName": "user",
    "User": "user",
    "IpAddress": "source_ip",
    "SourceIp": "source_ip",
    "Workstation": "host",
    "ComputerName": "host",
    "CommandLine": "message",
    "Image": "message",
    "Channel": "source",
}

# Sigma technique tags look like "attack.t1110.003" - pull the ID back out
# in the format the rest of this app already uses ("T1110.003").
def _mitre_id_from_tags(tags):
    for tag in tags or []:
        t = tag.lower()
        if t.startswith("attack.t"):
            return t.replace("attack.", "").upper()
    return None


def _load_rule_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not data or "detection" not in data:
        return None
    data["_source_file"] = os.path.basename(path)
    return data


def load_rules():
    """Loads every .yml/.yaml file in sigma_rules/ fresh each time it's
    called - rules are re-read on every log event, which is a bit wasteful
    at high volume but means you can drop a new rule file in and it's
    active on the very next event with zero restart needed. Fine for a
    project at this scale; a production system would cache + watch the
    folder instead."""
    if not os.path.isdir(RULES_DIR):
        return []
    rules = []
    for path in sorted(glob.glob(os.path.join(RULES_DIR, "*.yml")) + glob.glob(os.path.join(RULES_DIR, "*.yaml"))):
        try:
            rule = _load_rule_file(path)
            if rule:
                rules.append(rule)
        except Exception as e:
            print(f"[SIGMA] Failed to load {path}: {e}")
    return rules


def _selection_matches(selection: dict, log: dict) -> bool:
    """A selection matches if EVERY field in it matches the log (AND logic
    within one selection block - this is standard Sigma behavior)."""
    for field, expected in selection.items():
        actual_field = FIELD_ALIASES.get(field, field.lower())
        actual_value = log.get(actual_field)

        if actual_value is None:
            return False

        # Sigma allows a list of acceptable values (OR within the field)
        expected_list = expected if isinstance(expected, list) else [expected]

        matched = False
        for exp in expected_list:
            exp_str = str(exp).lower()
            actual_str = str(actual_value).lower()
            # Sigma's '*wildcard*' convention -> substring match; otherwise exact
            if exp_str.startswith("*") and exp_str.endswith("*") and len(exp_str) > 1:
                matched = exp_str.strip("*") in actual_str
            elif str(exp).isdigit() or isinstance(exp, int):
                matched = str(actual_value) == str(exp)
            else:
                matched = exp_str in actual_str
            if matched:
                break
        if not matched:
            return False
    return True


def _rule_matches(rule: dict, log: dict) -> bool:
    """Evaluates the detection.condition against detection's selection
    blocks. Supports the common cases: a single selection, or
    'selection1 and selection2' / 'selection1 or selection2'. Anything
    fancier than that (aggregations like 'count() > 5', 'timeframe', etc.)
    is out of scope for this simplified interpreter - see the module
    docstring."""
    detection = rule.get("detection", {})
    condition = str(detection.get("condition", "")).strip().lower()
    selections = {k: v for k, v in detection.items() if k != "condition"}

    if not condition or condition not in _condition_selection_names(condition, selections):
        # Fallback: no recognizable condition - just require ALL selections to match.
        return all(_selection_matches(sel, log) for sel in selections.values() if isinstance(sel, dict))

    if " and " in condition:
        parts = [p.strip() for p in condition.split(" and ")]
        return all(_selection_matches(selections.get(p, {}), log) for p in parts if p in selections)
    if " or " in condition:
        parts = [p.strip() for p in condition.split(" or ")]
        return any(_selection_matches(selections.get(p, {}), log) for p in parts if p in selections)

    # Single selection name
    sel = selections.get(condition)
    if isinstance(sel, dict):
        return _selection_matches(sel, log)
    return False


def _condition_selection_names(condition, selections):
    """Helper so we don't crash on a condition string that doesn't map to
    any real selection name - just treat it as unrecognized."""
    names = set(selections.keys())
    tokens = condition.replace("(", " ").replace(")", " ").split()
    return names if any(t in names for t in tokens) or condition in names else set()


def evaluate_sigma(new_log: dict):
    """Checks a new log against every loaded Sigma rule. Returns the FIRST
    match as an alert dict (keeping this consistent with how every other
    rule in rules.py behaves - one function call, one alert max), or None.
    If a log could match multiple Sigma rules, the rest will still catch it
    on a future correlation or can be found via Threat Hunting search."""
    for rule in load_rules():
        try:
            if _rule_matches(rule, new_log):
                level_to_severity = {
                    "critical": "Critical", "high": "High",
                    "medium": "Medium", "low": "Low", "informational": "Low",
                }
                severity = level_to_severity.get(str(rule.get("level", "medium")).lower(), "Medium")
                mitre_id = _mitre_id_from_tags(rule.get("tags"))
                return {
                    "rule_name": f"[Sigma] {rule.get('title', rule['_source_file'])}",
                    "severity": severity,
                    "description": rule.get("description", "").strip() or "Matched a Sigma detection rule.",
                    "related_user": new_log.get("user"),
                    "related_ip": new_log.get("source_ip"),
                    "mitre_id": mitre_id,
                    "mitre_technique": rule.get("title") if mitre_id else None,
                }
        except Exception as e:
            print(f"[SIGMA] Error evaluating rule {rule.get('_source_file')}: {e}")
    return None


def list_loaded_rules():
    """Summary info for the Sigma Rules management page."""
    out = []
    for rule in load_rules():
        out.append({
            "file": rule["_source_file"],
            "title": rule.get("title", "(untitled)"),
            "level": rule.get("level", "medium"),
            "description": rule.get("description", ""),
            "tags": rule.get("tags", []),
            "condition": rule.get("detection", {}).get("condition", ""),
        })
    return out


def save_new_rule(yaml_text: str) -> str:
    """Validates and saves a Sigma rule submitted through the UI. Returns
    the filename it was saved as. Raises ValueError with a helpful message
    if the YAML is invalid or missing required fields."""
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")

    if not isinstance(data, dict):
        raise ValueError("Rule must be a YAML mapping (see the example rules for the expected shape).")
    if "title" not in data:
        raise ValueError("Rule is missing required field: title")
    if "detection" not in data or "condition" not in data.get("detection", {}):
        raise ValueError("Rule is missing required field: detection.condition")

    os.makedirs(RULES_DIR, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in data["title"]).lower()[:60]
    filename = f"custom_{safe_name}.yml"
    path = os.path.join(RULES_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(yaml_text)
    return filename


def delete_rule(filename: str):
    """Only allows deleting files inside RULES_DIR, and only .yml/.yaml -
    guards against a filename like '../../something' being used to delete
    an unrelated file on disk."""
    safe_filename = os.path.basename(filename)
    if not (safe_filename.endswith(".yml") or safe_filename.endswith(".yaml")):
        raise ValueError("Not a Sigma rule file.")
    path = os.path.join(RULES_DIR, safe_filename)
    if os.path.exists(path) and os.path.dirname(path) == RULES_DIR:
        os.remove(path)


# ---------------------------------------------------------------------
# Self-contained Flask Blueprint - same pattern as ai_summary.py, so
# wiring this in needs zero changes to app.py's own route logic. Only
# two lines needed there: import sigma_rules, then
# app.register_blueprint(sigma_rules.bp)
# ---------------------------------------------------------------------
from flask import Blueprint, request, jsonify, render_template
import auth

bp = Blueprint("sigma_rules", __name__)


@bp.route("/sigma")
@auth.login_required
def sigma_page():
    return render_template("sigma.html")


@bp.route("/api/sigma")
@auth.login_required
def api_list_sigma():
    return jsonify(list_loaded_rules())


@bp.route("/api/sigma", methods=["POST"])
@auth.role_required("Analyst")
def api_add_sigma():
    yaml_text = (request.get_json(silent=True) or {}).get("yaml", "")
    try:
        filename = save_new_rule(yaml_text)
        return jsonify({"ok": True, "filename": filename})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@bp.route("/api/sigma/<path:filename>/delete", methods=["POST"])
@auth.role_required("Analyst")
def api_delete_sigma(filename):
    try:
        delete_rule(filename)
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
