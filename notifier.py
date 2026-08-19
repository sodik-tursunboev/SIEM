"""
notifier.py
-----------
Sends an email when an alert at or above a configured severity fires.
Configure via environment variables (see README) or edit the defaults
below directly. If SMTP isn't configured, this quietly does nothing -
email alerts are optional, not required for the rest of the app to work.

Usage: call notify_if_needed(alert_dict) right after an alert is inserted.
"""

import os
import smtplib
import ssl
from email.mime.text import MIMEText

SMTP_HOST = os.environ.get("SIEM_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SIEM_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SIEM_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SIEM_SMTP_PASSWORD", "")
ALERT_FROM = os.environ.get("SIEM_ALERT_FROM", SMTP_USER)
ALERT_TO = os.environ.get("SIEM_ALERT_TO", "")
MIN_SEVERITY = os.environ.get("SIEM_ALERT_EMAIL_MIN_SEVERITY", "Critical")

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def is_configured():
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD and ALERT_TO)


def notify_if_needed(alert: dict):
    """Sends an email if this alert's severity meets the configured
    threshold AND SMTP is actually configured. Never raises - a failed
    email send should never take down log collection."""
    if not is_configured():
        return
    if SEVERITY_RANK.get(alert.get("severity"), 0) < SEVERITY_RANK.get(MIN_SEVERITY, 4):
        return

    subject = f"[Mini SIEM] {alert['severity']} alert: {alert['rule_name']}"
    body = (
        f"Severity: {alert['severity']}\n"
        f"Rule: {alert['rule_name']}\n"
        f"Time: {alert.get('timestamp', '')}\n"
        f"User: {alert.get('related_user') or '-'}\n"
        f"IP: {alert.get('related_ip') or '-'}\n"
        f"MITRE: {alert.get('mitre_id') or '-'} ({alert.get('mitre_technique') or '-'})\n\n"
        f"{alert.get('description', '')}\n\n"
        f"-- Mini SIEM, http://127.0.0.1:5000"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = ALERT_FROM
    msg["To"] = ALERT_TO

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(ALERT_FROM, [ALERT_TO], msg.as_string())
        print(f"[NOTIFIER] Emailed alert to {ALERT_TO}: {subject}")
    except Exception as e:
        print(f"[NOTIFIER] Failed to send email alert: {e}")
