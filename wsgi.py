"""
wsgi.py
-------
Production entry point. Gunicorn imports `app` from here.

This exists because `app.py`'s `if __name__ == "__main__":` block never
runs under a WSGI server - gunicorn imports the module rather than
executing it as a script. Without this file the database would never be
initialised, no rules would be registered, and no demo data would ever
be generated: you'd get a running server serving empty pages.

Run locally exactly as the host will run it:
    gunicorn --workers 1 --bind 0.0.0.0:5000 wsgi:app

WHY --workers 1 MATTERS: this app keeps state in a SQLite file and runs
background threads (demo log generator, report scheduler). Every extra
gunicorn worker is a separate process that would start its OWN copy of
those threads, all writing to the same SQLite file concurrently. That
produces duplicate demo events and 'database is locked' errors. One
worker is correct here, not a limitation to work around.
"""

import os

import app as app_module
import database as db
import rules
import saved_queries
import auth

app = app_module.app


def _bootstrap():
    """Everything app.py's __main__ block does, minus the dev server."""
    db.init_db()
    rules.register_all_rules()
    saved_queries.register_builtin_queries()
    auth.ensure_default_admin()

    # Public demo always uses simulated logs. Real Windows Event Log
    # collection needs pywin32 and an actual Windows host - neither
    # exists on a Linux cloud container, so 'windows' mode is not an
    # option here even if someone set the env var.
    app_module.start_background_collector("demo")

    # Deliberately NOT started in the hosted demo:
    #   - syslog_listener: binds UDP 514, a privileged port most hosts
    #     block outright, and nothing is forwarding syslog to a demo.
    #   - report_scheduler: writes PDFs to disk on a container whose
    #     filesystem is wiped on every redeploy.
    if os.environ.get("SIEM_PUBLIC_DEMO") != "1":
        app_module.start_report_scheduler()
        app_module.syslog_listener.start_syslog_listener_thread()


_bootstrap()
