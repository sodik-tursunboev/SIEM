"""
auth.py
-------
Session-based authentication and role-based access control (RBAC).

Deliberately NOT using Flask-Login here - this app is small enough that a
plain signed session cookie (Flask's built-in `session`) does the same job
with one less dependency. Passwords are hashed with werkzeug's security
helpers, which ship with Flask, so still zero extra installs.

Roles, from least to most privileged:
  Viewer   - can view dashboards/logs/alerts, nothing else
  Analyst  - Viewer + can triage alerts (status changes), manage IOCs/assets
  Admin    - Analyst + manage users, everything

On first run (empty users table), a default admin/admin123 account is
created automatically so you have a way in. CHANGE THIS PASSWORD - see
the console warning printed at startup and the README.
"""

from functools import wraps

import os

from flask import session, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import database as db

ROLE_RANK = {"Viewer": 1, "Analyst": 2, "Admin": 3}


def ensure_default_admin():
    """Creates the starting accounts if no users exist yet.

    Two different situations, handled differently:

    LOCAL / LAB (default): creates admin/admin123 and shouts about it at
    startup. Convenient, and the app is only reachable from your own
    network anyway.

    PUBLIC DEMO (SIEM_PUBLIC_DEMO=1): admin/admin123 on a public URL is
    an instant takeover, so it is refused outright - the Admin password
    MUST come from the SIEM_ADMIN_PASSWORD environment variable and the
    app will not start without one. A separate 'demo' account is created
    at Viewer level, whose credentials are safe to publish on the login
    page: Viewer can read dashboards, logs and alerts but cannot triage,
    modify records, run SOAR actions, or manage users. Visitors get a
    real look at the tool without being able to alter what anyone else
    sees.
    """
    if db.count_users() != 0:
        return

    public_demo = os.environ.get("SIEM_PUBLIC_DEMO") == "1"

    if public_demo:
        admin_password = os.environ.get("SIEM_ADMIN_PASSWORD", "")
        if len(admin_password) < 12:
            raise RuntimeError(
                "SIEM_PUBLIC_DEMO=1 requires SIEM_ADMIN_PASSWORD to be set to at "
                "least 12 characters. Refusing to start with a default or weak "
                "admin password on a publicly reachable deployment."
            )
        db.create_user("admin", generate_password_hash(admin_password), role="Admin")

        demo_password = os.environ.get("SIEM_DEMO_PASSWORD", "demo")
        db.create_user("demo", generate_password_hash(demo_password), role="Viewer")
        print("[AUTH] Public demo mode: admin (from env) + read-only 'demo' account created.")
        return

    db.create_user("admin", generate_password_hash("admin123"), role="Admin")
    print("=" * 70)
    print("[AUTH] No users existed - created default account:")
    print("       username: admin   password: admin123")
    print("       CHANGE THIS PASSWORD after logging in (User Management page).")
    print("=" * 70)


def verify_login(username, password):
    user = db.get_user_by_username(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def current_user():
    if "user_id" not in session:
        return None
    return db.get_user_by_id(session["user_id"])


def _is_api_request():
    return request.path.startswith("/api/")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if _is_api_request():
                return jsonify({"error": "login required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def role_required(min_role):
    """@role_required('Analyst') allows Analyst and Admin, blocks Viewer."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                if _is_api_request():
                    return jsonify({"error": "login required"}), 401
                return redirect(url_for("login", next=request.path))
            user_role = session.get("role", "Viewer")
            if ROLE_RANK.get(user_role, 0) < ROLE_RANK.get(min_role, 99):
                if _is_api_request():
                    return jsonify({"error": f"requires {min_role} role or higher"}), 403
                flash(f"That action requires the '{min_role}' role or higher.", "error")
                return redirect(request.referrer or url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator
