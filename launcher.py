"""
launcher.py
-----------
Entry point for the desktop .exe. Double-click behaviour:

  1. Initialise the database and rules (first run creates them).
  2. Start the Flask server on a background thread.
  3. Wait until the port actually answers, then open the browser.
  4. Keep the console window open showing live detections.
  5. Ctrl+C, or closing the window, shuts everything down.

WHY NOT app.run()? Flask's built-in server prints a large red warning
that it is a development server, and it is genuinely not meant to face
anything but localhost. Waitress is a real production WSGI server, pure
Python, works on Windows (gunicorn does not - it needs fork()), and
PyInstaller bundles it without special handling.

WHY WAIT FOR THE PORT? Opening the browser immediately after starting
the thread is a race: on a cold start the server often is not listening
yet, the browser shows a connection-refused page, and the user assumes
the app is broken. Polling the port until it answers removes the race.
"""

import os
import socket
import sys
import threading
import time
import webbrowser

HOST = os.environ.get("SIEM_HOST", "127.0.0.1")
PORT = int(os.environ.get("SIEM_PORT", "5000"))


def _port_open(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _open_browser_when_ready():
    target = f"http://{'127.0.0.1' if HOST == '0.0.0.0' else HOST}:{PORT}"
    for _ in range(60):  # up to ~30 seconds
        if _port_open("127.0.0.1", PORT):
            webbrowser.open(target)
            return
        time.sleep(0.5)
    print(f"[LAUNCHER] Server did not come up in time. Try opening {target} manually.")


def main():
    import paths
    import database as db
    import rules
    import saved_queries
    import auth
    import app as app_module

    print("=" * 68)
    print("  Mini SIEM")
    print("=" * 68)
    print(f"  Data directory: {paths.data_dir()}")
    print("  (database, keys and reports live there and persist)")
    print()

    db.init_db()
    rules.register_all_rules()
    saved_queries.register_builtin_queries()
    auth.ensure_default_admin()

    # 'windows' collects from the real Windows Event Log and needs
    # pywin32; 'demo' generates simulated activity and runs anywhere.
    # Default to windows on Windows, demo elsewhere, override with
    # SIEM_MODE=demo if you want simulated data on a Windows box too.
    default_mode = "windows" if sys.platform == "win32" else "demo"
    mode = os.environ.get("SIEM_MODE", default_mode)
    if mode == "windows":
        try:
            import win32evtlog  # noqa: F401
        except ImportError:
            print("[LAUNCHER] pywin32 unavailable - falling back to demo mode.")
            mode = "demo"

    app_module.start_background_collector(mode)
    app_module.start_report_scheduler()
    try:
        app_module.syslog_listener.start_syslog_listener_thread()
    except Exception as e:
        # UDP 514 is privileged; failing to bind it must not stop the app.
        print(f"[LAUNCHER] Syslog listener not started: {e}")

    print(f"  Mode: {mode}")
    print(f"  Dashboard: http://127.0.0.1:{PORT}")
    print("  Close this window or press Ctrl+C to stop.")
    print("=" * 68)
    print()

    threading.Thread(target=_open_browser_when_ready, daemon=True).start()

    from waitress import serve
    try:
        serve(app_module.app, host=HOST, port=PORT, threads=8)
    except KeyboardInterrupt:
        print("\n[LAUNCHER] Shutting down.")


if __name__ == "__main__":
    main()
