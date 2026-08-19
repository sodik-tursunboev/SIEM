"""
paths.py
--------
One place that knows where things live, whether this is running as a
normal Python script or as a frozen PyInstaller .exe.

THE PROBLEM THIS SOLVES
Every module used to do:

    os.path.join(os.path.dirname(__file__), "siem.db")

That is correct when running `python app.py`, and wrong in an .exe, for
two separate reasons:

1. PyInstaller unpacks the bundle into a random temp directory exposed
   as sys._MEIPASS. `__file__` points in there, so the app would look
   for templates in a folder that exists - fine - but also try to WRITE
   siem.db in there.
2. That temp directory is deleted when the process exits. A database
   written there is silently destroyed on every close, so the app would
   appear to work perfectly and lose all data every time.

So paths split into two kinds:

  resource_path()  read-only things SHIPPED INSIDE the exe: HTML
                   templates, CSS/JS, the sigma rule YAMLs.

  data_path()      things the app WRITES: the SQLite database, the
                   session signing key, the forwarder key, PDF reports.
                   These go to a stable per-user location that survives
                   restarts and app updates:
                     Windows -> %LOCALAPPDATA%\\MiniSIEM
                     Linux   -> ~/.local/share/MiniSIEM
                     macOS   -> ~/Library/Application Support/MiniSIEM

Running from source behaves exactly as before EXCEPT that writable files
now live in the per-user folder rather than beside the code. That is the
right behaviour anyway - it keeps siem.db out of the git repo by
construction, not just by .gitignore.
"""

import os
import sys

APP_NAME = "MiniSIEM"


def is_frozen() -> bool:
    """True when running inside a PyInstaller bundle."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def resource_path(*parts) -> str:
    """Absolute path to a read-only file that ships with the app."""
    if is_frozen():
        base = sys._MEIPASS
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, *parts)


def data_dir() -> str:
    """Writable per-user directory. Created on first call."""
    override = os.environ.get("SIEM_DATA_DIR")
    if override:
        base = override
    elif sys.platform == "win32":
        base = os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), APP_NAME
        )
    elif sys.platform == "darwin":
        base = os.path.expanduser(f"~/Library/Application Support/{APP_NAME}")
    else:
        base = os.path.expanduser(f"~/.local/share/{APP_NAME}")

    os.makedirs(base, exist_ok=True)
    return base


def data_path(*parts) -> str:
    """Absolute path to a writable file, parent directories created."""
    full = os.path.join(data_dir(), *parts)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return full
