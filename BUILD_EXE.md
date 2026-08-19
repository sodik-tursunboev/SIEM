# Building MiniSIEM.exe

## One-time setup
Install Python 3.11 or 3.12 from python.org — tick **"Add Python to PATH"**
during install.

## Build
Open a normal Command Prompt in the project folder and run:

    build.bat

Takes 1–3 minutes. Result: **`dist\MiniSIEM.exe`**

## Using it
Double-click `MiniSIEM.exe`. A console window opens showing live
detections, and your browser opens the dashboard automatically.

First login: `admin` / `admin123` — change it immediately via User
Management.

## Where your data lives
    %LOCALAPPDATA%\MiniSIEM\

Contains `siem.db`, `instance_secret.key`, `ingest_key.txt`, `reports\`.
This folder persists across rebuilds — delete it to start fresh.

## Modes
By default the exe collects from the real Windows Event Log. To run with
simulated data instead:

    set SIEM_MODE=demo
    MiniSIEM.exe

## Sharing it
`MiniSIEM.exe` is fully self-contained — no Python needed on the target
machine. Expect ~40–60 MB.

**Expect a SmartScreen warning** on other people's machines: "Windows
protected your PC". This is normal for unsigned executables, not a sign
anything is wrong. Users click *More info → Run anyway*. Removing the
warning requires a code-signing certificate (~$100–400/year), which is
not worth it for a portfolio project — but knowing *why* it appears is
worth mentioning if it comes up in an interview.
