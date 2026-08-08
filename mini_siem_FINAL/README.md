# Mini SIEM

A full detection-and-response platform built from scratch in Python: multi-source log ingestion (Windows, Linux, Sysmon, remote forwarders), 35 correlation-based detection rules plus a Sigma engine, automatic attack-chain correlation, SOAR-style automated response, full case management, role-based access control, a real threat-hunting query language, and AI-assisted triage — with an enterprise-style redesigned UI (left sidebar nav, dense data tables, restrained severity-driven color).

> Built as a hands-on portfolio project. Every feature was tested against real attack simulations before being considered done — including a real, exploitable stored XSS that was found and fixed by actually attempting the attack, not just reviewing the code, and detection rules validated against real Atomic Red Team test runs.

## Screenshots

*(Add screenshots here — Dashboard, Attack Chains, Rules, and SOAR are the strongest ones to lead with.)*

## What it does

**Detection — 35 rules + Sigma engine**

*Core Windows:* Brute Force, Password Spraying, Account Lockout, Privilege Escalation, Audit Log Cleared, Suspicious Process, Suspicious PowerShell, New Scheduled Task, New Service, USB Device, Kerberoasting

*Advanced Windows/Sysmon:* Suspicious Parent-Child Process (Office→Shell), PowerShell Downgrade Attack, PowerShell Obfuscation, AMSI Bypass, Suspicious LSASS Access (real access-mask check, not just keyword matching), Process Injection (CreateRemoteThread), DNS Tunneling

*Discovery/Lateral/Persistence:* Discovery Command Burst, Living-off-the-Land Binary Abuse, Registry Run Key Persistence, Indicator Removal (log deletion), Remote Service Execution, Shadow Copy/Backup Deletion, Unsecured Credential Search, Process Masquerading

*Linux:* SSH Brute Force, Privilege Escalation, Suspicious Sudo Command, New User, Added to Privileged Group

*Behavioral:* Unusual Login Hour, New Source IP (no ML library — per-user baselining)

*Platform security:* SIEM Login Brute Force — watches attacks against the SIEM's own login

*Plus:* IOC Watchlist matching, and a full Sigma rule engine (industry-standard YAML format)

Every alert is MITRE ATT&CK-tagged automatically.

**Attack Chain Correlation** — 3+ distinct rule types firing for the same user/IP within 60 minutes auto-cluster into one incident. One click creates a case with every alert in the chain attached as evidence.

**Rule Management** — every rule shown with severity, MITRE mapping, hit count, last-triggered time, and a live enable/disable toggle. Disabling a rule actually stops it from firing.

**Investigation**
- Threat Hunting — free text plus a real query language (`eventid:4625 AND username:Administrator`, wildcards, quoted values)
- 8 built-in one-click Threat Hunt Queries (Failed Logins, PowerShell, Kerberos Tickets, Golden Ticket, LSASS Access, etc.) plus save your own
- MITRE ATT&CK Heatmap, Attack Timeline, Asset Inventory, Risk Scoring, IOC Watchlist

**Case Management** — INC-001 style numbered cases: status, priority, assignment, evidence (auto-pulls real alert details), investigation notes, resolution tracking.

**SOAR** — alerts matching a playbook queue a block-IP/disable-account action. Nothing fires automatically; every action needs one-click analyst approval, and hard safety guardrails apply regardless of approval.

**Access Control** — session login, three roles (Viewer/Analyst/Admin), brute-force lockout on the login itself (5 failures/15 min) — with failed attempts fed through the same detection pipeline as everything else.

**Reporting & AI** — PDF reports (daily/weekly), AI incident summaries (Anthropic or Groq), email alerts, CSV export everywhere.

**Ingestion**
- Local Windows Event Log (Security + System) and **Sysmon** (Process Create, Process Access, Process Injection, DNS Query)
- Linux syslog (SSH, sudo, su, useradd/usermod)
- Remote forwarder agent (Security/System/Sysmon, via PowerShell + Get-WinEvent — no pywin32 needed on the remote machine)

**Security hardening** — a full XSS audit across every page, found and fixed a real stored XSS (Sigma rule titles rendered unescaped), verified by actually exploiting it before and after the fix.

## Architecture

```
Windows Event Log ---\                                      +-------------------+
Linux syslog ---------+--> collector/listener --> rules.py --| MITRE tagging     |
Sysmon --------------/                                        | Sigma matching    |
Remote forwarder(s) -/          |                              | Anomaly detection |
                                 v                              | SOAR playbooks    |
                          SQLite (siem.db)                      | Chain correlation |
                                 |                               +-------------------+
                                 v
                    Flask app (session auth + RBAC)
                                 |
      +--------------+----------+----------+--------------+
      v              v          v          v              v
  Dashboard    Threat Hunting  Cases /   SOAR / Rules   Reports / AI
  + Chains      + Saved         Chains    Management      Summaries
                 Queries
```

## Tech stack

Python, Flask, SQLite, Chart.js, reportlab (PDF), PyYAML (Sigma), vanilla JS — no frontend framework, deliberate choice. UI: IBM Plex Mono (data) + IBM Plex Sans (UI chrome), left sidebar nav.

## Quickstart

```bash
git clone <your-repo-url>
cd mini-siem
pip install -r requirements.txt
python app.py demo        # simulated data, works on any OS
python app.py windows     # real Windows Event Log + Sysmon collection (run as Administrator)
```

Open `http://127.0.0.1:5000`. First login: `admin` / `admin123` — **change this immediately** under My Account.

Optional environment variables:
```bash
ANTHROPIC_API_KEY=sk-ant-...      # enables AI incident summaries
SIEM_AI_PROVIDER=groq             # switch to Groq's free tier instead
GROQ_API_KEY=gsk_...
SIEM_INGEST_KEY=...               # shared secret for remote forwarders (auto-generated if unset)
```

## Remote forwarding setup

Copy `forwarder.py` alone to any remote Windows machine (VM, server) — no other project files needed there.

```bash
pip install requests   # only dependency - no pywin32 required
set SIEM_URL=http://<main-SIEM-IP>:5000
set SIEM_INGEST_KEY=<from ingest_key.txt on the main SIEM>
python forwarder.py    # run as Administrator
```

Forwards Security, System, and Sysmon (if installed) via PowerShell's `Get-WinEvent` — reliable structured field extraction, no native message-formatting quirks.

## Project structure

```
mini_siem/
├── app.py                      # Flask routes, auth wiring, blueprint registration
├── auth.py                     # login/session/RBAC
├── database.py                 # SQLite schema + all queries
├── rules.py                    # core detection engine + rule registry (35 rules)
├── linux_rules.py              # SSH/sudo/su detection
├── anomaly.py                  # behavioral baselining
├── sigma_rules.py              # Sigma YAML rule engine
├── soar.py                     # response playbooks + execution
├── correlation.py              # attack chain correlation
├── cases.py                    # case management
├── rule_management.py          # rule registry API/page
├── query_lang.py                # threat hunting query language
├── saved_queries.py              # saved hunt query presets
├── collector.py                    # Windows Event Log + Sysmon reader
├── syslog_listener.py                # Linux syslog receiver
├── ingest.py                          # remote forwarder API
├── forwarder.py                        # standalone VM agent (PowerShell-based)
├── report.py                            # PDF report generation
├── ai_summary.py                         # AI incident summaries
├── notifier.py                            # email alerting
├── sigma_rules/                            # example Sigma YAMLs
├── templates/                               # Jinja2 HTML (sidebar-nav enterprise UI)
└── static/                                   # style.css + utils.js (+ chart.min.js, see above)
```

## Known limitations

- SQLite — not built for high-volume production log ingestion or concurrent writes at scale
- HTTP, not HTTPS — fine on an isolated lab/VM network, not for anything internet-facing
- Sigma support covers common single/multi-selection AND/OR condition patterns, not the full specification
- No automated test suite committed to the repo — every feature was tested extensively during development (live attack simulations, real browser automation, API-level verification) but that testing isn't preserved as re-runnable code yet
- Single-node — no clustering or horizontal scaling
- Account lockout carries the same tradeoff every lockout policy does: an attacker who knows a valid username could deliberately trigger it as denial-of-service against that user

## License

MIT — do whatever you want with it.
