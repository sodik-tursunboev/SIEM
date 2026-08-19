# Mini SIEM — Desktop Application & Security Hardening

Documentation for the standalone Windows build and the security hardening
pass applied to the application layer.

---

## 1. What this covers

The Mini SIEM began as a Flask application run with `python app.py` on a
single machine. This document covers two pieces of work that changed
that:

1. **Application security hardening** — auditing the app against a
   20-item web application security checklist and closing the gaps.
2. **Desktop packaging** — turning the project into a distributable
   Windows executable that runs without Python installed.

Both are deliberately scoped to the *application*, not the detection
engine. Nothing here changes how rules fire or how events are scored.

---

## 2. Quick start

### Running the executable

Double-click `MiniSIEM.exe`. A console window opens showing live
detections and the dashboard opens in your default browser
automatically.

First login is `admin` / `admin123`. Change it immediately from
**User Management**.

### Building the executable from source

Requires Python 3.11 or 3.12 with "Add Python to PATH" enabled.

```
build.bat
```

Output: `dist\MiniSIEM.exe`. Build takes 1–3 minutes.

### Running from source

```
pip install -r requirements.txt
python launcher.py
```

Behaves identically to the executable.

---

## 3. Architecture of the desktop build

### 3.1 Entry points

The project now has three, each for a different context:

| Entry point | Used by | Server |
|---|---|---|
| `launcher.py` | Desktop exe, local runs | waitress |
| `wsgi.py` | Hosted deployment | gunicorn |
| `app.py` (`__main__`) | Original dev workflow | Flask dev server |

`launcher.py` is the one PyInstaller freezes. It initialises the
database, registers detection rules, starts the background collector,
starts the web server, and opens the browser once the port actually
answers.

### 3.2 Why waitress rather than gunicorn

Gunicorn cannot run on Windows. It relies on `fork()`, which does not
exist on the platform — this is a hard architectural limitation, not a
configuration problem. Waitress is a production-grade pure-Python WSGI
server that runs on Windows and freezes cleanly under PyInstaller.

The hosted path keeps gunicorn, because there the target is Linux.

### 3.3 Why the browser launch polls the port

Opening the browser immediately after starting the server thread is a
race condition. On a cold start the socket is frequently not yet
listening, the browser lands on a connection-refused page, and the user
concludes the application is broken. The launcher polls the port at
half-second intervals until it answers, then opens the browser.

### 3.4 Single worker, deliberately

The hosted configuration pins gunicorn to one worker. This is a
correctness requirement, not a performance compromise:

- Application state lives in a SQLite file.
- Background threads generate demo events and schedule reports.

Each additional worker is a separate OS process that would start its own
copy of those threads, all writing to the same SQLite file. The result
is duplicated events and `database is locked` errors under concurrent
writes.

---

## 4. The path resolution problem

This was the defect that would have broken the executable most severely,
and it is worth documenting in full because the failure mode is silent.

### 4.1 The original code

Five modules resolved file paths relative to their own source file:

```python
DB_PATH     = os.path.join(os.path.dirname(__file__), "siem.db")
KEY_FILE    = os.path.join(os.path.dirname(__file__), "ingest_key.txt")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
RULES_DIR   = os.path.join(os.path.dirname(__file__), "sigma_rules")
_SECRET_PATH= os.path.join(os.path.dirname(__file__), "instance_secret.key")
```

This is correct when running `python app.py`. It is wrong inside a
frozen executable.

### 4.2 Why it fails

PyInstaller unpacks the bundle into a randomly named temporary
directory, exposed at runtime as `sys._MEIPASS`. Inside a frozen build,
`__file__` points into that temp directory.

Reading bundled files from there works fine. Writing to it does not —
**the operating system deletes that directory when the process exits.**

The consequence: the application would launch correctly, create a
database, ingest events, raise alerts, and display a fully working
dashboard. On close, the database would be destroyed along with the temp
directory. Next launch would start from empty, with no error message at
any point.

A crash would have been easier to diagnose than this.

### 4.3 The fix

A single module, `paths.py`, now distinguishes two categories:

**`resource_path()`** — read-only files shipped inside the executable:
HTML templates, CSS and JavaScript, sigma rule YAML files. Resolves to
`sys._MEIPASS` when frozen, the source directory otherwise.

**`data_path()`** — files the application writes: the SQLite database,
the session signing key, the forwarder ingest key, generated PDF
reports. Resolves to a stable per-user location:

| Platform | Location |
|---|---|
| Windows | `%LOCALAPPDATA%\MiniSIEM` |
| Linux | `~/.local/share/MiniSIEM` |
| macOS | `~/Library/Application Support/MiniSIEM` |

Override with the `SIEM_DATA_DIR` environment variable.

### 4.4 A side benefit

Running from source now also writes to the per-user directory rather
than into the project folder. `siem.db` is therefore kept out of the
git repository *by construction* rather than by `.gitignore` entry — a
structurally stronger guarantee than a rule someone can forget to add.

### 4.5 Flask template and static resolution

`Flask(__name__)` looks for `templates/` and `static/` beside the module
file. Under PyInstaller those folders are unpacked elsewhere, so both are
now passed explicitly:

```python
app = Flask(
    __name__,
    template_folder=paths.resource_path("templates"),
    static_folder=paths.resource_path("static"),
)
```

Without this, every page returns `TemplateNotFound` and every stylesheet
404s.

---

## 5. PyInstaller configuration

The build uses a `.spec` file rather than command-line flags, because
three settings are easy to get wrong and slow to debug.

### 5.1 `datas`

PyInstaller traces Python `import` statements. It has no visibility into
files loaded by name at runtime. Templates, static assets and sigma rule
YAMLs must be declared explicitly or the build produces an executable
that fails on every page render.

### 5.2 `hiddenimports`

Modules reached dynamically rather than through a literal import
statement are invisible to static analysis. Two cases here:

- **pywin32** (`win32evtlog` and related) — imported inside a
  `try`/`except` block for Windows Event Log collection.
- **Detection rule modules** — resolved by name by the rule engine.

### 5.3 `excludes`

Excluding `matplotlib`, `numpy`, `pandas`, `scipy`, `PIL` and the GUI
toolkits removes roughly 200 MB from the bundle. None are used. If
server-side charting is added later, revisit this list.

### 5.4 `console=True`

Kept deliberately. The console window streams live detections and
startup diagnostics. A windowed build hides the single clearest signal
that the application is working.

---

## 6. Security hardening

The application was audited against a 20-item web application security
checklist. Results below reflect the actual state of the codebase, not
aspirations.

### 6.1 Already implemented before this pass — 11 items

| Item | Implementation |
|---|---|
| Hide API keys | Ingest key read from `SIEM_INGEST_KEY`; never hardcoded |
| Purge git secrets | `.gitignore` covers keys, `.env`, database |
| Server-side auth | `login_required` / `role_required` decorators |
| Lock record access | RBAC: Viewer → Analyst → Admin |
| Block field tampering | Explicit field whitelist; no mass assignment |
| Hash passwords | werkzeug `generate_password_hash` |
| Rate limit login | Per-username lockout **and** per-IP limiting; both logged into the SIEM's own pipeline |
| Parameterize queries | All values parameterized |
| Validate input | Enumerated status/priority values; required-field checks |
| Escape user content | Jinja2 autoescaping |
| Restrict file uploads | No upload routes exist |

### 6.2 On SQL query construction

Six call sites build SQL with f-strings, which normally warrants
scrutiny. Inspection confirmed these interpolate only *structure* —
column names from application-controlled dictionaries and pre-built
`WHERE` fragments — while every user-supplied **value** is passed as a
bound parameter:

```python
set_clause = ", ".join(f"{k} = ?" for k in fields)
conn.execute(f"UPDATE cases SET {set_clause} WHERE id = ?",
             (*fields.values(), case_id))
```

The field names originate from a route-level whitelist, so no
user-controlled string reaches the query text. This is safe, but it is
safe *because* of the whitelist upstream — worth stating explicitly
rather than assuming.

### 6.3 Added in this pass

**Session cookie hardening**

| Setting | Value | Purpose |
|---|---|---|
| `SESSION_COOKIE_HTTPONLY` | `True` | Blocks JavaScript reading the cookie, so an XSS bug cannot escalate to session theft |
| `SESSION_COOKIE_SAMESITE` | `Lax` | Prevents the cookie riding cross-site POSTs (CSRF) |
| `SESSION_COOKIE_SECURE` | env-gated | HTTPS-only transmission |
| `PERMANENT_SESSION_LIFETIME` | 8 hours | Bounded session validity |

`SECURE` is read from `SIEM_HTTPS` rather than hardcoded to `True`,
because the lab runs over plain HTTP and hardcoding it would silently
break login locally with no visible error.

**Response security headers**

Applied to every route via `@app.after_request`:

- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy` — geolocation, microphone, camera disabled
- `Strict-Transport-Security` — enabled only when `SIEM_HTTPS=1`

### 6.4 A defect caught before shipping

The Content-Security-Policy was first written as:

```
script-src 'self'
```

This is the correct directive in general, and it would have broken the
entire dashboard. All 18 templates carry inline `<script>` blocks, every
one of which the browser would have refused to execute. The application
would have rendered as unstyled, non-functional pages.

The resolution was `'unsafe-inline'` on `script-src`, with the tradeoff
documented in the source rather than left implicit:

```
KNOWN LIMITATION: 'unsafe-inline' is present on script-src because all
18 templates carry inline <script> blocks. That weakens CSP's XSS
containment, so it is deliberate and documented rather than quietly
ignored. Proper fix is per-request nonces.
```

The remaining directives still hold: no external script origins, no
framing, no object/embed, `base-uri` locked to self.

This is a genuine weakening of the policy, not a clean win. The correct
fix is per-request nonces, which requires modifying all 18 templates.

### 6.5 Dependency scanning

`pip-audit` against the original `requirements.txt`:

```
Found 3 known vulnerabilities in 2 packages
Name      Version  ID               Fix Versions
--------  -------  ---------------  ------------
flask     3.0.3    PYSEC-2026-2151  3.1.3
requests  2.32.3   PYSEC-2026-1872  2.32.4
requests  2.32.3   PYSEC-2026-2275  2.33.0
```

Resolved by pinning Flask 3.1.3 and requests 2.33.0. Re-scan returns
clean.

### 6.6 Not applicable

Three checklist items assume a Supabase/Next.js stack and have no
equivalent here: publishable database keys, row-level security (this is
SQLite with application-layer RBAC), and managed bot protection.

Database-at-rest encryption is unaddressed. SQLite stores plaintext; the
answer would be SQLCipher. This is a real gap, relevant only if the
database leaves a controlled environment.

---

## 7. Public deployment notes

A hosted configuration exists alongside the desktop build. Two behaviours
change when `SIEM_PUBLIC_DEMO=1` is set.

### 7.1 The ingest endpoint is removed, not secured

`/api/ingest/event` accepts events from remote forwarders, authenticated
by a shared secret in a plaintext header. On a public URL this is an
invitation to inject fabricated alerts into a demo everyone is viewing.

The blueprint is therefore not registered at all in public demo mode.
There is no endpoint to attack, no key to leak, and no rate limit to
tune. This is a stronger position than hardening the route.

### 7.2 Default credentials are refused

`admin` / `admin123` on a public URL is immediate takeover. In public
demo mode the application **refuses to start** unless
`SIEM_ADMIN_PASSWORD` is set to at least 12 characters.

A separate `demo` account is created at Viewer level, whose credentials
are safe to publish. Viewer can read dashboards, logs and alerts but
cannot triage, modify records, trigger SOAR actions, or manage users.
Visitors get a real view of the tool without altering what anyone else
sees.

This also protects the AI incident summary feature, which calls a paid
API. That route is gated at Analyst, so demo visitors cannot invoke it.

---

## 8. Reference

### 8.1 Environment variables

| Variable | Default | Effect |
|---|---|---|
| `SIEM_MODE` | `windows` on Windows | `demo` for simulated events |
| `SIEM_PORT` | `5000` | Listening port |
| `SIEM_HOST` | `127.0.0.1` | Bind address |
| `SIEM_DATA_DIR` | Per-user path | Override writable data location |
| `SIEM_HTTPS` | unset | `1` enables Secure cookies and HSTS |
| `SIEM_PUBLIC_DEMO` | unset | `1` enables hosted demo restrictions |
| `SIEM_ADMIN_PASSWORD` | — | Required when `SIEM_PUBLIC_DEMO=1` |
| `SIEM_INGEST_KEY` | generated | Shared secret for forwarders |
| `ANTHROPIC_API_KEY` | — | AI incident summaries |

### 8.2 Data directory contents

```
%LOCALAPPDATA%\MiniSIEM\
├── siem.db                 SQLite database
├── instance_secret.key     Session signing key
├── ingest_key.txt          Forwarder shared secret
└── reports\                Generated PDF reports
```

Persists across rebuilds. Delete the folder to reset to a clean state.

### 8.3 Troubleshooting

**SmartScreen warning on other machines**

"Windows protected your PC" appears for any unsigned executable. Click
*More info → Run anyway*. Removing it requires a code-signing
certificate (roughly $100–400/year), which is not justified for a
portfolio project.

**Browser does not open**

The launcher waits up to 30 seconds for the port to answer. If it times
out it prints the URL to the console — open it manually.

**Port already in use**

```
set SIEM_PORT=5001
MiniSIEM.exe
```

**Windows Event Log collection unavailable**

The launcher checks for pywin32 at startup and falls back to demo mode
with a console message if it is missing.

**Starting over**

Delete `%LOCALAPPDATA%\MiniSIEM\`. The next launch recreates the
database, keys and default admin account.

---

## 9. UI redesign — v3 to v4 ("Terminal")

### 9.1 Why this happened

The original stylesheet (v3) was a legitimate dark dashboard — restrained
accent color, real dark-mode discipline, no obvious bugs. It was also
indistinguishable from what any AI assistant produces by default for
"clean dark SOC dashboard": near-black surface, one blue info color,
neutral sans UI font, 4px rounded corners. Nothing wrong with it, nothing
specific to it either.

v4 commits to one real reference point instead: TryHackMe's
terminal/CTF visual language, chosen because it matches both the
operator's TryHackMe top-1% background and the existing SODIK OS
branding direction, rather than a generic "professional SIEM" look.

### 9.2 What changed, concretely

| | v3 | v4 |
|---|---|---|
| Primary UI font | IBM Plex Sans | JetBrains Mono — mono everywhere, not just data |
| Accent color | Blue (`--info`) | Red (`--accent`), THM-derived |
| Border radius | 4px | 0px — sharp terminal edges |
| Nav styling | Plain list | `root@:~$` brand prefix, `›` link markers, `# ` section labels |
| Background | Flat | Faint scanline texture (low-opacity, deliberate, the one aesthetic risk taken) |
| Buttons | Plain text | `[ bracketed ]` via CSS `::before`/`::after` |
| Icons | Emoji (🤖, ⬇) | Removed entirely — bracket-styled text labels |
| Dashboard | No signature element | Boot-sequence block on load |

### 9.3 Why this was a one-file change

All 19 templates share one class API — `.card`, `.btn`, `.sev-*`,
`.badge-*`, `.mitre-tag`, `.panel-title`, etc. Every visual property
lives in `static/style.css`; no template's markup references a color,
font, or radius directly. Redesigning meant rewriting that one file
completely — new token values, same selectors — with zero markup
changes required across any of the 19 pages. This is precisely what
that shared class API is for.

The one template that DID need markup changes was `dashboard.html`,
for the boot-sequence element described below. The font `<link>` tag
also needed updating in each template's `<head>` — this is exactly
the kind of duplicated boilerplate that the (currently unused) planned
`base.html`/Jinja2-inheritance refactor would eliminate; see the
"Known limitations" note in section 9.5.

### 9.4 The boot-sequence element

```
[ok] sysmon.operational  ................ connected
[ok] detection_engine    ................ 30+ rules loaded
[ok] correlation_engine  ................ armed
[ok] soar_guardrails     ................ active
session: admin@mini-siem · role: Admin_
```

This is the one deliberately memorable element the redesign is built
around. It renders on the dashboard on every load, staggered in with a
short CSS animation, and respects `prefers-reduced-motion` (skips the
animation, shows all lines immediately).

It is written to be **honest, not theatrical** — every line reflects
something the application actually does on startup (these are close
paraphrases of what `launcher.py` prints to the real console), rather
than being decorative filler unconnected to what the tool does.

### 9.5 Known limitations

- **No template inheritance yet.** All 19 templates still duplicate the
  `<head>` block (font link, theme script, stylesheet link) rather than
  extending a shared Jinja2 base template. A `base.html` was drafted
  during this work but not wired in across all pages — the payoff
  (one shared `<head>`) is real but touching 19 files to route through
  it was deferred as a separate pass rather than bundled into the
  visual redesign. Worth doing before a portfolio review if time
  allows: it is a legitimate, describable craftsmanship improvement
  ("refactored 19 templates onto Jinja2 inheritance, removing ~150
  lines of duplicated boilerplate").
- **Inline `<style>` blocks remain in 14 templates.** These are
  page-specific layout rules (grid columns, chart heights) that don't
  belong in the global stylesheet, so their presence isn't itself a
  problem — but combined with the missing template inheritance, they
  are part of the same underlying gap.
- **Font import duplicated 19 times** rather than centralized — same
  root cause as the missing base template.

None of these affect correctness or the visual result the redesign
targets. They are the next round of structural cleanup, not defects
introduced by this pass.

