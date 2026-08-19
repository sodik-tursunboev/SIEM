# Mini SIEM — Application Security Audit

**Target:** Mini SIEM (Flask / SQLite / Jinja2)
**Assessor:** Sodik Tursunboev — CEH v13
**Scope:** Application layer. Detection engine, correlation and BAS
scoring logic excluded.
**Method:** White-box source review with functional verification.

---

## Why this document exists

I built this application. That makes me the worst possible person to
audit it, because I already believe it works — so this review was done
against a fixed 20-item checklist rather than by looking for problems I
expected to find. Every item below was checked against the source, and
where a control was claimed but not actually present, that is recorded
as a finding rather than quietly fixed.

Three items produced findings. One of those was a control I had
genuinely believed was implemented, and was not.

---

## Summary

| Result | Count |
|---|---|
| Verified present | 14 |
| Findings — remediated | 2 |
| Findings — accepted risk | 1 |
| Not applicable to this stack | 3 |
| **Total** | **20** |

---

## Full checklist results

| # | Control | Result | Evidence |
|---|---|---|---|
| 1 | Hide API keys | **Pass** | Ingest and AI provider keys read from environment; no literals in source |
| 2 | Purge git secrets | **Finding** | `.gitignore` correct, history unverified — see F-02 |
| 3 | Use public DB key | **N/A** | Supabase concept; no client-side database access exists |
| 4 | Enable row-level security | **N/A** | SQLite with application-layer RBAC |
| 5 | Encrypt sensitive data | **Finding** | Plaintext SQLite at rest — see F-03 |
| 6 | Enforce server-side auth | **Pass** | `login_required` / `role_required` decorators; session server-validated |
| 7 | Lock record access | **Pass** | Three-tier RBAC; all routes enumerated and confirmed |
| 8 | Block field tampering | **Pass** | Explicit field whitelist before database write |
| 9 | Secure session cookies | **Pass** | `HttpOnly`, `SameSite=Lax`, env-gated `Secure`, 8h lifetime |
| 10 | Hash passwords | **Pass** | werkzeug PBKDF2; no reversible storage |
| 11 | Rate limit login | **Finding** | Lockout present, rate limiting absent — see F-01 |
| 12 | Add bot protection | **N/A** | No public registration or unauthenticated write surface |
| 13 | Parameterize queries | **Pass** | All values bound; dynamic SQL builds structure only |
| 14 | Validate all input | **Pass** | Enumerated values, required-field checks, typed casts |
| 15 | Escape user content | **Pass** | Jinja2 autoescape; `escapeHtml()` + `escapeJsAttr()` client-side |
| 16 | Restrict file uploads | **Pass** | No upload routes exist |
| 17 | Trim API responses | **Pass** | Explicit column selection; no hash exposure |
| 18 | Add security headers | **Pass** | Six headers via `after_request` |
| 19 | Force HTTPS | **Pass** | HSTS + `Secure` cookies under `SIEM_HTTPS=1` |
| 20 | Scan dependencies | **Pass** | `pip-audit` clean after remediation |

---

## F-01 — Account lockout misidentified as rate limiting

**Severity:** Medium
**Status:** Remediated
**Item:** 11

### The mistake

I had recorded this control as implemented. It was not. What existed
was **account lockout**: five failed attempts against one username
within fifteen minutes locks that username.

Lockout and rate limiting defend against different attacks, and I had
been treating them as the same control because both involve counting
failed logins.

### Why it mattered

Account lockout counts failures **per username**. It stops brute force —
many passwords against one account.

Password spraying inverts that: one common password against many
usernames. No individual account accumulates enough failures to lock,
so the control never engages and the attacker walks the entire user
list unimpeded.

The application had no per-source-address control of any kind. A single
host could attempt one password against every account it could name,
indefinitely, without triggering anything.

### Verification before remediation

Simulated twenty single attempts against twenty distinct usernames from
one source address:

```
attempt  1 (employee1 )  -> allowed | username locked? False
attempt  2 (employee2 )  -> allowed | username locked? False
attempt  3 (employee3 )  -> allowed | username locked? False
...
attempt 20 (employee20)  -> allowed | username locked? False

username lockout on employee20 : False
```

Twenty attempts, zero controls engaged.

### Remediation

Added `is_ip_rate_limited()` — a sliding window counting failures by
source address across all usernames, threshold fifteen in fifteen
minutes. Wired into the login route **before** the username check,
because a spraying attacker cycles usernames specifically so the
username check never fires.

The IP threshold is set higher than the username threshold on purpose.
Multiple legitimate users share an address behind NAT, and a few genuine
typos between them should not lock out an entire office.

### Verification after remediation

```
attempt 15 (employee15)  -> allowed
attempt 16 (employee16)  -> BLOCKED by per-IP rate limit
attempt 20 (employee20)  -> BLOCKED by per-IP rate limit

username lockout on employee20 : False
per-IP rate limited            : True
```

The username lockout still never fires — correctly, since no account
was individually targeted. The per-IP control catches what it is blind
to.

Rejected attempts are written into the SIEM's own detection pipeline as
`SIEM_LoginRateLimited`, so the platform raises an alert on attacks
against itself.

### Root cause

Two controls that count the same events were assumed to provide the same
coverage. They count along different axes, and the axis determines which
attack is visible.

---

## F-02 — Git history not verified

**Severity:** Medium — unresolved pending verification
**Status:** Open, requires action on the development host
**Item:** 2

### The mistake

I initially recorded this control as satisfied on the basis that
`.gitignore` correctly excludes `instance_secret.key`, `ingest_key.txt`
and `siem.db`.

That verifies the wrong thing. `.gitignore` governs **future** commits.
It has no effect on anything already committed.

Both secret files are generated automatically on first run. If either
was committed before the `.gitignore` entry existed, it remains in
history and is extractable from any clone of a public repository, with
the working tree looking entirely clean.

### Required verification

```bash
git log --all --full-history --oneline -- \
    ingest_key.txt instance_secret.key siem.db
```

### If output is non-empty

The exposed values must be treated as compromised. Deleting the file in
a new commit does not remediate — history retains it.

1. Rotate both secrets. `instance_secret.key` signs session cookies;
   disclosure permits session forgery. `ingest_key.txt` authenticates
   log forwarders; disclosure permits injection of fabricated events
   into the SIEM.
2. Purge from history with `git filter-repo` or BFG Repo-Cleaner.
3. Force-push and treat prior clones as holding the old values
   permanently.

### Root cause

Verifying a control's configuration rather than its effect. The
`.gitignore` file was correct; the question of whether secrets had
already leaked was never actually asked.

---

## F-03 — Database stored in plaintext at rest

**Severity:** Low in current deployment
**Status:** Accepted risk, documented
**Item:** 5

SQLite stores all data unencrypted on disk. Passwords are hashed, so
credential material is not directly recoverable, but log content —
usernames, hostnames, source addresses, command lines captured from
Sysmon — is readable by anyone with filesystem access.

Not remediated. In the current model the database sits on the analyst's
own machine, where an attacker with filesystem access has already
achieved a position that makes database encryption largely irrelevant.

Remediation, if the deployment model changes: SQLCipher, or full-disk
encryption on the host. Recorded as an accepted risk rather than a
closed item, because the justification depends on a deployment
assumption that may not hold later.

---

## Defect caught during remediation — Content-Security-Policy

Not a finding against the original application; a defect I introduced
while fixing item 18, caught before it shipped.

The policy was first written as:

```
script-src 'self'
```

This is the correct directive in isolation and would have broken every
page in the application. All eighteen templates carry inline `<script>`
blocks. The browser would have refused to execute all of them, leaving
a dashboard that rendered as static markup with no functionality.

Resolved by restoring `'unsafe-inline'` on `script-src`, with the
tradeoff written into the source:

> KNOWN LIMITATION: 'unsafe-inline' is present on script-src because all
> 18 templates carry inline `<script>` blocks. That weakens CSP's XSS
> containment, so it is deliberate and documented rather than quietly
> ignored. Proper fix is per-request nonces.

This is a genuine weakening, not a clean pass. Remaining directives hold
— no external script origins, no framing, no object/embed, `base-uri`
locked to self — and the client-side escaping layer is the actual
primary XSS control here regardless.

The correct fix is per-request nonces across all eighteen templates.
Outstanding.

---

## Controls that held up

Three warrant specific mention, because they are the ones most often
found broken.

### Dynamic SQL construction — item 13

Six call sites build SQL with f-strings, which normally warrants
scrutiny:

```python
set_clause = ", ".join(f"{k} = ?" for k in fields)
conn.execute(f"UPDATE cases SET {set_clause} WHERE id = ?",
             (*fields.values(), case_id))
```

Only *structure* is interpolated — column names drawn from a route-level
whitelist. Every user-supplied value is bound. Safe, but safe **because
of** the whitelist upstream: remove it and this becomes injectable
immediately. The dependency is worth stating rather than assuming.

### Client-side escaping — item 15

Every page builds table rows from template literals inserted via
`innerHTML`, with values sourced from log messages, case notes and rule
descriptions — all attacker-influenceable.

`escapeHtml()` covers the general case. A separate `escapeJsAttr()`
exists for values inside inline event handlers, because HTML-entity
escaping is insufficient there: the browser HTML-decodes an attribute
value before the JavaScript engine parses it, so an escaped quote
becomes a literal quote by the time it reaches the parser, reopening the
string breakout the escaping was meant to prevent.

That distinction is a common source of stored XSS in applications that
believe they escape correctly.

### Response field selection — item 17

```python
conn.execute("SELECT id, username, role, created_at FROM users ...")
```

Explicit column selection rather than `SELECT *`. The `password_hash`
column is never returned by any endpoint — confirmed by tracing every
reference to it in the source.

---

## Dependency scanning — item 20

`pip-audit` against the original pins:

```
Found 3 known vulnerabilities in 2 packages
Name      Version  ID               Fix Versions
--------  -------  ---------------  ------------
flask     3.0.3    PYSEC-2026-2151  3.1.3
requests  2.32.3   PYSEC-2026-1872  2.32.4
requests  2.32.3   PYSEC-2026-2275  2.33.0
```

Remediated by pinning Flask 3.1.3 and requests 2.33.0. Re-scan returns
no known vulnerabilities.

Neither package was outdated by neglect — both were current when
pinned. This is the argument for scanning on a schedule rather than at
selection time.

---

## Outstanding

| Item | Action | Owner |
|---|---|---|
| F-02 | Run git history check; rotate and purge if positive | Development host |
| CSP | Per-request nonces across 18 templates | Backlog |
| F-03 | Revisit if deployment model changes | Conditional |

---

## What this exercise actually demonstrated

The two findings share a root cause, and it is not a coding mistake.

In both cases a control **existed** and I recorded the item as
satisfied. Lockout existed, so rate limiting was marked done.
`.gitignore` was correct, so secret exposure was marked handled. Both
conclusions were reached by confirming that something was present rather
than by asking what it actually stopped.

The per-IP gap only became visible when the attack was simulated and the
control was watched failing to fire. The git history gap only became
visible when the question changed from "does `.gitignore` list this
file" to "was this file ever committed."

This is the same distinction detection engineering runs on. A rule that
looks correct and a rule that fires on the technique it targets are two
different claims, and only the second one is testable. During the
Sentinel BAS work on this same platform, a Kerberoasting rule was
structurally unable to fire because a required field was never extracted
— it read as correct in review and was never going to alert.

Reviewing a control tells you what it is. Testing it tells you what it
covers. Those are not the same finding.

