# Administrative-share regression coverage

Run `python -m unittest discover -s tests -v` after installing the project dependencies.
These synthetic tests exercise the real rule evaluator and both Windows collection
paths, including XML forwarding, the local collector's insertion fields, case
handling, message truncation, unrelated events/shares, and the public alert API.

The rule now uses Windows Security 5140/5145 and `ShareName|endswith`, with the
named ShareName preserved at the beginning of the existing message field. Enable
Audit File Share / Audit Detailed File Share on the monitored Windows host to
produce the relevant telemetry. Legitimate administration can match; a match is
an investigation lead, not proof of lateral movement or successful file transfer.
The rule remains experimental until validated against a new recorded Windows run.

Schema references:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145

The historical ten-test Atomic Red Team result (7 detected, 3 missed) has not been
rerun by this change and must not be increased based on these regression tests.
