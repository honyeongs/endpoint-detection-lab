# Security Policy

This local portfolio lab analyzes selected telemetry. It is not an EDR, malware classifier, live collector, sandbox, or blocking service.

## Boundaries

- Runtime imports use only the Python standard library. No event command is executed, decoded or opened as a URL.
- No arbitrary server paths, external uploads, automatic persistence or collection agent.
- Loopback-only HTTP with exact Host and same-Origin POST checks, no CORS, fixed asset allowlist, strict Content-Length/Content-Type and request-body deadline.
- Input limits: 8 MiB, 10,000 source events, 4,096 characters per field, XML depth 16, XML nodes 400,000.
- Expat parses XML with DTD/entity/external-reference callbacks that reject these constructs, including UTF-16 inputs.
- Duplicate JSON keys, NaN, unknown fields, invalid types/GUIDs and conflicting process creation are rejected.
- Original rules use bounded field matches and time correlation; no eval, shell, arbitrary regex policy or network lookup.
- DOM uses textContent; control/bidi characters are displayed visibly. CSP, nosniff, no-store, frame denial.
- CLI output uses exclusive creation. Standard access logging is disabled to avoid leaking telemetry.

## Residual risks

Keep Python, Expat and the browser patched. Input limits are not OS-level CPU/memory isolation.
The single-request development server can be delayed by another local client. It has no authentication against native local processes or other OS users.
Host/Origin checks mitigate browser-origin attacks but do not authenticate telemetry or replace endpoint access controls.
Log forgery, missing events, timestamp precision, manipulated parent metadata, path aliases and hard links can defeat or mislead correlations.
Exact-match exclusions can hide an attacker that reproduces approved fields. Suppression is not trust or safety.
Command lines/usernames/paths may contain credentials or private data; export only deliberately. Memory is not securely erased.
Only four Sysmon event types and five original heuristics are covered. No alerts does not establish safety.

Do not expose through a reverse proxy, port forwarding, or a public address.
For real multi-user services, design authentication, tenancy, rate limits, worker isolation, telemetry privacy, provenance and incident response separately.

## Reporting

Do not attach real logs, credentials or executable malware to public issues.
Use private vulnerability reporting if enabled by the owner; otherwise ask for a private channel without publishing exploit data.
There is no response SLA or security certification.
