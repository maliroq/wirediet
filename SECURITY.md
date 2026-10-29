# Security policy

## Reporting

Please report a vulnerability privately to the repository maintainer rather than posting an exploit with real household traffic or credentials in a public issue.

Until a public security contact is configured, open a minimal GitHub Security Advisory draft if the hosting repository supports it.

## Sensitive data

Do not attach raw DNS logs, PCAPs, router backups, authentication headers, API passwords/tokens, MAC addresses, device names or private addressing information to public issues.

Use `wirediet redact --analysis analysis.json --out analysis.public.json` for identifier redaction. Public domain names remain visible, so review the output yourself before publishing it; the command does not promise anonymity.

## Security boundaries in v0.1

- no direct resolver/router mutation
- no credential storage
- no remote API login
- no cloud backend
- local UI refuses non-loopback binds
- 50 MiB resolver-input limit and 1,000,000-event processing limit
- bounded reads for evidence, analysis and experiment-session JSON
- duplicate JSON keys are rejected; WireDiet-owned state also rejects unknown fields
- malformed hostnames are dropped during ingestion
- evidence provenance/freshness is validated before candidate use
- policy export independently validates hostnames to prevent config injection
- policy output rejects a symlink final directory and symlink components in relative output paths and uses owner-only files/directories where supported
- analysis/report/session JSON is written owner-only (`0600`) where Unix permission bits apply
- local UI validates loopback binding and the HTTP Host header

WireDiet cannot guarantee that a domain is safe to block. Its final policy means only that the tested aggregate policy passed the user-selected feature checks in that environment.
