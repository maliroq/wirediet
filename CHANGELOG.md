# Changelog

All notable changes will be documented here.

## [Unreleased]

### Security / robustness

- Bound evidence, analysis and experiment-session reads instead of trusting arbitrarily large secondary state files.
- Reject duplicate JSON object keys; WireDiet-owned state/config formats also reject unknown fields.
- Reject duplicate normalized CSV headers, overlong DNS names, malformed provenance URL hosts/user-info and malformed session IDs.
- Validate experiment-session structure, trial IDs and final-verification consistency before use.
- Write sensitive policy bundles with owner-only permissions, reject symlink path components, use atomic writes and mark complete bundles explicitly.
- Commit a pending trial only after its policy bundle has been written successfully.
- Require evidence database review dates and auditable public HTTP(S) sources; stale block candidates are downgraded until reviewed.
- Expand identifier redaction to private/local IPv6, MAC-shaped/free-text identifiers and real generation timestamps.
- Validate local-web Host headers to reduce DNS-rebinding exposure.
- Limit prebuilt public release targets to checksummed Linux amd64/arm64 binaries; keep macOS/Windows as compile gates until appropriate signing/notarization is available.

### Real validation

- Imported a frozen 147-entry AdGuard Home v0.107.79 query log for exactly one isolated external client; corrected WireDiet produced a 147 → 147 event-count match.
- Preserved UNKNOWN when the 43 observed domains produced no evidence-backed low-risk candidate; an independent exact-domain Tracker Radar check also returned zero.
- Verified a controlled AdGuard Home exact-host rule blocked only the target while parent/sibling names resolved normally, then confirmed feature preservation and complete rollback on the isolated client.
- Live failure/split and smart-TV/IoT feature behavior remain explicitly NOT VERIFIED.

### Fixed

- AdGuard Home `/control/querylog` interoperability: parse the documented `question.name` field used by current releases (including v0.107.79), retain compatibility with the earlier synthetic `question.host` shape, and reject conflicting dual-field records instead of guessing.

### Added

- Initial WireDiet v0.1 implementation.
- CSV, JSON, dnsmasq, AdGuard Home and Pi-hole v6 query imports.
- Embedded auditable evidence seed.
- Conservative classification with explicit unknown/protected states.
- Reversible binary-splitting feature experiments.
- Multi-format policy export and rollback manifests.
- Exact-host export semantics so learned hostnames are not silently widened to all subdomains.
- Local-only web UI and redacted public reports.
- Synthetic fixtures, tests, CI and release workflow.
- `python3 dev.py` local release and guided real-device validation harness with machine-readable/text reports.
- Explicit exact-host neighbor regression for parent/sibling/subdomain non-broadening.


## v0.1.0-preview.5 — packaging/version verification correction

- froze a new unambiguous release-candidate filename after a stale preview.4 package surfaced the escaped-version bug again
- release harness injects and verifies the literal version `v0.1.0-preview.5` with no backslash escaping
- historical sanitized real-world evidence remains separately pinned under `docs/reproducibility/` and cannot be overwritten by Phase-A-only runs
- no classification, evidence, experiment, policy, export, rollback, resolver-write or privacy-boundary semantics changed


## v0.1.0-preview.4 — final evidence/reporting fix

- fixed release-version validation so escaped version strings cannot pass the deterministic gate; the binary must print exactly `wirediet v0.1.0-preview.4`
- separated current-run reproducibility output from committed historical real-world evidence
- pinned the sanitized 2026-10-27 real-world evidence files with SHA-256 and verify them during `dev.py`
- clarified that Phase-A-only live rows remain `NOT VERIFIED` for that invocation without downgrading the completed historical experiment
- no classification, experiment, policy, export, rollback, resolver-write or evidence-boundary semantics changed

## v0.1.0-preview.3 — product presentation pass

- added the WireDiet project mark, favicon and social preview assets
- redesigned the local UI around Observe → Test → Verify with intentional UNKNOWN states
- added optional read-only experiment-session state to `wirediet serve --session`
- rewrote the README around policy discovery vs DNS enforcement and the real validation boundary
- added privacy-safe device-profile contribution guidance and demo storyboards
- release workflow now publishes checksummed Linux amd64/arm64 binaries while keeping macOS/Windows as compile gates until distribution signing is addressed
- no classification, experiment, policy-generation, rollback or resolver-mutation semantics changed
