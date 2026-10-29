# Adversarial release audit — 2026-10-27

This audit followed the first real AdGuard Home validation. Its purpose was to find release-blocking ambiguity and privacy/security defects, not to add product scope.

## Findings fixed

### Real AdGuard schema mismatch

**Finding:** the synthetic AdGuard fixture used `question.host`; real AdGuard Home v0.107.79 uses `question.name`.

**Fix:** parse `question.name`, keep legacy `host` only when unambiguous, and reject conflicting dual fields. Added regression coverage based on the real schema shape.

### Sensitive policy bundles were too permissive

**Finding:** generated policies/rollback files can reveal sensitive domains but were written with ordinary `0644` defaults.

**Fix:** policy directories/files are owner-only (`0700`/`0600` where supported), written atomically, and marked complete only after all files finish.

### Session/state trust and corruption

**Finding:** session JSON had insufficient structural validation; malformed or contradictory state could be accepted.

**Fix:** bounded strict decoding, duplicate-key/unknown-field rejection, schema validation, safe trial IDs, domain-set consistency, single-pending-trial enforcement and final-verification consistency checks.

### Analysis-state semantic trust

**Finding:** a hand-edited analysis could preserve valid JSON/schema shape while inventing a `block_candidate` without the evidence/freshness invariants normally produced by `scan`.

**Fix:** analysis reads now validate domain uniqueness/shape, count consistency, category/confidence/disposition combinations, required evidence for candidates/protected findings, stale-evidence state and candidate evidence review freshness before experiment/export use.

### Interruption ordering

**Finding:** a pending trial could be committed before its policy bundle was successfully written.

**Fix:** the policy bundle must complete before the session advances to pending state. A failed bundle write leaves session state unchanged.

### Unbounded secondary JSON inputs

**Finding:** resolver input had a main bound, but custom evidence, analysis and session files did not all have dedicated bounded reads.

**Fix:** bounded reads were added to those WireDiet-owned formats, with regression tests for oversized state.

### Duplicate/ambiguous JSON keys

**Finding:** normal Go JSON decoding accepts duplicate object keys using last-value behavior, which can hide contradictory security-relevant fields.

**Fix:** recursive duplicate-key rejection was added. WireDiet-owned state formats additionally reject unknown fields. Resolver formats remain tolerant of provider-specific extra fields but reject duplicate keys.

### Parser/provenance edge ambiguity

**Finding:** duplicate normalized CSV headers, overlong DNS names, provenance URLs with embedded user-info, and arbitrary corrupted session IDs were additional ambiguity/injection edges.

**Fix:** CSV imports reject duplicate normalized column names; DNS names are capped at the protocol hostname length used by WireDiet policy output; evidence/analysis provenance URLs reject user-info and malformed public hostnames; loaded session IDs must match WireDiet's generated format.

### Evidence provenance and freshness

**Finding:** evidence lacked an enforced database review date, private/localhost URLs were technically possible, and stale candidate evidence could remain actionable indefinitely.

**Fix:** evidence now requires a schema version and `reviewed_at`; all evidence records require sources; source URLs must be HTTP(S) and reject local/private-literal hosts; stale candidate evidence is downgraded to observe/low until reviewed. Seed provenance was also tightened and blocklist-only candidates were downgraded where the evidence did not justify medium/high confidence.

### Redaction gaps

**Finding:** the identifier-redacted output retained the real generation timestamp and did not sanitize all private IPv6/free-text evidence locations.

**Fix:** the real generation timestamp is removed, private/local IPv4 and IPv6/MAC-shaped strings are redacted in supported free-text fields, and evidence source title/URL text is sanitized.

**Remaining boundary:** queried public domain names intentionally remain visible. `wirediet redact` is therefore identifier redaction, not anonymity.

The deterministic harness also scans the committed public reproducibility artifacts for obvious private/local IPs, MAC-shaped values, home-directory paths and exact timestamps. The controlled `0.0.0.0` blocking response is explicitly allowed because it is public test output, not a household identifier.

### Local UI DNS-rebinding surface

**Finding:** loopback binding alone did not validate the HTTP Host header.

**Fix:** the web UI rejects unexpected Host values and adds same-origin/resource/permissions headers in addition to existing CSP/referrer/cache controls.

### Output-path safety

**Finding:** policy output needed stronger guarantees against symlink traversal and partial directories.

**Fix:** policy output rejects a symlink final directory and symlink components in relative output paths, uses private atomic writes and writes a `.complete` marker last.

### macOS binary distribution

**Finding:** a checksummed but unsigned/notarized downloaded macOS CLI binary was blocked/killed by Gatekeeper during real validation.

**Fix:** tagged releases may publish checksummed Linux amd64/arm64 binaries, where this signing problem does not apply. macOS and Windows remain compile gates/source-build targets until an appropriate signing/notarization path exists; raw unsigned binaries are not presented as ordinary-user-ready. Apple recommends Developer ID signing and notarization for software distributed outside the Mac App Store: <https://developer.apple.com/macos/distribution/>.

## Claims deliberately limited after the audit

- A passed feature trial means the tested features passed in that environment; it is not proof of a globally minimal policy.
- No organically observed candidate existed in the first real iPhone baseline; none was invented.
- The controlled exact-host trial is labeled controlled and is not presented as observed telemetry.
- Live failure/split behavior remains `NOT VERIFIED` because no safe live failure occurred.
- Smart-TV/IoT behavior remains `NOT VERIFIED` until such a device is tested.
- DNS-only observation cannot see hard-coded IP traffic or encrypted DNS bypass.

## Anti-vibecode review

The repository intentionally avoids runtime third-party dependencies, speculative adapters and roadmap padding. The audit removed/changed claims rather than adding decorative features. Remaining first-release work is evidence-driven: one real smart-TV/IoT validation and platform-appropriate binary distribution if prebuilt binaries are offered.
