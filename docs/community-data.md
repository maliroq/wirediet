# Community data model

The public contribution unit is a **redacted, verified device experiment/profile**, not a raw household DNS dump.

A profile should answer:

> “On this model family, firmware and region, what happened when this exact hostname or domain set was tested while these exact features were checked?”

It must not imply:

> “One contributor blocked it, therefore everyone should.”

## Required context

Record when available:

- device/model family
- firmware/version
- region when endpoint behavior may vary
- exact observed hostname(s)
- state: observed, evidence-backed candidate, or verified by experiment
- evidence references
- exact feature(s) tested
- exact trial policy
- pass/fail/partial result
- aggregate verification result
- verification date
- limitations/uncertainty
- explicit privacy-redaction review

## Privacy boundary

Do not contribute raw household DNS history.

A public profile must exclude private IPs, MAC addresses, local device names, credentials, resolver tokens, router backups and unrelated household domains/clients.

`redaction_reviewed: true` means a human intentionally reviewed the profile for private identifiers. It is not an automatic anonymity guarantee.

## Evidence boundary

Observation is not classification. Classification is not verification.

Keep those states separate:

1. **Observed** — the device queried the hostname.
2. **Candidate** — auditable evidence supports a testable nonessential classification.
3. **Verified** — the exact trial was performed and the recorded required features passed.

Contradictory results should be preserved with their device/firmware/region context rather than collapsed into one universal answer.

## Schema

`profiles/schema/device-profile.schema.json` constrains schema version, hostname shape, field lengths, classification vocabulary and evidence-reference URL shape. Schema validation is necessary but not sufficient: reviewers must still verify that evidence supports the claim and that free-text fields do not leak private context.
