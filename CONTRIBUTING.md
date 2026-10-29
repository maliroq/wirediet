# Contributing to WireDiet

WireDiet should earn trust by being conservative, reproducible and easy to audit.

## Before opening a PR

Run:

```bash
go fmt ./...
go vet ./...
go test -race ./...
python3 dev.py --phase-a-only
```

Do not commit household DNS logs, PCAPs, MAC addresses, private IPs/device names, credentials, resolver tokens or router backups.

## Good code contributions

Useful changes include:

- import-adapter variants with synthetic fixtures
- policy-export exactness tests
- malformed-input and parser-ambiguity cases
- experiment-state interruption/corruption cases
- safer redaction
- local UI accessibility
- documentation that narrows ambiguity

Adapters are documented in `docs/adapters.md`.

## Evidence contributions

A hostname must not become a `block_candidate` because it looks suspicious.

A classification PR should include:

1. exact or suffix pattern and why that scope is justified
2. category and confidence
3. disposition
4. at least one auditable source
5. uncertainty or breakage notes
6. why the evidence does not justify a broader pattern

Prefer vendor documentation, reproducible technical research, well-maintained OSS datasets or multiple independent observations. Community posts can support a claim but should not automatically create high-confidence universal policy.

Software-update, authentication, DRM, payment, emergency and safety-related endpoints should default to `protect` when uncertain.

## Contribute a redacted, verified device experiment/profile

This is the preferred public contribution path for real-device work.

Use `profiles/schema/device-profile.schema.json` and the example profile. A useful submission records:

- device/model family
- firmware/version when known
- region when relevant
- observed hostname(s)
- state for each hostname: `observed`, evidence-backed candidate, or experimentally verified
- evidence reference(s)
- exact features tested
- exact policy/domain set used for the trial
- result and aggregate-verification state
- verification date
- `redaction_reviewed: true` only after a human privacy review

Do **not** submit raw query logs merely to prove that a hostname appeared. Reduce the observation to the minimum profile data needed for reproduction.

Never include:

- private IPs or MAC addresses
- local device names
- household browsing/DNS history
- credentials, API tokens or router backups
- unrelated clients/domains

One contributor's result is one observation. It must not automatically become a universal blocklist rule.

## Tests

New adapters need:

- normal synthetic fixture
- malformed-input case
- ambiguity/duplicate-field case where relevant
- no real private traffic

New exporters need:

- exact output test
- no unintended suffix/subdomain broadening
- injection/malformed-domain test
- rollback coverage

Changes to experiment logic need pass/fail/split/final-verification and interruption-state tests.
