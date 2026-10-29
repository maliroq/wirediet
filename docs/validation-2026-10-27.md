# Validation record — 2026-10-27

This record covers the final `v0.1.0-preview.5` release candidate after the first real AdGuard Home validation, adversarial audit and product-presentation pass. The physical AdGuard Home/external-client experiment itself was performed on the corrected `v0.1.0-preview.2` implementation; that historical provenance is intentionally preserved.

## Deterministic gates

The audited repository passed:

```text
gofmt (no remaining changes)
go vet ./...
go test ./...
go test -race ./...
python3 dev.py --phase-a-only
```

`dev.py --phase-a-only` rebuilt a versioned binary and exercised all five synthetic input adapters, experiment initialization, a complete feature-pass flow, learned export, malformed/oversized input tests, injection tests, rollback tests, exact-host exporter probes, session-corruption checks, DNS-rebinding Host checks and privacy/private-permission regressions.

Synthetic exact-host exporter checks remain synthetic evidence only. The harness correctly leaves the live `EXACT-HOST RULE BEHAVIOR` row as `NOT VERIFIED` when run Phase-A-only.

## Input adapters

Deterministic fixture coverage is green for:

- generic CSV
- generic JSON
- dnsmasq query logs
- AdGuard Home query-log JSON using current `question.name`
- Pi-hole v6 query JSON

Provider-specific extra JSON fields remain tolerated, while duplicate object keys are rejected.

## Export adapters

Deterministic exact-host and rollback coverage is green for:

- plain/Pi-hole exact domains
- AdGuard Home
- hosts
- dnsmasq/OpenWrt
- Unbound-style local data

Policy bundles are private by default and use a completion marker to distinguish fully materialized output from interruption.

## Real evidence

Separate real-world validation on the same date established:

- AdGuard Home v0.107.79 exact-client export: 147 entries, one client
- corrected WireDiet import: 147 events
- 43 unique observed domains
- no evidence-backed safe candidate was manufactured from the baseline
- live exact-host block/non-broadening: PASS in a controlled AdGuard Home trial
- feature-preserving controlled trial: PASS
- rollback/restoration: PASS
- live failure/split: NOT VERIFIED
- smart-TV/IoT feature behavior: NOT VERIFIED

See `docs/real-world-validation-2026-10-27.md`.

## Distribution finding

A checksummed raw macOS CLI binary was blocked/killed by Gatekeeper in real use. The presentation candidate therefore publishes prebuilt binaries only for Linux amd64/arm64; macOS and Windows remain source-build/compile-gate targets until appropriate signing is implemented. Cross-compilation is not a distribution-readiness claim.

## Security audit

The post-validation adversarial audit and remaining boundaries are documented in `docs/security-audit-2026-10-27.md`.


## Evidence-artifact lifecycle

The committed real-world evidence under `docs/reproducibility/` is historical evidence and is pinned by SHA-256. Current harness runs write separate `artifacts/current_run_reproducibility_report.*` files. A Phase-A-only run therefore leaves physical-validation rows `NOT VERIFIED` for that invocation without overwriting the historical PASS/NOT VERIFIED record from the completed 2026-10-27 experiment.

The final harness also rejects escaped/malformed release version strings and requires the built binary to print exactly `wirediet v0.1.0-preview.5`.
