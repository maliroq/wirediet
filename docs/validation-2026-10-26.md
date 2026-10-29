# Validation record — 2026-10-26 (superseded)

This record describes the checks performed on the original v0.1.0-preview source before packaging. It is retained for history and is superseded by `docs/validation-2026-10-27.md` plus the real-world validation/security-audit records.

## Toolchain

- Go 1.23.2
- Linux amd64 build host
- runtime dependencies: Go standard library only

## Automated checks passed

```text
go fmt ./...
go vet ./...
go test -race ./...
```

Coverage includes:

- CSV, generic JSON, dnsmasq, AdGuard Home and Pi-hole v6 imports
- current Pi-hole nested client object parsing
- device filtering that excludes clientless/other-client traffic
- malformed/oversized input rejection
- malformed evidence and unsafe evidence-URL rejection
- label-boundary-safe suffix evidence matching
- candidate/protected/unknown separation
- exact-host policy export semantics
- policy/config-injection rejection
- rollback manifest generation
- feature pass/fail/split behavior
- `skip` never becoming verification
- failure taking priority over simultaneous skip
- duplicate/unknown feature-result rejection
- local UI loopback-only binding
- report redaction

## End-to-end CLI smoke passed

The packaged workflow was exercised with repository synthetic data:

```text
scan -> redacted report -> experiment init -> experiment next ->
record all required features pass -> learned export -> rollback manifest
```

All five input adapters were separately scanned against their synthetic fixtures.

The generated final-policy files were checked to ensure they did not contain the broader forms `||domain^`, dnsmasq `address=/domain/`, or Unbound `always_nxdomain` for learned exact hosts.

## Local UI smoke passed

A real local server was started on loopback and fetched over HTTP. It returned the analysis and included:

- `Cache-Control: no-store`
- restrictive `Content-Security-Policy`
- `Referrer-Policy: no-referrer`
- `X-Content-Type-Options: nosniff`

## Cross-compilation passed

The same source cross-compiled with `CGO_ENABLED=0` for:

- Linux amd64
- Linux arm64
- macOS amd64
- macOS arm64
- Windows amd64
- Windows arm64

The resulting files were inspected as ELF, Mach-O or PE executables as appropriate and SHA-256 checksums were generated.

## Still requires external validation

Synthetic testing cannot prove the behavior of every resolver release or smart-device firmware. Before calling v0.1 production-validated, run the narrow manual matrix in `docs/live-validation.md` against current Pi-hole and AdGuard Home installations and at least one real IoT device. WireDiet does not need write credentials for that validation.
