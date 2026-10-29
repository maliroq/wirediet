# Guided local real-world validation

WireDiet v0.1 does not need resolver credentials or automatic router changes for the remaining validation.

Run from the repository root:

```bash
python3 dev.py
```

## Phase A — deterministic release validation

The harness automatically records macOS/architecture, Python, Go, and repository state, then runs:

- `go vet ./...`
- `go test ./...`
- `go test -race ./...`
- a clean versioned binary build and version check
- synthetic scan/import through CSV, JSON, dnsmasq, AdGuard Home, and Pi-hole adapters
- the synthetic experiment → record → learned-export journey
- malformed-input and oversize-input tests
- evidence/policy injection and loopback-only security tests
- rollback tests
- exact-host rule tests
- privacy/redaction and private-output permission tests

Results are written locally to:

- `artifacts/local_verification_report.txt`
- `artifacts/local_verification_report.json`
- `artifacts/full_validation.log`

`artifacts/` is ignored by Git. The text/JSON reports redact the selected local target identifier. The full log and raw analysis are private local artifacts and may contain local network identifiers or DNS history.

## Phase B — resolver discovery

The interactive phase supports one resolver at a time:

1. Pi-hole
2. AdGuard Home

If neither exists, the harness stops honestly with:

```text
REAL DEVICE VALIDATION: BLOCKED — NO SUPPORTED RESOLVER ENVIRONMENT
```

It does not ask the operator to deploy a resolver just to manufacture a passing result.

## Phase C — minimum safe device trial

The harness asks for one target device, required features, and a small baseline window. It then asks the operator to save a resolver query-log JSON response:

- Pi-hole v6: saved `/api/queries` response
- AdGuard Home: saved `/control/querylog` response

WireDiet itself does not receive resolver passwords. The saved response may contain other clients; `scan --device` isolates only the selected target. The operator confirms that WireDiet's parsed count matches the resolver's count for the same device/window. A missing count remains `NOT VERIFIED`.

Only medium/high-confidence evidence-backed candidates in noncritical categories are eligible for the first live block trial. The harness additionally rejects candidate hostnames containing authentication, security, firmware/update, payment, DRM/licensing, emergency, or safety terms. Unknown domains are never promoted.

The first trial contains at most one or two operator-selected candidates. The harness creates a normal WireDiet experiment session using a derived analysis that omits every unselected block candidate. It shows `rollback.json` **before** application and prints the exact manual rule.

### Pi-hole scoping

Use a temporary group containing only the selected client. Add each candidate as an **exact** denylist domain, assign it only to the temporary group, and remove the temporary domain's Default-group assignment so the test does not become household-wide. The harness never edits Pi-hole itself.

### AdGuard Home scoping

The harness can print a documented anchored client-specific rule for manual use, but the first real validation did **not** rely on that syntax for isolation. Instead, the temporary AdGuard Home lab restricted `allowed_clients` to loopback plus one selected external client, while the custom rule itself was an exact plain hostname. This made client isolation independently testable before any block rule was applied.

A rule such as `||telemetry.example.com^` is intentionally avoided for exact-host tests because it also covers subdomains. The harness never edits AdGuard Home itself. Per-client `$client` rule behavior remains separate from the live exact-host proof unless explicitly exercised.

## Exact-host verification

Phase A includes a literal synthetic exact-host export probe for `telemetry.example.com` and checks that the emitted forms do not encode parent/sibling/subdomain broadening. That deterministic gate tests the WireDiet exporters only.

`EXACT-HOST RULE BEHAVIOR` remains `NOT VERIFIED` until a real resolver is exercised. In the first AdGuard Home validation, a controlled exact-host rule blocked only the target while a parent and sibling resolved normally; that specific live run is documented in `docs/real-world-validation-2026-10-27.md`.

## Failure/split and rollback

If a multi-domain live batch breaks a required feature, the harness continues through WireDiet's existing narrowing logic. It rolls back the current temporary rule before generating/applying the next child trial. `FAILURE/SPLIT CYCLE` is `PASS` only after a narrower child generated from a live failed batch is itself recorded. If no multi-domain failure occurs, it remains `NOT VERIFIED`.

After every applied trial, the harness requires manual removal of the exact temporary rules and asks the operator to confirm baseline device behavior and normal hostname behavior returned. Skips remain `NOT VERIFIED`.

## Patch loop

If a deterministic or applicable live check fails, send back only:

```text
artifacts/local_verification_report.txt
```

Do not send `artifacts/full_validation.log` or `artifacts/real/analysis.json` unless a specific failure requires them; they may contain sensitive local network history.
