# Local run and experiment walkthrough

WireDiet v0.1 is intentionally a read-only analyzer and policy generator. It never logs in to or changes your resolver.

## 1. Build and verify

Requires Go 1.23+.

```bash
go test -race ./...
go vet ./...
go build -trimpath -o wirediet ./cmd/wirediet
./wirediet version
```

## 2. Run the synthetic demo first

```bash
./wirediet scan \
  --input examples/synthetic/generic.csv \
  --format csv \
  --device 192.0.2.42 \
  --out analysis.json

./wirediet experiment init \
  --analysis analysis.json \
  --features "Netflix,YouTube,AirPlay,app updates" \
  --session .wirediet/session.json

./wirediet experiment next \
  --session .wirediet/session.json \
  --out-dir .wirediet/policies
```

The last command prints a trial ID and writes a directory for that trial. Inspect `README.txt`, the resolver-specific exact-host rules and `rollback.json` before applying anything.

## 3. Export a real resolver log without giving WireDiet credentials

### Pi-hole v6

Use your normal authenticated Pi-hole interface/API workflow to save a JSON response from `/api/queries`. Current Pi-hole installations expose local API documentation under `/api/docs`. Give the saved file to WireDiet:

```bash
./wirediet scan --input pihole-queries.json --format pihole --device 192.0.2.42 --out analysis.json
```

### AdGuard Home

Save the JSON response from `/control/querylog`, then:

```bash
./wirediet scan --input adguard-querylog.json --format adguard --device 192.0.2.42 --out analysis.json
```

### dnsmasq

Export/copy the relevant query-log window and run:

```bash
./wirediet scan --input dnsmasq.log --format dnsmasq --device 192.0.2.42 --out analysis.json
```

### Generic CSV / downloaded DNS logs

A `domain` column is required. `timestamp`/`time`, `client`/`client_ip`, and `status` are optional.

```bash
./wirediet scan --input queries.csv --format csv --device 192.0.2.42 --out analysis.json
```

Keep raw DNS logs private. Prefer a short observation window in which you deliberately exercise the features you care about.

## 4. Define the features that must survive

Use concrete user-visible behavior, for example:

```bash
./wirediet experiment init \
  --analysis analysis.json \
  --features "Netflix playback,YouTube playback,AirPlay,app updates" \
  --session .wirediet/session.json
```

A feature is a required invariant. If you are unwilling or unable to test one during a trial, record `skip`; WireDiet will not count that trial as verified.

## 5. Generate one reversible trial

```bash
./wirediet experiment next \
  --session .wirediet/session.json \
  --out-dir .wirediet/policies
```

Before applying rules:

1. Back up the resolver configuration using that resolver's normal mechanism.
2. Inspect the exact domains in the trial.
3. Scope temporary rules to the test device/client/group/view when your resolver supports it.
4. If your resolver cannot scope rules, understand that the trial may temporarily affect other clients.
5. Do not broaden exact hostnames into suffix/wildcard blocks.

WireDiet emits exact-host forms for Pi-hole/domain lists, AdGuard, hosts, dnsmasq/OpenWrt and Unbound. The files are examples for manual application; v0.1 never changes the resolver itself.

## 6. Test every declared feature, then record the result

Example:

```bash
./wirediet experiment record \
  --session .wirediet/session.json \
  --trial trial-REPLACE_ME \
  --results "Netflix playback=pass,YouTube playback=pass,AirPlay=fail,app updates=pass"
```

Remove the temporary rules according to `rollback.json` before moving to the next trial unless your manual workflow deliberately replaces the previous temporary set atomically.

If a trial fails, `experiment next` narrows the failing set. A single-domain failure is recorded as required for the failed feature. `skip` never produces a safety claim. A known `fail` takes priority over a simultaneous `skip` so breakage evidence is not lost.

## 7. Final aggregate verification

After narrowing, `experiment next` eventually emits a final aggregate trial. This matters because domains can interact. If the aggregate fails, WireDiet sets an interaction warning and refuses learned-policy export.

Check progress at any time:

```bash
./wirediet experiment status --session .wirediet/session.json
```

## 8. Export only after verification

```bash
./wirediet export --session .wirediet/session.json --out-dir final-policy
```

The normal learned export is refused until final verification passes. `--allow-unverified` exists only for explicit expert use from an analysis file and should not be described as a learned-safe policy.

## 9. Inspect locally in the web UI

```bash
./wirediet serve --analysis analysis.json
```

To include read-only Test/Verify state from an existing experiment session:

```bash
./wirediet serve --analysis analysis.json --session .wirediet/session.json
```

Open `http://127.0.0.1:8787`. The server refuses non-loopback bind addresses, loads no remote UI assets, and never applies resolver changes from the browser.

## Real-network validation status

No external orchestration is required to build or test v0.1. A native AdGuard Home v0.107.79 import against one isolated external client has been exercised, including a live exact-host non-broadening check and rollback. The live failure/split path and an actual smart-TV/IoT feature trial remain `NOT VERIFIED`. See `docs/real-world-validation-2026-10-27.md` and `docs/live-validation.md`.


## Validation report lifecycle

`python3 dev.py --phase-a-only` writes current-run evidence to:

- `artifacts/local_verification_report.txt`
- `artifacts/local_verification_report.json`
- `artifacts/current_run_reproducibility_report.txt`
- `artifacts/current_run_reproducibility_report.json`

Those files describe only the current invocation. They do not replace the committed sanitized historical real-world record under `docs/reproducibility/`.
