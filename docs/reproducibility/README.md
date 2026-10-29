# Public reproducibility artifacts

Files in this directory are deliberately sanitized summaries of real validation. They are not raw resolver exports and must not contain private addresses, MAC addresses, device names, credentials, unrelated household domains or exact household event timestamps.

`adguard-real-validation-2026-10-27.json` and `adguard-real-validation-2026-10-27.md` record the first real AdGuard Home/external-client validation. The exact controlled hostname is safe to publish because it was deliberately chosen for the test and was not taken from private household history.

The narrative and limitations are in `../real-world-validation-2026-10-27.md`.

## Historical evidence vs current-run reports

The files in this directory are committed historical evidence. They are pinned by `SHA256SUMS` and `python3 dev.py --phase-a-only` verifies those checksums without rewriting the files.

Each harness invocation writes its own sanitized report to `artifacts/current_run_reproducibility_report.json` and `.txt`. A deterministic Phase-A-only run therefore reports live gates as `NOT VERIFIED` for that invocation without downgrading or replacing the completed real-world experiment recorded here.
