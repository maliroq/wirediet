# Sanitized AdGuard Home real-validation record — 2026-10-27

This artifact contains no private IP address, MAC address, device name, credential, household DNS history or exact household event timestamp. It is a reproducibility summary, not the raw resolver export.

## Software

- WireDiet: `v0.1.0-preview.2`
- Resolver: AdGuard Home `v0.107.79`
- Deployment: native secondary macOS host
- Admin UI: loopback-only
- DNS access during the external-client test: loopback plus one allowlisted client

## Real import

- exact-client resolver entries: **147**
- WireDiet parsed events: **147**
- distinct clients in private export: **1**
- unique domains observed privately: **43**
- result: **PASS**

The first preview failed against the real AdGuard schema because it expected `question.host`. The corrected adapter parses current `question.name`, retains legacy `host` only when unambiguous and rejects conflicts. The same frozen export then produced the 147 → 147 match.

## Candidate selection

- WireDiet evidence-backed low-risk candidates: **0**
- independent exact-domain Tracker Radar low-risk matches: **0**
- UNKNOWN promoted to telemetry/tracking: **no**

No private baseline hostname was selected merely to complete the test.

## Controlled exact-host behavior

A deliberately public control hostname was used separately from the private baseline: `www.google-analytics.com`.

- target: blocked to `0.0.0.0`
- parent control `google-analytics.com`: resolved normally
- sibling control `ssl.google-analytics.com`: resolved normally
- result: **PASS**

This proves the tested AdGuard Home rule did not broaden to those parent/sibling names. It does not claim the control hostname was organically observed from the client.

## Feature preservation and rollback

With cellular disabled, two ordinary Internet features were exercised on the isolated external client while the exact-host rule was active; both passed. The rule was then removed, client DNS was restored to automatic, the control hostname resolved normally again, and normal client behavior was restored.

- controlled feature-preserving trial: **PASS**
- restoration after rollback: **PASS**
- live failure/split cycle: **NOT VERIFIED**
- real smart-TV/IoT feature trial: **NOT VERIFIED**

The failure/split cycle was not forced because no safe live failure occurred.
