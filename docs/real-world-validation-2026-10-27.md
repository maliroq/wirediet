# Real-world validation — 2026-10-27

This report records the first real AdGuard Home/external-client validation of WireDiet. The hardened source tree produced after the audit identifies as `v0.1.0-preview.2` in the validation harness. It intentionally omits private addresses, MAC addresses, device names, unrelated household domains, credentials and exact household event timestamps.

## Environment and isolation

- Resolver: native AdGuard Home v0.107.79 on a secondary Apple-silicon Mac.
- Existing AdGuard for Mac remained installed/running.
- AdGuard Home's admin UI stayed loopback-only.
- During the external-client test, DNS access was allowlisted to loopback plus one selected iPhone client; unrelated LAN clients were denied.
- Router-wide DNS was not changed.
- The primary Mac was not made the resolver and was not reconfigured.
- Default AdGuard filter-list blocking was disabled for the passive baseline.

## Real resolver baseline

A frozen query-log export was made for exactly one external client:

- AdGuard Home entries: **147**
- distinct clients in private export: **1**
- WireDiet parsed events after the AdGuard adapter fix: **147**
- observed unique domains in the resulting analysis: **43**
- private client identifier absent from the identifier-redacted analysis: **PASS**

### Interoperability defect discovered

The initial preview adapter expected a synthetic `question.host` field. Real AdGuard Home v0.107.79 `/control/querylog` data uses `question.name`, so the initial real import correctly failed rather than fabricating events.

The adapter was fixed to:

- parse current `question.name`
- retain legacy `question.host` compatibility only when unambiguous
- reject records where both fields exist with conflicting values

The same frozen 147-entry export then produced a **147 → 147** count match.

## Candidate selection result

WireDiet found **zero** medium/high-confidence evidence-backed low-risk candidates in the real baseline. An additional local exact-domain cross-check of the 43 observed domains against DuckDuckGo Tracker Radar also produced zero low-risk exact matches.

No unknown hostname was promoted or selected merely to complete the test.

## Controlled exact-host trial

Because the organic baseline had no defensible candidate, the block behavior was validated separately with the deliberately controlled public hostname `www.google-analytics.com`, which Google documents as a Google Analytics collection endpoint. This hostname was **not claimed to be organically observed iPhone telemetry**.

Controlled custom rule:

```text
www.google-analytics.com
```

AdGuard documents domains-only syntax as exact-host behavior, distinct from the subtree-wide `||example.org^` form: <https://adguard-dns.io/kb/general/dns-filtering-syntax/>. Google Analytics collection reference: <https://developers.google.com/analytics/devguides/collection/protocol/ga4/reference>.

Live AdGuard Home DNS behavior:

- `www.google-analytics.com`: blocked to `0.0.0.0`
- `google-analytics.com`: resolved normally
- `ssl.google-analytics.com`: resolved normally

Result: **EXACT-HOST RULE BEHAVIOR — PASS**.

## Feature-preservation trial

With the controlled exact-host rule active and cellular data disabled on the selected iPhone:

- App Store search/page use: **PASS**
- a second ordinary Internet app: **PASS**

Result: **CONTROLLED FEATURE-PRESERVING TRIAL — PASS**.

This result validates the isolated resolver/rule/feature-test workflow. It does not establish that any organically observed hostname from the baseline is safe to block.

## Rollback

After the controlled trial:

- the custom rule was removed
- AdGuard filter-list/protection settings were returned to the passive lab state
- iPhone DNS was restored to Automatic
- the controlled hostname resolved to normal public addresses again
- normal iPhone behavior was confirmed restored

Result: **RESTORATION AFTER ROLLBACK — PASS**.

## Validation matrix

| Gate | Result |
|---|---|
| Real AdGuard Home resolver import | PASS |
| Real external-client baseline | PASS |
| Exact-host resolver behavior | PASS |
| Controlled feature-preserving trial | PASS |
| Restoration after rollback | PASS |
| Live failure/split cycle | NOT VERIFIED |
| Real smart-TV/IoT feature trial | NOT VERIFIED |

The failure/split cycle was not forced because the live feature test passed. Deliberately breaking a useful feature solely to turn that row green would provide worse evidence, not better evidence.

A real smart-TV/IoT profile remains a separate release-validation goal; an iPhone external client is not presented as smart-TV support.
