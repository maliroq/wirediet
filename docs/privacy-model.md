# Privacy model

WireDiet treats resolver history as sensitive household data.

## What stays local

Everything in v0.1 is processed locally:

- imported DNS/query logs
- analyses and experiment sessions
- generated test policies and rollback manifests
- the local web UI

There is no WireDiet service or account system.

## What WireDiet does not collect

- no account or email
- no product telemetry or analytics SDK
- no crash upload
- no remote model/LLM call
- no cloud copy of DNS history
- no runtime evidence lookup

Evidence URLs are provenance metadata only. WireDiet does not fetch them while scanning a log.

## Identifier-redacted reports are not anonymous reports

`wirediet redact` is designed to remove common local identifiers from an analysis, including:

- the selected device/client identifier
- private, loopback, link-local and unique-local IP literals found in supported text fields
- MAC-shaped identifiers
- the real analysis generation timestamp
- local identifiers that appear in warning/evidence free text

Raw and identifier-redacted analysis files are written with owner-only permissions (`0600`) on platforms that honor Unix permission bits.

**Queried public domain names remain visible by design.** A domain list can still reveal services, apps, habits, vendors or household equipment. Therefore a redacted analysis is not guaranteed anonymous or automatically safe to publish. Review it manually before sharing.

The validation harness also produces a narrower public reproducibility artifact that intentionally omits raw household domains, private addresses, MACs, device names, feature names and exact timestamps.

## Private generated artifacts

Experiment sessions, policy bundles, rollback manifests and reports may themselves reveal sensitive domains. WireDiet creates these with owner-only file/directory permissions where the platform supports Unix permission bits. Policy bundles use a completion marker written last so an interrupted write can be distinguished from a complete bundle.

## Community profiles

Community profiles should contain only the domains and test outcomes a contributor intentionally chooses to publish. They should not include raw resolver timelines, client addresses, MAC addresses, device names, credentials or unrelated household domains.

A contributor must perform a redaction/privacy review before publication. One person's profile is evidence for that tested environment, not universal truth.

## Fixtures

Repository fixtures are synthetic and use documentation-only address ranges. No real household DNS history, packet capture or router backup should be committed.
