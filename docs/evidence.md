# Evidence and classification

WireDiet separates **observation** from **classification**.

A DNS query proves only that a client asked for a hostname. It does not prove why the hostname was queried, whether an application successfully transmitted data, or whether blocking it is safe.

## Evidence database

The evidence database has a schema version, a database-level `reviewed_at` date and individual records. Each record contains:

- `pattern`: hostname or suffix
- `match`: `exact` or `suffix`
- `category`
- `confidence`: `high`, `medium`, `low`
- `disposition`: `block_candidate`, `protect`, `observe`
- optional explanatory `notes`
- auditable `sources[]`

WireDiet rejects duplicate JSON keys, unsupported schema versions and evidence-source URLs that use non-HTTP(S) schemes or name localhost/private/link-local literal hosts. This rejects obvious local/private-literal provenance URLs; WireDiet does not resolve or fetch evidence hosts at runtime.

## Categories

Current vocabulary:

- `core_service`
- `cdn`
- `authentication`
- `software_update`
- `streaming_service`
- `telemetry`
- `advertising`
- `acr`
- `content_recognition`
- `crash_reporting`
- `vendor_analytics`
- `unknown`

## Confidence

`high` means the endpoint purpose is strongly documented for the scoped hostname/pattern. It does **not** mean the endpoint is guaranteed safe to block.

`medium` means useful but incomplete evidence exists, often with device, region, firmware or feature caveats.

`low` is informational and is not automatically promoted into a test policy.

## Disposition

- `block_candidate`: eligible for a controlled feature test when confidence is medium/high.
- `protect`: excluded from generated block candidates.
- `observe`: information only.

Every evidence record must have at least one auditable source. `block_candidate` is accepted only for the noncritical telemetry/advertising/ACR/content-recognition/crash-reporting/vendor-analytics categories and only at medium/high confidence. A hostname must not become a candidate merely because its name looks suspicious or because an LLM says it is tracking.

## Freshness

Evidence is not timeless. The database-level `reviewed_at` value records when candidate/protection evidence was last reviewed. If that review is more than 365 days old, WireDiet conservatively downgrades `block_candidate` records to `observe`/low until the evidence is reviewed again. `protect` records remain protected because stale protection is safer than silently exposing a known-sensitive category to blocking.

The analysis records the evidence review date and whether candidate evidence is stale.

## Conflicts and suffix scope

If multiple evidence records match the same observed hostname, any matching `protect` record wins over candidate/observe evidence. Safety is not allowed to lose merely because a conflicting candidate is more specific. Without a protection conflict, exact and then longest-suffix matching determine the classification.

A suffix evidence record can classify an observed exact hostname, but WireDiet policy generation still emits only the **exact observed hostname**. Classification scope and resolver-rule scope are intentionally separate.

## Seed evidence

The embedded seed is deliberately small. It is a model for auditable provenance, not a universal smart-device blocklist. Blocklist-only observations are not sufficient on their own for medium/high `block_candidate` status.
