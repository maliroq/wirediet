# Threat model

## Assets

Sensitive assets include:

- household DNS history
- device names and local addresses
- MAC addresses
- resolver credentials or session material
- router/firewall configuration
- knowledge of which devices and services exist in a home
- experiment state and generated policies, which themselves reveal domains

## Malicious or malformed input

Imported files may be oversized, malformed, ambiguous or crafted so untrusted strings become resolver configuration.

Mitigations:

- 50 MiB resolver-input limit and 1,000,000-event limit
- bounded reads for evidence, analysis and session JSON
- scanner line limits for text logs
- duplicate JSON object-key rejection
- strict unknown-field rejection for WireDiet-owned state/config formats
- semantic validation of loaded analyses so forged candidate state cannot bypass evidence/freshness invariants
- hostname normalization/validation during import
- independent hostname validation during policy export
- no shell execution of imported fields
- exact-device/client filtering rather than substring selection

The size limit bounds bytes read by WireDiet; it is not a mathematical bound on all transient parser memory overhead.

## Accidental denial of service to a device

A broad or incorrect block can break streaming, app stores, authentication, updates or other device features.

Mitigations:

- `unknown` stays unknown
- protected update/core-service records are excluded from candidates
- candidate batches require medium/high evidence confidence and current-enough evidence
- exact observed hostnames are emitted instead of suffix-wide rules
- temporary test bundles and rollback manifests are generated before application
- per-feature pass/fail results are explicit
- final aggregate verification is required before learned-policy export
- no automatic router/resolver mutation

A passing policy proves only that the user-selected features passed in the tested environment. It does not prove the policy is globally minimal or safe on every firmware, region or application state.

## State corruption and interruption

Experiment/session files are untrusted local state.

Mitigations:

- bounded, strict JSON decoding
- schema/version and structural validation on load
- trial IDs restricted to a safe generated format
- queue/domain membership and result consistency checks
- at most one pending trial
- atomic owner-only state writes
- a policy bundle must be fully written before a new pending trial is committed to the session
- policy bundles write `.complete` last so interrupted bundles are detectable
- final-verification state must be backed by a corresponding aggregate passing trial

## Filesystem/path safety

Policy output contains potentially sensitive domains and is also a configuration-injection surface.

Mitigations:

- policy directories use owner-only permissions (`0700`) where supported
- generated policy/rollback files use owner-only permissions (`0600`)
- relative output paths with symlink components are rejected, and the final policy directory itself may not be a symlink
- atomic writes avoid exposing partially written final files
- malformed domains are rejected again at export time

## Evidence provenance

Evidence can become stale or maliciously crafted.

Mitigations:

- explicit schema version and `reviewed_at`
- stale candidate evidence is downgraded rather than silently trusted
- candidate/protection records require sources
- evidence URLs must be HTTP(S) URLs whose hostname is not a localhost/private/link-local literal or `.local` name
- exact/suffix evidence scope is recorded
- WireDiet does not fetch evidence URLs at runtime

## Sensitive-data exfiltration by WireDiet itself

Mitigations:

- no cloud service, account, analytics or telemetry
- no runtime evidence fetch
- local UI binds only to loopback
- no remote UI assets
- identifier redaction covers private IPv4/IPv6 forms, MAC-shaped values, free-text evidence/warnings and the real generation timestamp
- the validation harness keeps raw logs/private analysis separate from its sanitized public reproducibility report

Redaction is defense-in-depth, not anonymity: public domain names remain sensitive and visible in normal redacted analyses.

## Browser-based access to the local UI

Mitigations:

- explicit loopback-only bind check
- Host-header validation against the configured loopback listener to reduce DNS-rebinding exposure
- restrictive `Content-Security-Policy`
- `Referrer-Policy: no-referrer`
- `Cross-Origin-Resource-Policy: same-origin`
- restrictive `Permissions-Policy`
- `Cache-Control: no-store`
- no mutation endpoints in v0.1

## Resolver API compromise

The WireDiet CLI does not log in to or mutate Pi-hole/AdGuard Home in v0.1. Manual validation may use resolver-native tools outside WireDiet, but credentials are not part of WireDiet's runtime design.

## Out of scope for v0.1

- defending a compromised host OS or root/admin account
- preventing a device from bypassing DNS with hard-coded IPs, DoH or DoT
- deep packet inspection
- DRM circumvention
- bypassing authentication or payment systems
- proving a hostname is nonessential across every firmware, region or device state
- guaranteeing causality from DNS observations alone

## Safety invariants

WireDiet must not intentionally recommend blocking endpoints known to be required for emergency services, device safety, firmware integrity, authentication security, DRM or payments. When evidence is insufficient, classification should be `unknown`/`observe` or `protect`, not `block_candidate`.
