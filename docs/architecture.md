# Architecture

## Design goals

WireDiet is deliberately small, auditable and local-first. v0.1 is a single Go binary with no runtime third-party dependencies.

```text
               +-------------------------+
               |  DNS logs / JSON / CSV  |
               +------------+------------+
                            |
                            v
                 +---------------------+
                 |  ingest adapters    |
                 | csv/json/dnsmasq/   |
                 | adguard/pihole      |
                 +----------+----------+
                            |
                            v
                 +---------------------+
                 | normalized events   |
                 +----------+----------+
                            |
                 +----------+----------+
                 |                     |
                 v                     v
        +------------------+   +------------------+
        | evidence engine  |   | device filter    |
        +--------+---------+   +--------+---------+
                 \                   /
                  \                 /
                   v               v
                  +-----------------+
                  | analysis        |
                  | domain findings |
                  +--------+--------+
                           |
             +-------------+-------------+
             |                           |
             v                           v
   +------------------+          +------------------+
   | local web UI     |          | experiment       |
   | read-only view   |          | state machine    |
   +------------------+          +--------+---------+
                                         |
                                         v
                                +------------------+
                                | policy exporters |
                                | + rollback       |
                                +------------------+
```

## Packages

- `internal/ingest`: adapter registry, input limits, parsing, normalization.
- `internal/evidence`: embedded and optional user-supplied evidence database.
- `internal/analyze`: aggregates per-domain observations and applies evidence.
- `internal/experiment`: feature-test state machine and split/narrow logic.
- `internal/policy`: candidate selection, format exporters and rollback manifests.
- `internal/redact`: public-report redaction.
- `internal/report`: bounded, strict JSON persistence and terminal summaries.
- `internal/safejson`: duplicate-key rejection and strict decoding for WireDiet-owned JSON state.
- `internal/safeio`: bounded reads and private atomic file writes.
- `internal/webui`: loopback-only local UI with Host-header validation.

## Experiment algorithm

1. Start with medium/high-confidence `block_candidate` domains only.
2. Never include `protect` or `unknown` domains in automatic candidate batches.
3. Generate a temporary policy bundle for the current batch.
4. User tests every feature they declared important.
5. If all pass, the domains are provisionally safe for those features.
6. If any feature fails and the batch has multiple domains, split the batch in half.
7. If a one-domain batch fails a feature, mark that domain as required for that feature.
8. After narrowing, test the aggregate learned policy.
9. If the aggregate fails despite narrower passes, flag an interaction risk and disable final export.

This is intentionally conservative. Domain interactions can be complex; WireDiet does not pretend binary splitting proves causal independence.

## Why no direct mutation in v0.1

Direct resolver writes add credential storage, version-specific API behavior, rollback complexity and a larger attack surface. They are not necessary to validate the product’s core value. v0.1 generates exact reversible bundles and lets users apply them using the resolver controls they already trust.
