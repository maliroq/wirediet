# WireDiet v0.1.0-preview.5

**Cut the chatter. Keep the features.**

WireDiet builds minimal, device-specific DNS policies through evidence and reversible experiments. It is **not** a DNS server, an AdGuard Home/Pi-hole replacement, or a giant blocklist. It helps determine what policy should be enforced by the DNS tool you already use.

## Install

With Go 1.23+ on macOS, Linux, or Windows:

```bash
go install github.com/maliroq/wirediet/cmd/wirediet@v0.1.0-preview.5
wirediet version
```

Windows is compile-gated only in this preview; that command is a source installation path, not a claim of independently validated Windows runtime/distribution behavior.

Linux users may instead download the native release archive for their architecture:

- `wirediet_0.1.0-preview.5_linux_amd64.tar.gz` — x86-64 Linux
- `wirediet_0.1.0-preview.5_linux_arm64.tar.gz` — ARM64 Linux

The release also includes `wirediet_0.1.0-preview.5_source.zip` and `SHA256SUMS.txt`.

macOS intentionally has **no unsigned downloadable executable** in this release. A downloaded unsigned CLI was blocked by Gatekeeper during validation, so WireDiet does not ask users to weaken macOS security. Use `go install` or build from source. Homebrew follows only after the core publication gate is complete.

## Included capabilities

- import saved AdGuard Home, Pi-hole v6, dnsmasq, CSV, and JSON query data
- classify only when loaded evidence supports the classification; UNKNOWN stays UNKNOWN
- generate reversible exact-host trials with rollback manifests
- record required-feature pass/fail results and narrow failed candidate groups
- require aggregate verification before final export
- export exact-host policy for AdGuard Home, Pi-hole/domain lists, dnsmasq/OpenWrt, Unbound, and hosts-style consumers
- local read-only **Observe → Test → Verify** web UI

## Validation boundary

The preserved October 27, 2026 validation includes a real AdGuard Home v0.107.79 import with **147 resolver entries → 147 WireDiet events**, a real external-client baseline, live exact-host behavior, a separately labeled controlled feature-preserving trial, and successful rollback. The real baseline produced **zero defensible low-risk candidates**, and WireDiet left those unknown domains alone.

Still **NOT VERIFIED**:

- a real smart-TV/IoT feature-preservation trial
- a live failure/split cycle

These are explicit limitations, not implied successes. The historical validation record is preserved separately from per-run Phase-A output.

## Safety

WireDiet generates trial/final policy artifacts and rollback information. v0.1 does **not** automatically mutate resolver or router configuration. Exact-host behavior, verification requirements, rollback, privacy/redaction, and UNKNOWN handling remain conservative by design.

## Verify downloads

From a directory containing the release assets and `SHA256SUMS.txt`:

```bash
# macOS
shasum -a 256 -c SHA256SUMS.txt

# Linux
sha256sum -c SHA256SUMS.txt
```

See the README for the quick start, supported inputs/exports, privacy model, and known limitations.
