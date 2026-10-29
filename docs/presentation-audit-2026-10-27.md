# Product presentation / local-UI audit — 2026-10-27

Scope: presentation, local read-only UI, README, brand assets and release packaging. No classification, experiment, policy-generation, rollback or resolver-write semantics were intentionally changed.

## Positioning

The README and local UI now state the boundary directly:

- enforcement: AdGuard Home, Pi-hole and other DNS tools
- WireDiet: policy discovery and verification

The primary flow is **Observe → Test → Verify**.

## Local UI review

The UI is still served from the single local Go binary and remains loopback-only with no remote assets.

Reviewed states:

- **navigation/hierarchy** — three stage cards plus detailed Observe/Test/Verify sections
- **typography/spacing** — system fonts, restrained density, responsive cards
- **domains** — monospace rendering with wrapping for long hostnames and horizontally scrollable table on narrow screens
- **evidence/confidence** — separate columns; evidence links are explicit and user-opened
- **UNKNOWN** — deliberately described as “Insufficient evidence. Leave this domain alone.”
- **warnings** — prominent but not styled as catastrophic errors
- **trial state** — optional read-only experiment session can show required features and pending/completed state
- **pass/fail/aggregate verification** — session view surfaces final-verification state without inventing results
- **rollback** — Verify section calls out `rollback.json` and manual resolver application
- **privacy** — local-only/no-telemetry banner; raw analysis link is explicit
- **empty state** — analysis-only view explains that verification has not started rather than calling it a failure
- **responsive layout** — 3/4-column cards collapse to 2 and then 1 column; domain table remains scrollable
- **accessibility** — semantic headings, skip link, keyboard-focus styles, reduced-motion handling, text labels in addition to color
- **appearance** — light/dark palettes use `prefers-color-scheme`; no remote theme scripts

No claim of formal WCAG conformance is made.

The README hero screenshot is rendered from the actual local UI using repository synthetic data. No household DNS history is used in public screenshots.

## Brand assets

The mark shows multiple network paths reaching a trim boundary with one path continuing. It deliberately avoids shield/checkmark, scissors, terminal-prompt and robot imagery.

Public assets:

- `assets/brand/wirediet-mark.svg`
- `assets/brand/wirediet-mark.png`
- `assets/brand/favicon.svg`
- `assets/brand/favicon-64.png`
- `assets/brand/social-preview.svg`
- `assets/brand/social-preview.png`

## Release packaging

Prebuilt release artifacts are limited to Linux amd64/arm64 with SHA-256 checksums. macOS/Windows remain source-build/compile-gate targets until appropriate distribution signing is available. This preserves the Gatekeeper finding from real validation rather than asking users to weaken platform security.
