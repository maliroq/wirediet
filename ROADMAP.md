# Roadmap

WireDiet's roadmap is deliberately limited to work justified by observed user needs or validation failures. It is not a feature wishlist.

## v0.1 — prove the workflow honestly

- [x] offline DNS-log imports for CSV/JSON, dnsmasq, AdGuard Home and Pi-hole v6
- [x] evidence/confidence classification with UNKNOWN preserved
- [x] protected update/core-service states
- [x] reversible feature-test engine and final aggregate verification
- [x] exact-host policy exports and rollback manifests
- [x] local loopback-only UI
- [x] community profile/evidence schemas
- [x] real AdGuard Home import against a single isolated client
- [x] live exact-host block/non-broadening/rollback check on an isolated client
- [ ] one real smart-TV/IoT device validation with a privacy-safe public profile
- [ ] macOS Developer ID signing/notarization before publishing prebuilt macOS binaries
- [ ] decide Windows signing/distribution only after testing the real SmartScreen experience

## After v0.1 — only if demand/evidence justifies it

- read-only resolver APIs may replace manual export steps, but only with explicit credential handling and no default mutation
- direct apply mode is not planned until backup, exact preview and tested restore behavior exist for that resolver version
- new adapters should be added from real user demand plus synthetic fixtures, not to increase adapter count
- profile/evidence conflict and freshness tooling should grow only as community data exists to exercise it
