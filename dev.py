#!/usr/bin/env python3
"""WireDiet local release + guided real-world validation harness.

Run from the repository root:

    python3 dev.py

The harness never changes resolver/router configuration. Phase A is fully
local/deterministic. Phase B/C only guides manual Pi-hole or AdGuard Home
validation and records exactly what the operator confirms.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
LOG_PATH = ARTIFACTS / "full_validation.log"
TXT_REPORT = ARTIFACTS / "local_verification_report.txt"
JSON_REPORT = ARTIFACTS / "local_verification_report.json"
CURRENT_RUN_REPRO_TXT = ARTIFACTS / "current_run_reproducibility_report.txt"
CURRENT_RUN_REPRO_JSON = ARTIFACTS / "current_run_reproducibility_report.json"
HISTORICAL_REPRO_MANIFEST = ROOT / "docs" / "reproducibility" / "SHA256SUMS"
BIN_PATH = ARTIFACTS / "wirediet-validation-bin"
VERSION = "v0.1.0-preview.5"

PASS = "PASS"
FAIL = "FAIL"
NOT_VERIFIED = "NOT VERIFIED"

MATRIX_ORDER = [
    "GO TOOLCHAIN",
    "UNIT TESTS",
    "RACE TESTS",
    "BUILD",
    "SYNTHETIC END-TO-END",
    "ALL INPUT ADAPTERS",
    "ALL EXPORT ADAPTERS",
    "ROLLBACK",
    "PRIVACY/REDACTION",
    "REAL RESOLVER IMPORT",
    "REAL DEVICE BASELINE",
    "EXACT-HOST RULE BEHAVIOR",
    "FEATURE-PRESERVING TRIAL",
    "FAILURE/SPLIT CYCLE",
    "RESTORATION AFTER ROLLBACK",
]

SAFE_CATEGORIES = {
    "telemetry": 0,
    "vendor_analytics": 1,
    "crash_reporting": 2,
    "advertising": 3,
    "acr": 4,
    "content_recognition": 4,
}

# Extra guardrail on top of WireDiet's evidence disposition. A hostname that
# contains one of these tokens is not selected automatically for a live block
# trial even if a custom evidence file classified it as a candidate.
CRITICAL_TOKENS = {
    "auth", "login", "oauth", "token", "account", "identity", "signin",
    "security", "secure", "cert", "certificate", "key", "firmware",
    "update", "upgrade", "ota", "payment", "payments", "billing", "pay",
    "drm", "license", "licensing", "widevine", "playready", "fairplay",
    "emergency", "sos", "safety", "alarm",
}


class Tee:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fp = path.open("a", encoding="utf-8", buffering=1)

    def write(self, msg: str, *, screen: bool = True) -> None:
        if screen:
            sys.stdout.write(msg)
            sys.stdout.flush()
        self.fp.write(msg)
        self.fp.flush()

    def line(self, msg: str = "", *, screen: bool = True) -> None:
        self.write(msg + "\n", screen=screen)

    def close(self) -> None:
        self.fp.close()


log: Tee
report: Dict[str, Any]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass


def chmod_private(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def reset_artifacts() -> None:
    ensure_private_dir(ARTIFACTS)
    # Preserve no old report/log state that could be confused with this run.
    for p in (LOG_PATH, TXT_REPORT, JSON_REPORT, CURRENT_RUN_REPRO_TXT, CURRENT_RUN_REPRO_JSON):
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def print_header(title: str) -> None:
    log.line()
    log.line("=" * 78)
    log.line(title)
    log.line("=" * 78)


def set_matrix(name: str, status: str, detail: str = "") -> None:
    if status not in {PASS, FAIL, NOT_VERIFIED}:
        raise ValueError(status)
    report["matrix"][name] = {"status": status, "detail": detail}
    write_reports()


def add_check(name: str, status: str, detail: str = "", command: Optional[List[str]] = None) -> None:
    entry: Dict[str, Any] = {"name": name, "status": status, "detail": detail}
    if command:
        entry["command"] = command
    report["checks"].append(entry)
    write_reports()


def run(cmd: List[str], *, cwd: Path = ROOT, env: Optional[Dict[str, str]] = None,
        quiet: bool = False) -> subprocess.CompletedProcess[str]:
    rendered = " ".join(shell_quote(x) for x in cmd)
    log.line(f"$ {rendered}", screen=not quiet)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    try:
        cp = subprocess.run(
            cmd,
            cwd=str(cwd),
            env=merged_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        cp = subprocess.CompletedProcess(cmd, 127, stdout=str(exc) + "\n")
    if cp.stdout:
        log.write(cp.stdout, screen=not quiet)
    log.line(f"[exit {cp.returncode}]", screen=not quiet)
    return cp


def shell_quote(s: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=+,-]+", s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def command_check(name: str, cmd: List[str], *, quiet: bool = False) -> bool:
    cp = run(cmd, quiet=quiet)
    ok = cp.returncode == 0
    add_check(name, PASS if ok else FAIL, f"exit={cp.returncode}", cmd)
    return ok


def parse_go_version(text: str) -> Optional[Tuple[int, int, int]]:
    m = re.search(r"\bgo(\d+)\.(\d+)(?:\.(\d+))?\b", text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)


def validate_release_version_literal() -> Tuple[bool, str]:
    """Reject escaped or malformed release-version strings before build injection."""
    expected_shape = re.fullmatch(r"v\d+\.\d+\.\d+-preview\.\d+", VERSION) is not None
    no_escape = "\\" not in VERSION
    ok = expected_shape and no_escape
    detail = f"literal={VERSION!r}; expected output='wirediet {VERSION}'"
    return ok, detail


def historical_reproducibility_integrity_check() -> Tuple[bool, str]:
    """Pin committed historical evidence so current-run validation cannot replace it."""
    if not HISTORICAL_REPRO_MANIFEST.is_file():
        return False, f"missing {HISTORICAL_REPRO_MANIFEST.relative_to(ROOT)}"
    problems: List[str] = []
    checked = 0
    for raw in HISTORICAL_REPRO_MANIFEST.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split(None, 1)
        if len(parts) != 2:
            problems.append("malformed SHA256SUMS line")
            continue
        expected, rel = parts
        rel = rel.lstrip("*")
        path = ROOT / "docs" / "reproducibility" / rel
        if not path.is_file():
            problems.append(f"missing {path.relative_to(ROOT)}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        checked += 1
        if actual != expected:
            problems.append(f"checksum mismatch for {path.relative_to(ROOT)}")
    if problems:
        return False, "; ".join(problems)
    if checked == 0:
        return False, "historical reproducibility manifest contains no files"
    return True, f"{checked} committed historical evidence files match pinned SHA-256 values"


def detect_environment() -> bool:
    print_header("PHASE A — ENVIRONMENT")
    env: Dict[str, Any] = {
        "platform": platform.platform(),
        "system": platform.system(),
        "macos_version": platform.mac_ver()[0] or None,
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
        "repository_root": str(ROOT),
    }
    cp = run(["go", "version"], quiet=True)
    env["go_version_raw"] = cp.stdout.strip() if cp.returncode == 0 else None
    parsed = parse_go_version(cp.stdout) if cp.returncode == 0 else None
    env["go_version"] = ".".join(map(str, parsed)) if parsed else None

    git = run(["git", "rev-parse", "--is-inside-work-tree"], quiet=True)
    if git.returncode == 0 and git.stdout.strip() == "true":
        commit = run(["git", "rev-parse", "HEAD"], quiet=True)
        status = run(["git", "status", "--short"], quiet=True)
        env["repository_state"] = {
            "git": True,
            "commit": commit.stdout.strip() if commit.returncode == 0 else None,
            "dirty": bool(status.stdout.strip()),
            "status": status.stdout.splitlines(),
        }
    else:
        env["repository_state"] = {"git": False, "note": "source tree is not a Git working tree"}

    report["environment"] = env
    toolchain_ok = cp.returncode == 0 and parsed is not None and parsed >= (1, 23, 0)
    detail = env["go_version_raw"] or "Go executable not found"
    if parsed and parsed < (1, 23, 0):
        detail += " (WireDiet requires Go 1.23+)"
    set_matrix("GO TOOLCHAIN", PASS if toolchain_ok else FAIL, detail)
    log.line(f"Platform: {env['system']} {env['macos_version'] or ''} / {env['architecture']}")
    log.line(f"Python:   {env['python_version']}")
    log.line(f"Go:       {env['go_version_raw'] or 'NOT FOUND'}")
    if platform.system() != "Darwin":
        log.line("Note: this harness is intended for macOS real-device validation; Phase A is portable.")
    return toolchain_ok


def static_public_artifact_privacy_check() -> Tuple[bool, str]:
    """Reject obvious local identifiers in committed public validation artifacts."""
    paths = [
        ROOT / "docs" / "real-world-validation-2026-10-27.md",
        ROOT / "docs" / "reproducibility" / "adguard-real-validation-2026-10-27.json",
        ROOT / "docs" / "reproducibility" / "adguard-real-validation-2026-10-27.md",
    ]
    problems: List[str] = []
    mac_re = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    # Broad enough for normal IPv6 text; ipaddress performs the real decision.
    ipv6_re = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")
    timestamp_re = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})\b")

    for path in paths:
        if not path.is_file():
            problems.append(f"missing public artifact {path.relative_to(ROOT)}")
            continue
        text = path.read_text(encoding="utf-8")
        if mac_re.search(text):
            problems.append(f"MAC-shaped value in {path.relative_to(ROOT)}")
        if "/Users/" in text or "\\Users\\" in text:
            problems.append(f"local home path in {path.relative_to(ROOT)}")
        if timestamp_re.search(text):
            problems.append(f"exact timestamp in {path.relative_to(ROOT)}")
        for token in ipv4_re.findall(text) + ipv6_re.findall(text):
            try:
                ip = ipaddress.ip_address(token.strip("[]"))
            except ValueError:
                continue
            if str(ip) == "0.0.0.0":
                # Public controlled trial documents the resolver's null-route response.
                continue
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                problems.append(f"local/private IP in {path.relative_to(ROOT)}")
                break
    if problems:
        return False, "; ".join(sorted(set(problems)))
    return True, "committed reproducibility artifacts contain no obvious local IP/MAC/home-path/exact-timestamp values"


def phase_a() -> bool:
    toolchain_ok = detect_environment()
    if not toolchain_ok:
        log.line("Go toolchain requirement failed; remaining Go checks will be recorded as failures.")

    print_header("PHASE A — DETERMINISTIC RELEASE VALIDATION")

    vet_ok = command_check("go vet", ["go", "vet", "./..."])
    unit_ok = command_check("unit tests", ["go", "test", "./...", "-count=1"])
    set_matrix("UNIT TESTS", PASS if unit_ok else FAIL, "go test ./... -count=1")

    race_ok = command_check("race tests", ["go", "test", "-race", "./...", "-count=1"])
    set_matrix("RACE TESTS", PASS if race_ok else FAIL, "go test -race ./... -count=1")

    version_literal_ok, version_literal_detail = validate_release_version_literal()
    version_literal_status = PASS if version_literal_ok else FAIL
    add_check("version string literal", version_literal_status, version_literal_detail)
    log.line(f"{version_literal_status}: version string literal — {version_literal_detail}")

    try:
        BIN_PATH.unlink()
    except FileNotFoundError:
        pass
    build_cmd = [
        "go", "build", "-trimpath",
        "-ldflags", f"-X main.version={VERSION}",
        "-o", str(BIN_PATH), "./cmd/wirediet",
    ]
    build_ok = command_check("clean build", build_cmd)
    if build_ok:
        try:
            BIN_PATH.chmod(0o700)
        except OSError:
            pass
    version_ok = False
    if build_ok:
        cp = run([str(BIN_PATH), "version"])
        version_ok = cp.returncode == 0 and cp.stdout.strip() == f"wirediet {VERSION}"
        add_check("version check", PASS if version_ok else FAIL,
                  f"expected 'wirediet {VERSION}', got {cp.stdout.strip()!r}",
                  [str(BIN_PATH), "version"])
    else:
        add_check("version check", FAIL, "build failed")
    set_matrix("BUILD", PASS if (build_ok and version_ok) else FAIL,
               "clean build + embedded version check")

    # Targeted safety checks are deliberately repeated even though they are
    # included in the full unit suite. This makes the report actionable.
    malformed_ok = command_check(
        "malformed-input tests",
        ["go", "test", "./internal/ingest", "-run", "TestMalformedJSON|TestRejectsOversizeFile|TestCSVRejectsDuplicateNormalizedHeaders|TestRejectsOverlongDomain", "-count=1"],
    )
    injection_ok = command_check(
        "injection/security tests",
        ["go", "test", "./internal/policy", "./internal/evidence", "./internal/report", "./internal/webui", "./internal/safejson",
         "-run", "TestRejectsPolicyInjection|TestRejectsMalformedEvidence|TestRejectsEvidenceURLUserInfo|TestReadAnalysisRejectsUnsafeEvidenceURLHost|TestLoopbackOnly|TestAllowedHostRejectsDNSRebindingHost|TestRejectsDuplicateKeys", "-count=1"],
    )
    rollback_ok = command_check(
        "rollback tests",
        ["go", "test", "./internal/policy", "-run", "TestBundleAndRollback", "-count=1"],
    )
    exactness_ok = command_check(
        "exact-host export tests",
        ["go", "test", "./internal/policy", "-run", "TestExactHost", "-count=1"],
    )
    privacy_ok = command_check(
        "privacy/redaction tests",
        ["go", "test", "./internal/redact", "./internal/report", "./internal/policy",
         "-run", "TestAnalysisRedactsDeviceAndTiming|TestAnalysisRedactsGeneratedTimeIPv6AndEvidenceText|TestWriteJSONUsesPrivatePermissions|TestBundleUsesPrivatePermissions", "-count=1"],
    )
    public_privacy_ok, public_privacy_detail = static_public_artifact_privacy_check()
    add_check("public reproducibility privacy scan", PASS if public_privacy_ok else FAIL, public_privacy_detail)
    historical_ok, historical_detail = historical_reproducibility_integrity_check()
    historical_status = PASS if historical_ok else FAIL
    add_check("historical real-world evidence preserved", historical_status, historical_detail)
    log.line(f"{historical_status}: historical real-world evidence preserved — {historical_detail}")
    privacy_ok = privacy_ok and public_privacy_ok and historical_ok
    split_ok = command_check(
        "experiment split/verification tests",
        ["go", "test", "./internal/experiment",
         "-run", "TestFailureSplitsAndFindsRequired|TestSkippedFeatureDoesNotVerifyPolicy|TestFailTakesPriorityOverSkip|TestRejectsUnknownAndDuplicateFeatureResults|TestLoadRejectsCorruptedSessionState|TestLoadRejectsPathTraversalTrialID|TestLoadRejectsInvalidSessionID|TestNextBundleFailureDoesNotCommitPendingTrial",
         "-count=1"],
    )
    set_matrix("ROLLBACK", PASS if rollback_ok else FAIL, "policy rollback manifest tests")
    set_matrix("PRIVACY/REDACTION", PASS if privacy_ok else FAIL, "redaction + private file permission tests")

    synthetic_ok = False
    inputs_ok = False
    exports_ok = False
    if build_ok and version_ok:
        synthetic_ok, inputs_ok, exports_ok, semantic_exact_ok = synthetic_journey()
        exactness_ok = exactness_ok and semantic_exact_ok
    else:
        add_check("synthetic end-to-end", FAIL, "build/version check failed")
        semantic_exact_ok = False

    set_matrix("SYNTHETIC END-TO-END", PASS if synthetic_ok else FAIL,
               "all-adapter scans + experiment + learned export")
    set_matrix("ALL INPUT ADAPTERS", PASS if inputs_ok else FAIL,
               "csv,json,dnsmasq,adguard,pihole")
    set_matrix("ALL EXPORT ADAPTERS", PASS if exports_ok else FAIL,
               "Pi-hole, AdGuard, hosts, dnsmasq/OpenWrt, Unbound")
    set_matrix("EXACT-HOST RULE BEHAVIOR", NOT_VERIFIED if exactness_ok else FAIL,
               "synthetic exporter exactness passed; live resolver behavior not yet verified" if exactness_ok else "synthetic exact-host verification failed")

    all_phase_a = all([
        toolchain_ok, vet_ok, unit_ok, race_ok, version_literal_ok, build_ok, version_ok,
        malformed_ok, injection_ok, rollback_ok, exactness_ok, privacy_ok,
        split_ok, synthetic_ok, inputs_ok, exports_ok,
    ])
    report["phase_a_pass"] = all_phase_a
    write_reports()
    return all_phase_a


def synthetic_journey() -> Tuple[bool, bool, bool, bool]:
    print_header("PHASE A — SYNTHETIC END-TO-END")
    synth_dir = ARTIFACTS / "synthetic"
    if synth_dir.exists():
        shutil.rmtree(synth_dir)
    ensure_private_dir(synth_dir)

    fixtures = [
        ("csv", "generic.csv", 7),
        ("json", "generic.json", 3),
        ("dnsmasq", "dnsmasq.log", 4),
        ("adguard", "adguard.json", 4),
        ("pihole", "pihole.json", 3),
    ]
    adapter_results: Dict[str, Any] = {}
    all_inputs = True
    for fmt, filename, expected_count in fixtures:
        out = synth_dir / f"{fmt}-analysis.json"
        cmd = [
            str(BIN_PATH), "scan",
            "--input", str(ROOT / "examples" / "synthetic" / filename),
            "--format", fmt,
            "--device", "192.0.2.42",
            "--out", str(out),
        ]
        cp = run(cmd)
        ok = cp.returncode == 0 and out.exists()
        parsed: Dict[str, Any] = {}
        if ok:
            try:
                parsed = json.loads(out.read_text(encoding="utf-8"))
                ok = (
                    parsed.get("source_format") == fmt
                    and parsed.get("event_count") == expected_count
                    and parsed.get("device") == "192.0.2.42"
                )
            except Exception as exc:  # noqa: BLE001
                log.line(f"Could not parse {out}: {exc}")
                ok = False
        adapter_results[fmt] = {
            "status": PASS if ok else FAIL,
            "expected_queries": expected_count,
            "parsed_queries": parsed.get("event_count") if parsed else None,
        }
        all_inputs = all_inputs and ok
        add_check(f"input adapter {fmt}", PASS if ok else FAIL,
                  f"expected={expected_count}, parsed={parsed.get('event_count') if parsed else None}", cmd)

    report["synthetic"]["input_adapters"] = adapter_results
    if not all_inputs:
        write_reports()
        return False, False, False, False

    analysis = synth_dir / "csv-analysis.json"
    session = synth_dir / "session.json"
    policies = synth_dir / "policies"
    final = synth_dir / "final-policy"
    commands = [
        [str(BIN_PATH), "experiment", "init", "--analysis", str(analysis),
         "--features", "Streaming,AirPlay", "--session", str(session)],
        [str(BIN_PATH), "experiment", "next", "--session", str(session),
         "--out-dir", str(policies)],
    ]
    e2e_ok = True
    for cmd in commands:
        cp = run(cmd)
        e2e_ok = e2e_ok and cp.returncode == 0
    trial_id = None
    if e2e_ok:
        try:
            s = json.loads(session.read_text(encoding="utf-8"))
            pending = [t for t in s.get("trials", []) if t.get("status") == "pending"]
            trial_id = pending[-1]["id"] if pending else None
        except Exception:
            trial_id = None
    if not trial_id:
        e2e_ok = False
    if e2e_ok:
        record_cmd = [str(BIN_PATH), "experiment", "record", "--session", str(session),
                      "--trial", trial_id, "--results", "Streaming=pass,AirPlay=pass"]
        export_cmd = [str(BIN_PATH), "export", "--session", str(session), "--out-dir", str(final)]
        e2e_ok = run(record_cmd).returncode == 0 and e2e_ok
        e2e_ok = run(export_cmd).returncode == 0 and e2e_ok

    export_ok, semantic_exact_ok, export_detail = verify_export_bundle(final)
    report["synthetic"]["export_verification"] = export_detail
    add_check("all export adapters", PASS if export_ok else FAIL,
              "verified generated resolver files and rollback manifest")
    add_check("synthetic exact-host semantic probe", PASS if semantic_exact_ok else FAIL,
              "proved exact target syntax does not encode parent/sibling/subdomain wildcarding")
    add_check("synthetic end-to-end", PASS if (e2e_ok and export_ok) else FAIL,
              "scan -> experiment -> record -> learned export")
    write_reports()
    return e2e_ok and export_ok, all_inputs, export_ok, semantic_exact_ok


def verify_export_bundle(bundle: Path) -> Tuple[bool, bool, Dict[str, Any]]:
    expected = {
        "domains.txt", "adguard.txt", "hosts.txt", "dnsmasq.conf",
        "unbound.conf", "openwrt-dnsmasq.conf", "pihole-exact.txt",
        "rollback.json", "README.txt",
    }
    present = {p.name for p in bundle.iterdir()} if bundle.exists() else set()
    missing = sorted(expected - present)
    detail: Dict[str, Any] = {"missing": missing, "files": sorted(present)}
    if missing:
        return False, False, detail

    try:
        domains = [x.strip() for x in (bundle / "domains.txt").read_text().splitlines() if x.strip()]
        if not domains:
            raise ValueError("domains.txt empty")
        domain_set = set(domains)

        pihole = {x.strip() for x in (bundle / "pihole-exact.txt").read_text().splitlines() if x.strip()}
        adguard_lines = [x.strip() for x in (bundle / "adguard.txt").read_text().splitlines()
                         if x.strip() and not x.lstrip().startswith(("!", "#"))]
        hosts_lines = [x.strip() for x in (bundle / "hosts.txt").read_text().splitlines()
                       if x.strip() and not x.startswith("#")]
        dnsmasq = (bundle / "dnsmasq.conf").read_text(encoding="utf-8")
        openwrt = (bundle / "openwrt-dnsmasq.conf").read_text(encoding="utf-8")
        dnsmasq_rules = "\n".join(x for x in dnsmasq.splitlines() if x.strip() and not x.lstrip().startswith("#"))
        openwrt_rules = "\n".join(x for x in openwrt.splitlines() if x.strip() and not x.lstrip().startswith("#"))
        unbound = (bundle / "unbound.conf").read_text(encoding="utf-8")
        rb = json.loads((bundle / "rollback.json").read_text(encoding="utf-8"))

        exact = True
        exact &= pihole == domain_set
        exact &= set(adguard_lines) == domain_set
        exact &= not any("||" in x or "*" in x for x in adguard_lines)
        exact &= "address=/" not in dnsmasq_rules and "address=/" not in openwrt_rules
        exact &= all(f"host-record={d},0.0.0.0,::" in dnsmasq_rules for d in domains)
        exact &= all(f"host-record={d},0.0.0.0,::" in openwrt_rules for d in domains)
        exact &= all(f'local-zone: "{d}." transparent' in unbound for d in domains)
        exact &= all(f'local-data: "{d}. A 0.0.0.0"' in unbound for d in domains)
        exact &= set(rb.get("remove_domains", [])) == domain_set
        for d in domains:
            exact &= any(line.endswith(" " + d) for line in hosts_lines)

        # A literal-neighbor proof independent of the real synthetic fixture.
        # We do not pretend to run third-party resolver engines here; instead
        # this verifies that WireDiet's emitted forms contain only the exact
        # learned hostname and never encode a suffix/wildcard rule.
        target = "telemetry.example.com"
        neighbors = {
            "other.telemetry.example.com",
            "example.com",
            "sub.example.com",
        }
        semantic_probe = synthetic_exact_match(target, target)
        semantic_probe &= all(not synthetic_exact_match(target, n) for n in neighbors)
        detail.update({
            "domains": domains,
            "rollback_domains": rb.get("remove_domains", []),
            "exact_semantics": exact,
            "literal_neighbor_probe": semantic_probe,
            "probe_target": target,
            "probe_expected_unaffected": sorted(neighbors),
        })
        return exact, exact and semantic_probe, detail
    except Exception as exc:  # noqa: BLE001
        detail["error"] = str(exc)
        return False, False, detail


def synthetic_exact_match(rule_domain: str, query_domain: str) -> bool:
    return rule_domain.rstrip(".").lower() == query_domain.rstrip(".").lower()


def prompt(msg: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    rendered = f"{msg}{suffix}: "
    log.write(rendered)
    try:
        value = input()
    except (EOFError, KeyboardInterrupt):
        log.line("<input unavailable>", screen=False)
        return default or ""
    # Avoid copying local device identifiers into the verbose log.
    log.line("<operator response recorded>", screen=False)
    value = value.strip()
    return value if value else (default or "")


def prompt_choice(msg: str, choices: Dict[str, str], default: Optional[str] = None) -> str:
    while True:
        log.line(msg)
        for key, label in choices.items():
            log.line(f"  {key}) {label}")
        value = prompt("Choose", default)
        if value in choices:
            return value
        log.line("Invalid choice.")


def yes_no_skip(msg: str, default: str = "s") -> str:
    choices = {"y": "yes", "n": "no", "s": "skip / not verified"}
    c = prompt_choice(msg, choices, default)
    return choices[c]


def phase_b_c() -> None:
    print_header("PHASE B — RESOLVER DISCOVERY")
    if not sys.stdin.isatty():
        block_real_validation("non-interactive terminal; rerun python3 dev.py in Terminal for guided live validation")
        return

    resolver_choice = prompt_choice(
        "Select ONE real resolver environment",
        {"1": "Pi-hole", "2": "AdGuard Home", "3": "Neither / no supported resolver", "4": "Skip real-device validation this run"},
        "3",
    )
    if resolver_choice in {"3", "4"}:
        reason = "no supported resolver environment" if resolver_choice == "3" else "operator skipped real validation"
        block_real_validation(reason)
        return

    resolver = "pihole" if resolver_choice == "1" else "adguard"
    report["real_validation"]["resolver_type"] = "Pi-hole" if resolver == "pihole" else "AdGuard Home"
    resolver_version = prompt("Resolver version (blank if unknown)", "")
    report["real_validation"]["resolver_version"] = resolver_version or "unknown"
    write_reports()

    print_header("PHASE C — SAFE REAL-DEVICE TEST")
    log.line("WireDiet will NOT log into, write to, restart, or reconfigure your resolver.")
    log.line("Raw resolver exports and analyses stay under artifacts/ with owner-only permissions when supported.")

    target = prompt("Target device IP/name exactly as it appears in the resolver query log")
    if not target:
        block_real_validation("target device was not provided")
        return
    features_raw = prompt("Required feature(s), comma-separated", "Netflix")
    features = dedupe([x.strip() for x in features_raw.split(",") if x.strip()])
    if not features:
        block_real_validation("no required features were provided")
        return
    duration = prompt("Small safe baseline window in minutes", "2")
    if not duration.isdigit() or int(duration) < 1:
        duration = "2"

    report["real_validation"]["target"] = "[local-target]"
    report["real_validation"]["features"] = features
    report["real_validation"]["baseline_window_minutes"] = int(duration)
    write_reports()

    log.line()
    log.line(f"BASELINE: filter the {report['real_validation']['resolver_type']} query log to ONLY the selected device if practical.")
    log.line(f"Exercise these features normally for about {duration} minute(s): {', '.join(features)}")
    if resolver == "pihole":
        log.line("Save the corresponding Pi-hole v6 /api/queries JSON response. WireDiet does not need your Pi-hole password.")
    else:
        log.line("Save the corresponding AdGuard Home /control/querylog JSON response. WireDiet does not need your AdGuard password.")
    log.line("It is okay if the saved response contains other clients: WireDiet will filter to the target identifier you entered.")

    baseline_result = yes_no_skip("During that baseline window, did EVERY required feature work normally?", "y")
    if baseline_result == "yes":
        set_matrix("REAL DEVICE BASELINE", PASS, "operator confirmed all required features worked before blocking")
    elif baseline_result == "no":
        set_matrix("REAL DEVICE BASELINE", FAIL, "required feature was already broken at baseline; live block trial stopped")
        mark_live_trial_not_verified("baseline behavior is not healthy enough for a causal block test")
        return
    else:
        set_matrix("REAL DEVICE BASELINE", NOT_VERIFIED, "baseline behavior was not confirmed")
        mark_live_trial_not_verified("baseline was skipped")
        return

    baseline_path_raw = prompt("Path to the saved resolver JSON export")
    baseline_path = resolve_input_path(baseline_path_raw)
    if not baseline_path or not baseline_path.is_file():
        set_matrix("REAL RESOLVER IMPORT", FAIL, "resolver export file was not found")
        mark_live_trial_not_verified("resolver import failed")
        return

    real_dir = ARTIFACTS / "real"
    ensure_private_dir(real_dir)
    analysis_path = real_dir / "analysis.json"
    public_path = real_dir / "analysis.public.json"
    scan_cmd = [
        str(BIN_PATH), "scan", "--input", str(baseline_path), "--format", resolver,
        "--device", target, "--out", str(analysis_path), "--public-out", str(public_path),
    ]
    cp = run(scan_cmd)
    if cp.returncode != 0 or not analysis_path.exists():
        set_matrix("REAL RESOLVER IMPORT", FAIL, f"WireDiet could not import/filter the {resolver} export")
        mark_live_trial_not_verified("resolver import failed")
        return
    chmod_private(analysis_path)
    chmod_private(public_path)

    try:
        analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        set_matrix("REAL RESOLVER IMPORT", FAIL, f"analysis JSON unreadable: {exc}")
        mark_live_trial_not_verified("resolver import failed")
        return

    parsed_count = int(analysis.get("event_count", 0))
    report["real_validation"]["parsed_query_count"] = parsed_count
    log.line(f"WireDiet parsed {parsed_count} query event(s) for the selected device.")
    ui_count_raw = prompt("Resolver UI/API query count for the SAME device and SAME saved window (number; blank if unavailable)")
    count_match: Optional[bool] = None
    if ui_count_raw:
        try:
            count_match = int(ui_count_raw) == parsed_count
        except ValueError:
            count_match = False
    if ui_count_raw and ui_count_raw.isdigit():
        report["real_validation"]["resolver_query_count"] = int(ui_count_raw)
    if count_match is True:
        report["real_validation"]["query_count_match"] = True
        set_matrix("REAL RESOLVER IMPORT", PASS, f"parsed query count matched resolver count ({parsed_count})")
    elif count_match is False:
        report["real_validation"]["query_count_match"] = False
        set_matrix("REAL RESOLVER IMPORT", FAIL, f"parsed={parsed_count}; resolver-reported count did not match")
        mark_live_trial_not_verified("resolver import count mismatch")
        return
    else:
        set_matrix("REAL RESOLVER IMPORT", NOT_VERIFIED,
                   f"import parsed {parsed_count} query events, but source count was not supplied for comparison")
        log.line("Import parsing succeeded, but the required count comparison is NOT VERIFIED.")

    candidates = safe_candidates(analysis)
    report["real_validation"]["safe_candidate_count"] = len(candidates)
    write_reports()
    if not candidates:
        log.line("No sufficiently safe evidence-backed telemetry/analytics/advertising candidate exists in this baseline.")
        log.line("REAL BLOCK TEST: NOT VERIFIED — refusing to guess at an unknown or potentially critical hostname.")
        mark_live_trial_not_verified("no sufficiently safe evidence-backed candidate")
        return

    log.line()
    log.line("Evidence-backed low-risk candidates observed for this device:")
    for i, d in enumerate(candidates[:8], 1):
        src = ", ".join(s.get("title", "source") for s in d.get("evidence", [])[:2]) or "no source"
        log.line(f"  {i}) {d['domain']} — {d.get('category')} / {d.get('confidence')} / {d.get('queries')} queries")
        log.line(f"     evidence: {src}")
        if d.get("notes"):
            log.line(f"     note: {d['notes']}")

    max_pick = min(2, len(candidates), 8)
    while True:
        pick_raw = prompt(f"Choose 1 or 2 candidate numbers for the first trial (recommended: 1)", "1")
        try:
            indexes = [int(x.strip()) for x in pick_raw.split(",") if x.strip()]
        except ValueError:
            indexes = []
        indexes = dedupe(indexes)
        if 1 <= len(indexes) <= 2 and all(1 <= i <= min(8, len(candidates)) for i in indexes):
            break
        log.line("Choose one or two numbers from the displayed candidates.")
    selected = [candidates[i - 1] for i in indexes]
    selected_domains = [d["domain"] for d in selected]
    report["real_validation"]["selected_candidates"] = [
        {
            "id": hashlib.sha256(str(d["domain"]).encode("utf-8")).hexdigest()[:12],
            "category": d.get("category"),
            "confidence": d.get("confidence"),
        }
        for d in selected
    ]
    write_reports()

    trial_analysis = make_trial_analysis(analysis, selected_domains)
    trial_analysis_path = real_dir / "trial-analysis.json"
    write_private_json(trial_analysis_path, trial_analysis)
    session_path = real_dir / "session.json"
    policies_dir = real_dir / "policies"

    init_cmd = [str(BIN_PATH), "experiment", "init", "--analysis", str(trial_analysis_path),
                "--features", ",".join(features), "--session", str(session_path)]
    if run(init_cmd).returncode != 0:
        mark_live_trial_not_verified("could not initialize real-device experiment")
        return

    split_observed = False
    split_child_recorded = False
    any_applied = False
    all_rollbacks_confirmed = True
    feature_trial_result = NOT_VERIFIED

    while True:
        next_cmd = [str(BIN_PATH), "experiment", "next", "--session", str(session_path), "--out-dir", str(policies_dir)]
        cp = run(next_cmd)
        if cp.returncode != 0:
            # Expected when complete or when final aggregate failed. Inspect session.
            break
        session_obj = read_json(session_path)
        pending = [t for t in session_obj.get("trials", []) if t.get("status") == "pending"]
        if not pending:
            break
        trial = pending[-1]
        trial_id = trial["id"]
        domains = list(trial.get("domains", []))
        bundle = policies_dir / trial_id
        if trial.get("parent_id") and trial.get("parent_id") != "FINAL":
            split_observed = True

        print_header(f"LIVE TRIAL {trial_id}")
        log.line(f"Temporary exact-host target(s): {', '.join(domains)}")
        log.line("ROLLBACK IS GENERATED BEFORE APPLICATION:")
        rollback_text = (bundle / "rollback.json").read_text(encoding="utf-8")
        log.line(rollback_text.rstrip())

        app_text = manual_application_instructions(resolver, target, domains)
        app_path = bundle / "MANUAL_APPLICATION.txt"
        app_path.write_text(app_text, encoding="utf-8")
        chmod_private(app_path)
        rule_hash = hashlib.sha256(app_text.encode("utf-8")).hexdigest()
        report["real_validation"].setdefault("private_rule_artifacts", []).append({
            "trial_id": trial_id,
            "path": str(app_path.relative_to(ROOT)),
            "sha256": rule_hash,
        })
        write_reports()
        log.line()
        log.line("EXACT POLICY TO APPLY MANUALLY:")
        log.line(app_text.rstrip())
        log.line()
        log.line("The harness will not apply these rules itself.")

        applied = yes_no_skip("Did you apply ONLY the shown temporary rule(s) to ONLY the selected device?", "s")
        if applied != "yes":
            if applied == "no":
                log.line("Rule was not applied. Live trial remains NOT VERIFIED.")
            break
        any_applied = True

        log.line()
        log.line("LIVE EXACT-HOST CHECK: verify the target hostname is blocked without broadening to a parent/sibling/subdomain that should remain resolvable. If no valid related hostname exists, skip rather than guess.")
        exact_live = yes_no_skip("Did live resolver behavior confirm exact-host-only scope?", "s")
        if exact_live == "yes":
            set_matrix("EXACT-HOST RULE BEHAVIOR", PASS, "synthetic exporter exactness + live resolver exact-host behavior confirmed")
            report["real_validation"]["live_exact_host_verified"] = True
        elif exact_live == "no":
            set_matrix("EXACT-HOST RULE BEHAVIOR", FAIL, "live resolver rule broadened or otherwise failed exact-host verification")
            report["real_validation"]["live_exact_host_verified"] = False
        else:
            report["real_validation"]["live_exact_host_verified"] = None
        write_reports()

        results: List[str] = []
        saw_fail = False
        saw_skip = False
        for feature in features:
            r = yes_no_skip(f"With this rule active, does '{feature}' still work normally?", "s")
            if r == "yes":
                results.append(f"{feature}=pass")
            elif r == "no":
                results.append(f"{feature}=fail")
                saw_fail = True
            else:
                results.append(f"{feature}=skip")
                saw_skip = True

        record_cmd = [str(BIN_PATH), "experiment", "record", "--session", str(session_path),
                      "--trial", trial_id, "--results", ",".join(results)]
        record_ok = run(record_cmd).returncode == 0
        if not record_ok:
            feature_trial_result = FAIL

        if split_observed and record_ok:
            split_child_recorded = True

        # Roll back immediately before any subsequent trial.
        log.line()
        log.line("ROLLBACK NOW: remove exactly the temporary rule(s) just applied before continuing.")
        log.line(rollback_action(resolver, target, domains))
        removed = yes_no_skip("Were all temporary rules removed?", "y")
        if removed != "yes":
            all_rollbacks_confirmed = False
            if removed == "no":
                feature_trial_result = FAIL
            break

        restored = yes_no_skip("After removal, did the selected device return to its baseline feature behavior?", "y")
        if restored != "yes":
            all_rollbacks_confirmed = False
            if restored == "no":
                feature_trial_result = FAIL
            break

        normal_dns = yes_no_skip("After removal, did the target hostname(s) resolve/behave normally again according to the device or resolver log?", "s")
        if normal_dns != "yes":
            all_rollbacks_confirmed = False
            if normal_dns == "no":
                feature_trial_result = FAIL

        if saw_skip:
            feature_trial_result = NOT_VERIFIED
            break
        if not saw_fail and record_ok:
            feature_trial_result = PASS
        elif saw_fail and record_ok:
            feature_trial_result = NOT_VERIFIED  # may become PASS after narrowing/final verification

        # If a failed multi-domain batch was recorded, Next() will produce a
        # narrower child on the next loop. A singleton failure needs no split.
        if saw_fail and len(domains) > 1:
            split_observed = True
            log.line("A required feature failed with multiple domains. WireDiet will now exercise its narrowing/split logic.")
            continue

        # Continue while queue/final verification requires another trial.
        current = read_json(session_path)
        if current.get("final_verification") == "passed":
            feature_trial_result = PASS
            break
        if current.get("final_verification") == "failed":
            feature_trial_result = FAIL
            break
        if current.get("queue"):
            continue
        # No queue can mean a FINAL aggregate trial is still needed.
        continue

    final_session = read_json(session_path) if session_path.exists() else {}
    final_ver = final_session.get("final_verification")
    if final_ver == "passed":
        feature_trial_result = PASS
    elif final_ver == "failed":
        feature_trial_result = FAIL

    set_matrix("FEATURE-PRESERVING TRIAL", feature_trial_result,
               f"WireDiet final verification={final_ver or 'not completed'}")
    if split_observed and split_child_recorded:
        set_matrix("FAILURE/SPLIT CYCLE", PASS, "multi-domain failure generated and recorded a narrower child trial")
    else:
        set_matrix("FAILURE/SPLIT CYCLE", NOT_VERIFIED,
                   "no multi-domain live failure required a split, or split was not completed")

    if any_applied and all_rollbacks_confirmed:
        set_matrix("RESTORATION AFTER ROLLBACK", PASS,
                   "operator confirmed temporary rules removed, baseline behavior restored, and hostname behavior normalized")
    elif any_applied and not all_rollbacks_confirmed:
        set_matrix("RESTORATION AFTER ROLLBACK", FAIL if feature_trial_result == FAIL else NOT_VERIFIED,
                   "rollback/restoration was not fully confirmed")
    else:
        set_matrix("RESTORATION AFTER ROLLBACK", NOT_VERIFIED, "no live rule was applied")

    report["real_validation"]["session_final_verification"] = final_ver
    report["real_validation"]["raw_analysis_path"] = "artifacts/real/analysis.json (local/private; do not send unless intentionally redacted)"
    report["real_validation"]["public_analysis_path"] = "artifacts/real/analysis.public.json"
    write_reports()


def safe_candidates(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for d in analysis.get("domains", []):
        domain = str(d.get("domain", "")).lower()
        category = str(d.get("category", ""))
        confidence = str(d.get("confidence", ""))
        disposition = str(d.get("disposition", ""))
        if disposition != "block_candidate" or category not in SAFE_CATEGORIES:
            continue
        if confidence not in {"high", "medium"}:
            continue
        if not d.get("evidence"):
            continue
        labels = set(re.split(r"[.\-_]+", domain))
        if labels & CRITICAL_TOKENS:
            continue
        out.append(d)
    confidence_rank = {"high": 0, "medium": 1}
    out.sort(key=lambda d: (
        SAFE_CATEGORIES.get(str(d.get("category")), 99),
        confidence_rank.get(str(d.get("confidence")), 9),
        -int(d.get("queries", 0)),
        str(d.get("domain", "")),
    ))
    return out


def make_trial_analysis(analysis: Dict[str, Any], selected_domains: List[str]) -> Dict[str, Any]:
    selected = set(selected_domains)
    clone = copy.deepcopy(analysis)
    clone["domains"] = [
        d for d in clone.get("domains", [])
        if d.get("disposition") != "block_candidate" or d.get("domain") in selected
    ]
    clone["event_count"] = sum(int(d.get("queries", 0)) for d in clone["domains"])
    clone.setdefault("warnings", []).append(
        "Validation harness derived analysis: unselected block candidates omitted so the first live trial contains only operator-selected low-risk hosts."
    )
    return clone


def manual_application_instructions(resolver: str, client: str, domains: List[str]) -> str:
    if resolver == "pihole":
        lines = [
            "Pi-hole manual, client-scoped test (NO automatic changes):",
            "1. Create/use a temporary WireDiet test group containing ONLY the selected target client.",
            "2. Add each hostname below as an EXACT denylist domain (not regex/wildcard).",
            "3. Assign each temporary domain ONLY to the temporary test group.",
            "4. IMPORTANT: remove the Default-group assignment from each temporary domain, or it can affect other clients.",
            "5. Do not alter any unrelated client/group/list membership.",
            "",
            "Exact domains:",
        ]
        lines.extend(f"  {d}" for d in domains)
        lines.extend([
            "",
            "Rollback: delete these temporary exact-domain entries, then remove the temporary group/client association if it was created only for this test.",
        ])
        return "\n".join(lines) + "\n"

    client_expr = adguard_client_expr(client)
    lines = [
        "AdGuard Home manual, client-scoped test (NO automatic changes):",
        "Add ONLY the following lines to Custom filtering rules for the duration of the trial.",
        "The |hostname| anchors are intentional exact-host matching; do NOT replace them with ||hostname^, which includes subdomains.",
        "The $client modifier scopes the rule to the selected client.",
        "",
    ]
    lines.extend(f"|{d}|$client={client_expr}" for d in domains)
    lines.extend([
        "",
        "Rollback: delete exactly these temporary Custom filtering rule lines.",
    ])
    return "\n".join(lines) + "\n"


def adguard_client_expr(client: str) -> str:
    try:
        ipaddress.ip_address(client)
        return client
    except ValueError:
        escaped = (client.replace("\\", "\\\\").replace("'", "\\'")
                   .replace(",", "\\,").replace("|", "\\|"))
        return "'" + escaped + "'"


def rollback_action(resolver: str, client: str, domains: List[str]) -> str:
    if resolver == "pihole":
        return "Pi-hole: remove the temporary exact denylist entries for: " + ", ".join(domains) + ". Do not remove unrelated rules."
    rules = [f"|{d}|$client={adguard_client_expr(client)}" for d in domains]
    return "AdGuard Home: delete exactly these Custom filtering rules:\n  " + "\n  ".join(rules)


def block_real_validation(reason: str) -> None:
    log.line()
    if "no supported resolver" in reason:
        log.line("REAL DEVICE VALIDATION: BLOCKED — NO SUPPORTED RESOLVER ENVIRONMENT")
    else:
        log.line(f"REAL DEVICE VALIDATION: NOT VERIFIED — {reason}")
    for name in [
        "REAL RESOLVER IMPORT", "REAL DEVICE BASELINE", "FEATURE-PRESERVING TRIAL",
        "FAILURE/SPLIT CYCLE", "RESTORATION AFTER ROLLBACK",
    ]:
        if report["matrix"][name]["status"] == NOT_VERIFIED:
            set_matrix(name, NOT_VERIFIED, reason)
    report["real_validation"]["blocked_reason"] = reason
    write_reports()


def mark_live_trial_not_verified(reason: str) -> None:
    for name in ["FEATURE-PRESERVING TRIAL", "FAILURE/SPLIT CYCLE", "RESTORATION AFTER ROLLBACK"]:
        if report["matrix"][name]["status"] == NOT_VERIFIED:
            set_matrix(name, NOT_VERIFIED, reason)
    report["real_validation"]["trial_blocked_reason"] = reason
    write_reports()


def resolve_input_path(raw: str) -> Optional[Path]:
    if not raw:
        return None
    p = Path(raw).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    try:
        return p.resolve()
    except OSError:
        return p


def read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_private_json(path: Path, obj: Any) -> None:
    ensure_private_dir(path.parent)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    chmod_private(path)


def dedupe(items: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    seen = set()
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def matrix_text() -> str:
    lines = []
    for name in MATRIX_ORDER:
        entry = report["matrix"][name]
        lines.append(f"{name:<30} {entry['status']}")
        if entry.get("detail"):
            lines.append(f"  {entry['detail']}")
    return "\n".join(lines)


def write_reports() -> None:
    if "matrix" not in report:
        return
    report["updated_at"] = utc_now()
    ensure_private_dir(ARTIFACTS)
    JSON_REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    chmod_private(JSON_REPORT)

    env = report.get("environment", {})
    txt = [
        "WireDiet local verification report",
        f"Generated: {report.get('started_at')}",
        f"Updated:   {report.get('updated_at')}",
        "",
        "ENVIRONMENT",
        f"Platform: {env.get('system', 'unknown')} {env.get('macos_version') or ''} {env.get('architecture', '')}".strip(),
        f"Python:   {env.get('python_version', 'unknown')}",
        f"Go:       {env.get('go_version_raw') or 'not detected'}",
        "",
        "FINAL MATRIX",
        matrix_text(),
        "",
        "PATCH-LOOP FILE",
        "Send this file back: artifacts/local_verification_report.txt",
        "Do not send artifacts/full_validation.log or artifacts/real/analysis.json unless specifically needed; they may contain local identifiers or DNS history.",
        "",
        "CHECKS",
    ]
    for c in report.get("checks", []):
        txt.append(f"- {c['status']}: {c['name']} — {c.get('detail', '')}")
    if report.get("real_validation"):
        rv = report["real_validation"]
        txt.extend([
            "",
            "REAL VALIDATION SUMMARY",
            f"Resolver: {rv.get('resolver_type', 'not selected')} {rv.get('resolver_version', '')}".rstrip(),
            f"Target:   {rv.get('target', 'not supplied')}",
            f"Query counts: resolver={rv.get('resolver_query_count', 'not supplied')} parsed={rv.get('parsed_query_count', 'not run')}",
            f"Features: {', '.join(rv.get('features', [])) if rv.get('features') else 'not supplied'}",
            f"Selected candidate records: {', '.join((x.get('id', '') + ':' + str(x.get('category', '')) + '/' + str(x.get('confidence', ''))) for x in rv.get('selected_candidates', [])) or 'none'}",
            f"Final verification: {rv.get('session_final_verification', 'not completed')}",
            f"Blocked reason: {rv.get('blocked_reason') or rv.get('trial_blocked_reason') or 'none'}",
        ])
    TXT_REPORT.write_text("\n".join(txt) + "\n", encoding="utf-8")
    chmod_private(TXT_REPORT)
    write_current_run_reproducibility()


def write_current_run_reproducibility() -> None:
    """Write a sanitized summary of this invocation only.

    This file is intentionally separate from committed historical real-world
    evidence under docs/reproducibility/. A phase-a-only run must never erase
    or downgrade a previously completed physical validation record.
    """
    rv = report.get("real_validation", {})
    safe_selected = [
        {"category": x.get("category"), "confidence": x.get("confidence")}
        for x in rv.get("selected_candidates", [])
    ]
    matrix_names = [
        "REAL RESOLVER IMPORT", "REAL DEVICE BASELINE", "EXACT-HOST RULE BEHAVIOR",
        "FEATURE-PRESERVING TRIAL", "FAILURE/SPLIT CYCLE", "RESTORATION AFTER ROLLBACK",
    ]
    obj = {
        "schema_version": "1",
        "wire_diet_version": report.get("wire_diet_version"),
        "scope": "current harness invocation only",
        "resolver": {
            "type": rv.get("resolver_type", "not selected"),
            "version": rv.get("resolver_version", "unknown"),
        },
        "baseline": {
            "resolver_query_count": rv.get("resolver_query_count"),
            "wirediet_parsed_query_count": rv.get("parsed_query_count"),
            "counts_match": rv.get("query_count_match"),
        },
        "candidate_count": rv.get("safe_candidate_count"),
        "selected_candidate_metadata": safe_selected,
        "required_feature_count": len(rv.get("features", [])),
        "matrix": {name: report["matrix"][name]["status"] for name in matrix_names},
        "privacy_statement": "This artifact intentionally contains no raw household domains, private IPs, MAC addresses, device names, feature names, credentials, or household timestamps.",
    }
    CURRENT_RUN_REPRO_JSON.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    chmod_private(CURRENT_RUN_REPRO_JSON)
    lines = [
        "WireDiet sanitized current-run reproducibility summary",
        f"WireDiet version: {obj['wire_diet_version']}",
        f"Resolver: {obj['resolver']['type']} {obj['resolver']['version']}",
        f"Resolver query count: {obj['baseline']['resolver_query_count']}",
        f"WireDiet parsed count: {obj['baseline']['wirediet_parsed_query_count']}",
        f"Counts match: {obj['baseline']['counts_match']}",
        f"Evidence-backed candidate count: {obj['candidate_count']}",
        f"Required feature count: {obj['required_feature_count']}",
        "",
        "REAL-WORLD MATRIX",
    ]
    for name in matrix_names:
        lines.append(f"{name:<30} {obj['matrix'][name]}")
    lines.extend(["", obj["privacy_statement"]])
    CURRENT_RUN_REPRO_TXT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    chmod_private(CURRENT_RUN_REPRO_TXT)


def init_report() -> Dict[str, Any]:
    return {
        "schema_version": "1",
        "wire_diet_version": VERSION,
        "started_at": utc_now(),
        "updated_at": utc_now(),
        "environment": {},
        "checks": [],
        "synthetic": {},
        "real_validation": {},
        "phase_a_pass": False,
        "matrix": {name: {"status": NOT_VERIFIED, "detail": "not run"} for name in MATRIX_ORDER},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="WireDiet local release and guided real-device validation harness")
    parser.add_argument("--phase-a-only", action="store_true", help="run deterministic checks only; skip interactive resolver/device validation")
    args = parser.parse_args()

    global log, report
    reset_artifacts()
    log = Tee(LOG_PATH)
    chmod_private(LOG_PATH)
    report = init_report()
    write_reports()

    try:
        print_header("WireDiet local validation harness")
        log.line("No cloud upload. No router/resolver writes. No unrelated-device inspection.")
        log.line(f"Repository: {ROOT}")
        phase_a_ok = phase_a()
        if args.phase_a_only:
            block_real_validation("phase-a-only mode")
        elif not phase_a_ok:
            log.line()
            log.line("Phase A contains a failure. Real-device testing is intentionally not started until deterministic failures are fixed.")
            block_real_validation("Phase A failed; fix deterministic release checks first")
        else:
            phase_b_c()

        print_header("FINAL MATRIX")
        log.line(matrix_text())
        log.line()
        log.line(f"Text report: {TXT_REPORT.relative_to(ROOT)}")
        log.line(f"JSON report: {JSON_REPORT.relative_to(ROOT)}")
        log.line(f"Full log:    {LOG_PATH.relative_to(ROOT)}")
        write_reports()
        # A non-zero exit only reflects deterministic/local failures. Live
        # NOT VERIFIED is an honest state, not a process failure.
        return 0 if report.get("phase_a_pass") else 1
    finally:
        write_reports()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
