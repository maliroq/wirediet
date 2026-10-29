package redact

import (
	"strings"
	"testing"
	"time"

	"github.com/maliroq/wirediet/internal/model"
)

func TestAnalysisRedactsDeviceAndTiming(t *testing.T) {
	now := time.Now().UTC()
	a := Analysis(model.Analysis{
		Device:   "Living Room TV",
		Warnings: []string{"client 192.168.203.42 mac aa:bb:cc:dd:ee:ff"},
		Domains:  []model.DomainFinding{{Domain: "telemetry.example.com", FirstSeen: now, LastSeen: now}},
	})
	if a.Device != "[redacted-device]" {
		t.Fatalf("device not fully redacted: %s", a.Device)
	}
	if strings.Contains(a.Warnings[0], "192.168.203") || strings.Contains(strings.ToLower(a.Warnings[0]), "aa:bb") {
		t.Fatalf("warning retained local identifier: %s", a.Warnings[0])
	}
	if !a.Domains[0].FirstSeen.IsZero() || !a.Domains[0].LastSeen.IsZero() {
		t.Fatal("public analysis retained exact observation timestamps")
	}
}

func TestAnalysisRedactsGeneratedTimeIPv6AndEvidenceText(t *testing.T) {
	now := time.Now().UTC()
	a := Analysis(model.Analysis{
		GeneratedAt: now,
		Device:      "Phone",
		Warnings:    []string{"ULA fd00::123 and link-local fe80::1"},
		Domains: []model.DomainFinding{{
			Domain: "telemetry.example.com",
			Notes:  "seen from 10.203.0.25 and aa:bb:cc:dd:ee:ff",
			Evidence: []model.EvidenceSource{{
				Title: "local 192.168.203.1",
				URL:   "https://example.com/path?ref=10.203.0.2",
			}},
		}},
	})
	if !a.GeneratedAt.IsZero() {
		t.Fatal("redacted analysis retained generated_at")
	}
	blob := a.Warnings[0] + a.Domains[0].Notes + a.Domains[0].Evidence[0].Title + a.Domains[0].Evidence[0].URL
	for _, secret := range []string{"fd00::123", "fe80::1", "10.203.0.25", "aa:bb:cc:dd:ee:ff", "192.168.203.1", "10.203.0.2"} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(secret)) {
			t.Fatalf("redacted analysis retained %q: %s", secret, blob)
		}
	}
}
