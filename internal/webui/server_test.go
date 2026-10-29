package webui

import (
	"bytes"
	"strings"
	"testing"

	"github.com/maliroq/wirediet/internal/model"
)

func TestLoopbackOnly(t *testing.T) {
	allowed := []string{"127.0.0.1:8787", "localhost:8787", "[::1]:8787"}
	for _, addr := range allowed {
		if err := loopbackOnly(addr); err != nil {
			t.Fatalf("expected %s to be allowed: %v", addr, err)
		}
	}
	blocked := []string{"0.0.0.0:8787", "192.0.2.10:8787", ":8787"}
	for _, addr := range blocked {
		if err := loopbackOnly(addr); err == nil {
			t.Fatalf("expected %s to be rejected", addr)
		}
	}
}

func TestAllowedHostRejectsDNSRebindingHost(t *testing.T) {
	if !allowedHost("127.0.0.1:8787", "127.0.0.1:8787") {
		t.Fatal("expected loopback Host header to be allowed")
	}
	if !allowedHost("localhost:8787", "127.0.0.1:8787") {
		t.Fatal("expected localhost Host header to be allowed")
	}
	if allowedHost("attacker.example:8787", "127.0.0.1:8787") {
		t.Fatal("DNS-rebinding Host header must be rejected")
	}
}

func TestMakeViewUnknownIsIntentional(t *testing.T) {
	a := model.Analysis{Domains: []model.DomainFinding{
		{Domain: "one.example", Disposition: "observe"},
		{Domain: "two.example", Disposition: "observe"},
	}}
	v := makeView(a, nil)
	if v.Unknown != 2 || v.Candidates != 0 || v.VerifyState != "not started" {
		t.Fatalf("unexpected view counts/state: %+v", v)
	}
}

func TestMakeViewSessionState(t *testing.T) {
	s := &model.Session{
		Candidates:        []string{"telemetry.example"},
		Features:          []string{"Streaming"},
		SafeToBlock:       map[string][]string{"telemetry.example": {"Streaming"}},
		FinalVerification: "pending",
		Trials:            []model.Trial{{ID: "trial-1", Status: "pending", Domains: []string{"telemetry.example"}}},
	}
	v := makeView(model.Analysis{}, s)
	if v.Pending == nil || v.TestState != "trial pending" || v.VerifyState != "pending" || v.SafeCount != 1 {
		t.Fatalf("unexpected session view: %+v", v)
	}
}

func TestPageRendersWorkflowAndUnknownState(t *testing.T) {
	a := model.Analysis{
		EventCount: 1,
		Domains:    []model.DomainFinding{{Domain: "unknown.example", Category: "unknown", Confidence: "unknown", Disposition: "observe"}},
	}
	var buf bytes.Buffer
	if err := newTemplate().Execute(&buf, makeView(a, nil)); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, want := range []string{"Observe", "Test", "Verify", "Unknown is a valid result.", "Insufficient evidence"} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered UI missing %q", want)
		}
	}
}
