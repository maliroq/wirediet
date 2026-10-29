package analyze

import (
	"github.com/maliroq/wirediet/internal/evidence"
	"github.com/maliroq/wirediet/internal/ingest"
	"github.com/maliroq/wirediet/internal/model"
	"path/filepath"
	"testing"
)

func TestEvidenceAndDeviceFilter(t *testing.T) {
	db, err := evidence.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	ev, fmtName, err := ingest.ReadFile(filepath.Join("..", "..", "examples", "synthetic", "generic.csv"), "csv")
	if err != nil {
		t.Fatal(err)
	}
	a := Run(ev, db, "192.0.2.42", fmtName)
	if a.EventCount != 7 {
		t.Fatalf("got %d events", a.EventCount)
	}
	m := map[string]string{}
	for _, d := range a.Domains {
		m[d.Domain] = d.Disposition
	}
	if m["us.ad.lgsmartad.com"] != "block_candidate" {
		t.Fatalf("lgsmartad disposition %q", m["us.ad.lgsmartad.com"])
	}
	if m["snu.lge.com"] != "protect" {
		t.Fatalf("update disposition %q", m["snu.lge.com"])
	}
	if m["nrdp.nccp.netflix.com"] != "observe" {
		t.Fatalf("unknown disposition %q", m["nrdp.nccp.netflix.com"])
	}
}

func TestDeviceFilterExcludesClientlessEvents(t *testing.T) {
	db, err := evidence.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	events := []model.Event{
		{Client: "192.0.2.42", Domain: "a.example.com"},
		{Client: "", Domain: "global.example.com"},
		{Client: "192.0.2.99", Domain: "other.example.com"},
	}
	a := Run(events, db, "192.0.2.42", "test")
	if a.EventCount != 1 || len(a.Domains) != 1 || a.Domains[0].Domain != "a.example.com" {
		t.Fatalf("device-scoped analysis included unscoped/other-client traffic: %#v", a.Domains)
	}
}
