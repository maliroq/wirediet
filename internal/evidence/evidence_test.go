package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedEvidenceMatchesPublicSeed(t *testing.T) {
	public, err := os.ReadFile(filepath.Join("..", "..", "data", "evidence.seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := os.ReadFile("evidence.seed.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(public), bytes.TrimSpace(embedded)) {
		t.Fatal("runtime embedded evidence drifted from data/evidence.seed.json")
	}
	if _, err := LoadDefault(); err != nil {
		t.Fatalf("default evidence must remain parseable: %v", err)
	}
}

func TestRejectsMalformedEvidence(t *testing.T) {
	tests := []string{
		`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"good.example.com;evil","match":"exact","category":"telemetry","confidence":"high","disposition":"block_candidate"}]}`,
		`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"good.example.com","match":"wildcard","category":"telemetry","confidence":"high","disposition":"block_candidate"}]}`,
		`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"good.example.com","match":"exact","category":"telemetry","confidence":"high","disposition":"block_candidate","sources":[{"title":"bad","url":"javascript:alert(1)"}]}]}`,
		`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"observe.example.com","match":"exact","category":"telemetry","confidence":"low","disposition":"observe"}]}`,
	}
	for _, raw := range tests {
		if _, err := loadBytes([]byte(raw)); err == nil {
			t.Fatalf("expected malformed evidence rejection: %s", raw)
		}
	}
}

func TestEvidenceMatchingDoesNotCrossLabelBoundary(t *testing.T) {
	db, err := loadBytes([]byte(`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"example.com","match":"suffix","category":"telemetry","confidence":"medium","disposition":"block_candidate","sources":[{"title":"e","url":"https://example.com/evidence"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := db.Classify("api.example.com"); !ok {
		t.Fatal("expected proper subdomain match")
	}
	if _, ok := db.Classify("notexample.com"); ok {
		t.Fatal("suffix evidence crossed a DNS label boundary")
	}
	if _, ok := db.Classify(strings.Repeat("x", 10) + ".notexample.com"); ok {
		t.Fatal("suffix evidence crossed a DNS label boundary")
	}
}

func TestStaleEvidenceCannotAutoPromoteBlockCandidate(t *testing.T) {
	raw := `{"schema_version":"1","reviewed_at":"2020-01-01","records":[{"pattern":"telemetry.example.com","match":"exact","category":"telemetry","confidence":"high","disposition":"block_candidate","sources":[{"title":"e","url":"https://example.com/e"}]}]}`
	db, err := loadBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := db.Classify("telemetry.example.com")
	if !ok {
		t.Fatal("expected stale evidence record to remain observable")
	}
	if r.Disposition != "observe" || r.Confidence != "low" || !db.IsStaleForBlocking() {
		t.Fatalf("stale evidence retained blocking eligibility: %#v", r)
	}
}

func TestLoadRejectsOversizedEvidenceFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "huge-evidence.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxEvidenceBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected oversized evidence rejection")
	}
}

func TestProtectEvidenceWinsOverMoreSpecificCandidate(t *testing.T) {
	b := []byte(`{
  "schema_version":"1",
  "reviewed_at":"2026-10-27",
  "records":[
    {"pattern":"login.vendor.example","match":"exact","category":"telemetry","confidence":"high","disposition":"block_candidate","sources":[{"title":"candidate","url":"https://example.com/candidate"}]},
    {"pattern":"vendor.example","match":"suffix","category":"authentication","confidence":"high","disposition":"protect","sources":[{"title":"protect","url":"https://example.com/protect"}]}
  ]
}`)
	db, err := loadBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := db.Classify("login.vendor.example")
	if !ok {
		t.Fatal("expected classification")
	}
	if r.Disposition != "protect" || r.Category != "authentication" {
		t.Fatalf("expected protect to win, got %#v", r)
	}
}

func TestRejectsUnsafeBlockCandidateSemantics(t *testing.T) {
	tests := []string{
		`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"login.example.com","match":"exact","category":"authentication","confidence":"high","disposition":"block_candidate","sources":[{"title":"e","url":"https://example.com/e"}]}]}`,
		`{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"telemetry.example.com","match":"exact","category":"telemetry","confidence":"low","disposition":"block_candidate","sources":[{"title":"e","url":"https://example.com/e"}]}]}`,
	}
	for _, raw := range tests {
		if _, err := loadBytes([]byte(raw)); err == nil {
			t.Fatalf("expected unsafe block-candidate semantics to be rejected: %s", raw)
		}
	}
}

func TestRejectsEvidenceURLUserInfo(t *testing.T) {
	raw := `{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"example.com","match":"exact","category":"telemetry","confidence":"medium","disposition":"block_candidate","sources":[{"title":"evidence","url":"https://user:secret@example.com/path"}]}]}`
	if _, err := loadBytes([]byte(raw)); err == nil {
		t.Fatal("expected evidence URL userinfo rejection")
	}
}

func TestRejectsOverlongEvidenceDomain(t *testing.T) {
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pattern := label + "." + label + "." + label + "." + label + ".example"
	raw := `{"schema_version":"1","reviewed_at":"2026-10-27","records":[{"pattern":"` + pattern + `","match":"exact","category":"telemetry","confidence":"medium","disposition":"block_candidate","sources":[{"title":"evidence","url":"https://example.com/evidence"}]}]}`
	if _, err := loadBytes([]byte(raw)); err == nil {
		t.Fatal("expected overlong evidence domain rejection")
	}
}
