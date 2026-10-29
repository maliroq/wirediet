package report

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/maliroq/wirediet/internal/model"
)

func TestWriteJSONUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not authoritative on Windows")
	}
	p := filepath.Join(t.TempDir(), "nested", "analysis.json")
	if err := WriteJSON(p, model.Analysis{SchemaVersion: "1"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("analysis permissions = %o, want 600", got)
	}
}

func TestReadAnalysisRejectsOversizedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAnalysisBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysis(p); err == nil {
		t.Fatal("expected oversized analysis rejection")
	}
}

func TestReadAnalysisRejectsForgedCandidateWithoutEvidence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "analysis.json")
	raw := `{"schema_version":"1","generated_at":"2026-10-27T00:00:00Z","source_format":"json","evidence_reviewed_at":"2026-10-27","event_count":1,"domains":[{"domain":"telemetry.example.com","queries":1,"category":"telemetry","confidence":"high","disposition":"block_candidate"}]}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysis(p); err == nil {
		t.Fatal("expected forged evidence-less candidate analysis to be rejected")
	}
}

func TestReadAnalysisRejectsCountMismatch(t *testing.T) {
	p := filepath.Join(t.TempDir(), "analysis.json")
	raw := `{"schema_version":"1","generated_at":"2026-10-27T00:00:00Z","source_format":"json","event_count":2,"domains":[{"domain":"unknown.example.com","queries":1,"category":"unknown","confidence":"unknown","disposition":"observe"}]}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysis(p); err == nil {
		t.Fatal("expected analysis count mismatch to be rejected")
	}
}

func TestReadAnalysisRejectsUnsafeEvidenceURLHost(t *testing.T) {
	p := filepath.Join(t.TempDir(), "analysis.json")
	raw := `{"schema_version":"1","generated_at":"2026-10-27T00:00:00Z","source_format":"json","evidence_reviewed_at":"2026-10-27","event_count":1,"domains":[{"domain":"telemetry.example.com","queries":1,"category":"telemetry","confidence":"high","disposition":"block_candidate","evidence":[{"title":"bad provenance","url":"https://bad_host.example/evidence"}]}]}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysis(p); err == nil {
		t.Fatal("expected malformed evidence URL host rejection")
	}
}
