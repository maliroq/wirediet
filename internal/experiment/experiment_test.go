package experiment

import (
	"encoding/json"
	"github.com/maliroq/wirediet/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func baseAnalysis() model.Analysis {
	return model.Analysis{Device: "192.0.2.42", Domains: []model.DomainFinding{{Domain: "a.example.com", Category: "telemetry", Confidence: "high", Disposition: "block_candidate"}, {Domain: "b.example.com", Category: "advertising", Confidence: "high", Disposition: "block_candidate"}, {Domain: "updates.example.com", Category: "software_update", Confidence: "high", Disposition: "protect"}}}
}

func TestAllPassCompletes(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "session.json")
	s, err := Init("analysis.json", sp, baseAnalysis(), []string{"Netflix", "AirPlay"})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Candidates) != 2 {
		t.Fatal("candidate count")
	}
	tr, err := Next(sp, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err = Record(sp, tr.ID, []model.FeatureResult{{Feature: "Netflix", Result: "pass"}, {Feature: "AirPlay", Result: "pass"}})
	if err != nil {
		t.Fatal(err)
	}
	if s.FinalVerification != "passed" {
		t.Fatalf("final=%s", s.FinalVerification)
	}
	d, err := FinalDomains(s)
	if err != nil || len(d) != 2 {
		t.Fatalf("domains=%v err=%v", d, err)
	}
}

func TestFailureSplitsAndFindsRequired(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "session.json")
	_, err := Init("analysis.json", sp, baseAnalysis(), []string{"Netflix"})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Next(sp, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := Record(sp, tr.ID, []model.FeatureResult{{Feature: "Netflix", Result: "fail"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Queue) != 2 {
		t.Fatalf("expected split queue, got %d", len(s.Queue))
	}
	tr1, err := Next(sp, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err = Record(sp, tr1.ID, []model.FeatureResult{{Feature: "Netflix", Result: "fail"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.RequiredForFeature["Netflix"]) != 1 {
		t.Fatalf("required=%v", s.RequiredForFeature)
	}
}

func TestSkippedFeatureDoesNotVerifyPolicy(t *testing.T) {
	d := t.TempDir()
	sp := filepath.Join(d, "session.json")
	a := model.Analysis{Device: "192.0.2.42", Domains: []model.DomainFinding{
		{Domain: "a.example.com", Category: "telemetry", Confidence: "high", Disposition: "block_candidate"},
	}}
	if _, err := Init("analysis.json", sp, a, []string{"Netflix", "AirPlay"}); err != nil {
		t.Fatal(err)
	}
	trial, err := Next(sp, filepath.Join(d, "policies"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Record(sp, trial.ID, []model.FeatureResult{
		{Feature: "Netflix", Result: "pass"},
		{Feature: "AirPlay", Result: "skip"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.FinalVerification == "passed" {
		t.Fatal("skipped required feature incorrectly produced final verification")
	}
	if len(s.Queue) != 1 || len(s.Queue[0]) != 1 || s.Queue[0][0] != "a.example.com" {
		t.Fatalf("expected inconclusive trial to be re-queued, got %#v", s.Queue)
	}
	if _, err := FinalDomains(s); err == nil {
		t.Fatal("expected final export to be refused after skipped feature")
	}
}

func TestFailTakesPriorityOverSkip(t *testing.T) {
	d := t.TempDir()
	sp := filepath.Join(d, "session.json")
	a := model.Analysis{Domains: []model.DomainFinding{
		{Domain: "a.example.com", Category: "telemetry", Confidence: "high", Disposition: "block_candidate"},
		{Domain: "b.example.com", Category: "advertising", Confidence: "high", Disposition: "block_candidate"},
	}}
	if _, err := Init("analysis.json", sp, a, []string{"Netflix", "AirPlay"}); err != nil {
		t.Fatal(err)
	}
	trial, err := Next(sp, filepath.Join(d, "policies"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Record(sp, trial.ID, []model.FeatureResult{
		{Feature: "Netflix", Result: "fail"},
		{Feature: "AirPlay", Result: "skip"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Trials[0].Status != "fail" || len(s.Queue) != 2 {
		t.Fatalf("fail+skip must preserve breakage evidence and split: status=%s queue=%#v", s.Trials[0].Status, s.Queue)
	}
}

func TestRejectsUnknownAndDuplicateFeatureResults(t *testing.T) {
	features := []string{"Netflix", "AirPlay"}
	if _, err := validateResults(features, []model.FeatureResult{
		{Feature: "Netflix", Result: "pass"},
		{Feature: "NotConfigured", Result: "pass"},
		{Feature: "AirPlay", Result: "pass"},
	}); err == nil {
		t.Fatal("expected unknown feature rejection")
	}
	if _, err := validateResults(features, []model.FeatureResult{
		{Feature: "Netflix", Result: "pass"},
		{Feature: "Netflix", Result: "fail"},
		{Feature: "AirPlay", Result: "pass"},
	}); err == nil {
		t.Fatal("expected duplicate feature rejection")
	}
}

func TestLoadRejectsCorruptedSessionState(t *testing.T) {
	d := t.TempDir()
	sp := filepath.Join(d, "session.json")
	s, err := Init("analysis.json", sp, baseAnalysis(), []string{"Netflix"})
	if err != nil {
		t.Fatal(err)
	}

	// Corruption must not allow a learned export merely by flipping the final
	// verification field in the JSON file.
	s.FinalVerification = "passed"
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sp); err == nil {
		t.Fatal("expected inconsistent final verification to be rejected")
	}
}

func TestLoadRejectsPathTraversalTrialID(t *testing.T) {
	d := t.TempDir()
	sp := filepath.Join(d, "session.json")
	_, err := Init("analysis.json", sp, baseAnalysis(), []string{"Netflix"})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Next(sp, "")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(sp)
	if err != nil {
		t.Fatal(err)
	}
	for i := range s.Trials {
		if s.Trials[i].ID == tr.ID {
			s.Trials[i].ID = "../escape"
		}
	}
	b, _ := json.Marshal(s)
	if err := os.WriteFile(sp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sp); err == nil {
		t.Fatal("expected unsafe trial id to be rejected")
	}
}

func TestLoadRejectsOversizedSession(t *testing.T) {
	p := filepath.Join(t.TempDir(), "huge-session.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSessionBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected oversized session rejection")
	}
}

func TestNextBundleFailureDoesNotCommitPendingTrial(t *testing.T) {
	d := t.TempDir()
	sp := filepath.Join(d, "session.json")
	if _, err := Init("analysis.json", sp, baseAnalysis(), []string{"Netflix"}); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(d, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(d, "policies-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if _, err := Next(sp, "policies-link"); err == nil {
		t.Fatal("expected policy bundle path failure")
	}
	s, err := Load(sp)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Trials) != 0 || len(s.Queue) != 1 {
		t.Fatalf("failed bundle generation committed session state: trials=%d queue=%d", len(s.Trials), len(s.Queue))
	}
}

func TestLoadRejectsInvalidSessionID(t *testing.T) {
	d := t.TempDir()
	sp := filepath.Join(d, "session.json")
	s, err := Init("analysis.json", sp, baseAnalysis(), []string{"Netflix"})
	if err != nil {
		t.Fatal(err)
	}
	s.ID = "session-ok\nINJECTED"
	b, _ := json.Marshal(s)
	if err := os.WriteFile(sp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sp); err == nil {
		t.Fatal("expected invalid session id rejection")
	}
}
