package experiment

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/model"
	"github.com/maliroq/wirediet/internal/policy"
	"github.com/maliroq/wirediet/internal/safeio"
	"github.com/maliroq/wirediet/internal/safejson"
)

var sessionDomainRE = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var trialIDRE = regexp.MustCompile(`^trial-[0-9a-f]{10}$`)
var sessionIDRE = regexp.MustCompile(`^session-[0-9a-f]{12}$`)

func Init(analysisPath, sessionPath string, a model.Analysis, features []string) (model.Session, error) {
	features = clean(features)
	if len(features) == 0 {
		return model.Session{}, errors.New("at least one feature is required")
	}
	candidates, protected, unknown := policy.CandidateDomains(a)
	if len(candidates) == 0 {
		return model.Session{}, errors.New("analysis contains no medium/high-confidence block candidates; unknown domains are intentionally not auto-promoted")
	}
	now := time.Now().UTC()
	s := model.Session{SchemaVersion: "1", ID: "session-" + randID(6), CreatedAt: now, UpdatedAt: now, AnalysisPath: analysisPath, Device: a.Device, Features: features, Candidates: candidates, Protected: protected, Unknown: unknown, Queue: [][]string{append([]string(nil), candidates...)}, SafeToBlock: map[string][]string{}, RequiredForFeature: map[string][]string{}, FinalVerification: "not_started"}
	if err := Save(sessionPath, s); err != nil {
		return model.Session{}, err
	}
	return s, nil
}

const maxSessionBytes = 10 << 20

func Load(path string) (model.Session, error) {
	var s model.Session
	b, err := safeio.ReadFileLimit(path, maxSessionBytes)
	if err != nil {
		return s, err
	}
	if err := safejson.DecodeStrict(b, &s); err != nil {
		return s, err
	}
	if s.SafeToBlock == nil {
		s.SafeToBlock = map[string][]string{}
	}
	if s.RequiredForFeature == nil {
		s.RequiredForFeature = map[string][]string{}
	}
	if err := validateSession(s); err != nil {
		return model.Session{}, fmt.Errorf("invalid experiment session: %w", err)
	}
	return s, nil
}

func Save(path string, s model.Session) error {
	s.UpdatedAt = time.Now().UTC()
	if err := validateSession(s); err != nil {
		return fmt.Errorf("refusing invalid experiment session: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return safeio.AtomicWritePrivate(path, b)
}

func Next(sessionPath, outDir string) (model.Trial, error) {
	s, err := Load(sessionPath)
	if err != nil {
		return model.Trial{}, err
	}
	for _, t := range s.Trials {
		if t.Status == "pending" {
			return model.Trial{}, fmt.Errorf("trial %s is still pending; record its result before generating another", t.ID)
		}
	}
	var domains []string
	parent := ""
	if len(s.Queue) > 0 {
		domains = s.Queue[0]
		s.Queue = s.Queue[1:]
	} else {
		if s.FinalVerification == "passed" {
			return model.Trial{}, errors.New("experiment is complete; final aggregate policy passed")
		}
		if s.FinalVerification == "failed" {
			return model.Trial{}, errors.New("final aggregate policy failed; interaction risk remains and automatic export is disabled")
		}
		domains = finalCandidates(s)
		if len(domains) == 0 {
			return model.Trial{}, errors.New("no domains remain safe across every required feature")
		}
		s.FinalVerification = "pending"
		parent = "FINAL"
	}
	trial := model.Trial{ID: "trial-" + randID(5), Domains: append([]string(nil), domains...), Status: "pending", CreatedAt: time.Now().UTC(), ParentID: parent}
	// Materialize the reversible policy before committing a pending trial to
	// session state. If bundle generation fails or is interrupted, the session
	// remains resumable instead of becoming stuck on a trial with no policy.
	if outDir != "" {
		dir := filepath.Join(outDir, trial.ID)
		if err := policy.WriteBundle(dir, trial.Domains, trial.ID); err != nil {
			return model.Trial{}, err
		}
	}
	s.Trials = append(s.Trials, trial)
	if err := Save(sessionPath, s); err != nil {
		return model.Trial{}, err
	}
	return trial, nil
}

func Record(sessionPath, trialID string, results []model.FeatureResult) (model.Session, error) {
	s, err := Load(sessionPath)
	if err != nil {
		return s, err
	}
	idx := -1
	for i := range s.Trials {
		if s.Trials[i].ID == trialID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s, fmt.Errorf("trial %q not found", trialID)
	}
	if s.Trials[idx].Status != "pending" {
		return s, fmt.Errorf("trial %s is not pending", trialID)
	}
	validated, err := validateResults(s.Features, results)
	if err != nil {
		return s, err
	}
	now := time.Now().UTC()
	s.Trials[idx].FeatureResults = validated
	s.Trials[idx].CompletedAt = &now
	failed := []string{}
	passed := []string{}
	skipped := []string{}
	for _, r := range validated {
		switch r.Result {
		case "fail":
			failed = append(failed, r.Feature)
		case "pass":
			passed = append(passed, r.Feature)
		case "skip":
			skipped = append(skipped, r.Feature)
		}
	}
	trial := &s.Trials[idx]
	for _, d := range trial.Domains {
		for _, f := range passed {
			s.SafeToBlock[d] = appendUnique(s.SafeToBlock[d], f)
		}
	}
	// An explicit failure is decisive even if another required feature was
	// skipped.  Otherwise a fail+skip result could accidentally re-queue the
	// batch as merely inconclusive and discard useful breakage evidence.
	if len(failed) > 0 {
		trial.Status = "fail"
		if trial.ParentID == "FINAL" {
			s.FinalVerification = "failed"
			s.InteractionWarning = true
		} else if len(trial.Domains) == 1 {
			d := trial.Domains[0]
			for _, f := range failed {
				s.RequiredForFeature[f] = appendUnique(s.RequiredForFeature[f], d)
			}
		} else {
			mid := (len(trial.Domains) + 1) / 2
			a := append([]string(nil), trial.Domains[:mid]...)
			b := append([]string(nil), trial.Domains[mid:]...)
			s.Queue = append(s.Queue, a)
			if len(b) > 0 {
				s.Queue = append(s.Queue, b)
			}
		}
	} else if len(skipped) > 0 {
		// A required feature that was not tested cannot contribute to a learned
		// safety claim. Preserve any explicit pass evidence, but make the batch
		// eligible for another trial instead of treating it as verified.
		trial.Status = "inconclusive"
		if trial.ParentID == "FINAL" {
			s.FinalVerification = "not_started"
		} else {
			s.Queue = append(s.Queue, append([]string(nil), trial.Domains...))
		}
	} else {
		trial.Status = "pass"
		if trial.ParentID == "FINAL" {
			s.FinalVerification = "passed"
		}
		if sameSet(trial.Domains, s.Candidates) {
			s.FinalVerification = "passed"
		}
	}
	if err := Save(sessionPath, s); err != nil {
		return s, err
	}
	return s, nil
}

func FinalDomains(s model.Session) ([]string, error) {
	if s.FinalVerification != "passed" {
		return nil, fmt.Errorf("final verification is %s; refusing to export a learned final policy", s.FinalVerification)
	}
	return finalCandidates(s), nil
}

func finalCandidates(s model.Session) []string {
	required := map[string]bool{}
	for _, ds := range s.RequiredForFeature {
		for _, d := range ds {
			required[d] = true
		}
	}
	out := []string{}
	for _, d := range s.Candidates {
		if required[d] {
			continue
		}
		if containsAll(s.SafeToBlock[d], s.Features) {
			out = append(out, d)
		}
	}
	sort.Strings(out)
	return out
}

func validateResults(features []string, in []model.FeatureResult) ([]model.FeatureResult, error) {
	allowed := map[string]bool{}
	for _, f := range features {
		allowed[f] = true
	}
	m := map[string]string{}
	for _, r := range in {
		f := strings.TrimSpace(r.Feature)
		if !allowed[f] {
			return nil, fmt.Errorf("unknown feature %q", f)
		}
		if _, exists := m[f]; exists {
			return nil, fmt.Errorf("duplicate result for feature %q", f)
		}
		v := strings.ToLower(strings.TrimSpace(r.Result))
		if v != "pass" && v != "fail" && v != "skip" {
			return nil, fmt.Errorf("invalid result %q for %s (use pass, fail, or skip)", v, f)
		}
		m[f] = v
	}
	out := make([]model.FeatureResult, 0, len(features))
	for _, f := range features {
		v, ok := m[f]
		if !ok {
			return nil, fmt.Errorf("missing result for feature %q", f)
		}
		out = append(out, model.FeatureResult{Feature: f, Result: v})
	}
	return out, nil
}
func ParseResults(spec string) []model.FeatureResult {
	var out []model.FeatureResult
	for _, p := range strings.Split(spec, ",") {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			out = append(out, model.FeatureResult{Feature: strings.TrimSpace(kv[0]), Result: strings.TrimSpace(kv[1])})
		}
	}
	return out
}
func clean(in []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x != "" && !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	return out
}
func appendUnique(in []string, v string) []string {
	for _, x := range in {
		if x == v {
			return in
		}
	}
	return append(in, v)
}
func containsAll(got, want []string) bool {
	m := map[string]bool{}
	for _, x := range got {
		m[x] = true
	}
	for _, x := range want {
		if !m[x] {
			return false
		}
	}
	return true
}
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func validateSession(s model.Session) error {
	if s.SchemaVersion != "1" {
		return fmt.Errorf("unsupported schema_version %q", s.SchemaVersion)
	}
	if !sessionIDRE.MatchString(s.ID) {
		return fmt.Errorf("invalid session id %q", s.ID)
	}
	features := clean(s.Features)
	if len(features) == 0 || len(features) != len(s.Features) {
		return errors.New("features must be non-empty and unique")
	}
	featureSet := map[string]bool{}
	for _, f := range features {
		if !validFeatureName(f) {
			return fmt.Errorf("invalid feature name %q", f)
		}
		featureSet[f] = true
	}

	candidateSet, err := validateDomainSet("candidates", s.Candidates)
	if err != nil {
		return err
	}
	if len(candidateSet) == 0 {
		return errors.New("candidates must not be empty")
	}
	protectedSet, err := validateDomainSet("protected", s.Protected)
	if err != nil {
		return err
	}
	unknownSet, err := validateDomainSet("unknown", s.Unknown)
	if err != nil {
		return err
	}
	for d := range candidateSet {
		if protectedSet[d] || unknownSet[d] {
			return fmt.Errorf("domain %q appears in multiple classification sets", d)
		}
	}
	for d := range protectedSet {
		if unknownSet[d] {
			return fmt.Errorf("domain %q appears in multiple classification sets", d)
		}
	}

	if s.FinalVerification != "not_started" && s.FinalVerification != "pending" && s.FinalVerification != "passed" && s.FinalVerification != "failed" {
		return fmt.Errorf("invalid final_verification %q", s.FinalVerification)
	}

	trialIDs := map[string]bool{}
	pending := 0
	for i, t := range s.Trials {
		if !trialIDRE.MatchString(t.ID) || trialIDs[t.ID] {
			return fmt.Errorf("trial %d has invalid or duplicate id %q", i, t.ID)
		}
		trialIDs[t.ID] = true
		if t.ParentID != "" && t.ParentID != "FINAL" {
			return fmt.Errorf("trial %s has invalid parent_id %q", t.ID, t.ParentID)
		}
		if t.Status != "pending" && t.Status != "pass" && t.Status != "fail" && t.Status != "inconclusive" && t.Status != "superseded" {
			return fmt.Errorf("trial %s has invalid status %q", t.ID, t.Status)
		}
		if t.Status == "pending" {
			pending++
		}
		if _, err := validateSubset("trial domains", t.Domains, candidateSet); err != nil {
			return fmt.Errorf("trial %s: %w", t.ID, err)
		}
		if t.Status == "pending" {
			if len(t.FeatureResults) != 0 || t.CompletedAt != nil {
				return fmt.Errorf("pending trial %s contains completed results", t.ID)
			}
		} else if t.Status != "superseded" {
			if _, err := validateResults(features, t.FeatureResults); err != nil {
				return fmt.Errorf("trial %s results: %w", t.ID, err)
			}
			if t.CompletedAt == nil {
				return fmt.Errorf("completed trial %s is missing completed_at", t.ID)
			}
		}
	}
	if pending > 1 {
		return errors.New("more than one pending trial")
	}

	for i, group := range s.Queue {
		if _, err := validateSubset(fmt.Sprintf("queue[%d]", i), group, candidateSet); err != nil {
			return err
		}
	}
	for d, fs := range s.SafeToBlock {
		if !candidateSet[d] {
			return fmt.Errorf("safe_to_block contains non-candidate domain %q", d)
		}
		seen := map[string]bool{}
		for _, f := range fs {
			if !featureSet[f] || seen[f] {
				return fmt.Errorf("safe_to_block[%q] has invalid/duplicate feature %q", d, f)
			}
			seen[f] = true
		}
	}
	for f, ds := range s.RequiredForFeature {
		if !featureSet[f] {
			return fmt.Errorf("required_for_feature contains unknown feature %q", f)
		}
		if _, err := validateSubset("required_for_feature["+f+"]", ds, candidateSet); err != nil {
			return err
		}
	}
	if s.FinalVerification == "passed" {
		final := finalCandidates(s)
		if len(final) == 0 {
			return errors.New("final verification passed but no final domains are verified")
		}
		verified := false
		for _, t := range s.Trials {
			if t.Status != "pass" {
				continue
			}
			allPass := true
			for _, r := range t.FeatureResults {
				if r.Result != "pass" {
					allPass = false
					break
				}
			}
			if allPass && ((t.ParentID == "FINAL" && sameSet(t.Domains, final)) || sameSet(t.Domains, s.Candidates)) {
				verified = true
				break
			}
		}
		if !verified {
			return errors.New("final verification passed without a matching aggregate pass trial")
		}
	}
	return nil
}

func validFeatureName(s string) bool {
	if s == "" || len(s) > 128 || strings.ContainsAny(s, ",=\r\n") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validateDomainSet(label string, ds []string) (map[string]bool, error) {
	set := map[string]bool{}
	for _, d := range ds {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" || set[d] {
			return nil, fmt.Errorf("%s contains empty or duplicate domain %q", label, d)
		}
		if !sessionDomainRE.MatchString(d) || strings.Contains(d, "..") {
			return nil, fmt.Errorf("%s contains invalid domain %q", label, d)
		}
		set[d] = true
	}
	return set, nil
}

func validateSubset(label string, ds []string, allowed map[string]bool) (map[string]bool, error) {
	set, err := validateDomainSet(label, ds)
	if err != nil {
		return nil, err
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%s must not be empty", label)
	}
	for d := range set {
		if !allowed[d] {
			return nil, fmt.Errorf("%s contains non-candidate domain %q", label, d)
		}
	}
	return set, nil
}

func randID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
