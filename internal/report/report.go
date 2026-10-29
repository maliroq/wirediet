package report

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/model"
	"github.com/maliroq/wirediet/internal/safeio"
	"github.com/maliroq/wirediet/internal/safejson"
)

const maxAnalysisBytes = 50 << 20
const maxAnalysisEvents = 1_000_000

func WriteJSON(path string, a model.Analysis) error {
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return safeio.AtomicWritePrivate(path, b)
}

func ReadAnalysis(path string) (model.Analysis, error) {
	var a model.Analysis
	b, err := safeio.ReadFileLimit(path, maxAnalysisBytes)
	if err != nil {
		return a, err
	}
	if err := safejson.DecodeStrict(b, &a); err != nil {
		return a, err
	}
	if a.SchemaVersion != "1" {
		return a, fmt.Errorf("unsupported analysis schema_version %q", a.SchemaVersion)
	}
	if err := validateAnalysis(a); err != nil {
		return model.Analysis{}, fmt.Errorf("invalid analysis: %w", err)
	}
	return a, nil
}

func Summary(a model.Analysis) string {
	counts := map[string]int{}
	disposition := map[string]int{}
	for _, d := range a.Domains {
		counts[d.Category]++
		disposition[d.Disposition]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "Device: %s\n", empty(a.Device, "(all clients in input)"))
	fmt.Fprintf(&b, "Observed: %d DNS queries across %d domains\n", a.EventCount, len(a.Domains))
	fmt.Fprintf(&b, "Block candidates: %d | protected: %d | unknown/observe: %d\n", disposition["block_candidate"], disposition["protect"], disposition["observe"])
	b.WriteString("Categories:\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-20s %d\n", k, counts[k])
	}
	b.WriteString("\nTop domains:\n")
	limit := 10
	if len(a.Domains) < limit {
		limit = len(a.Domains)
	}
	for _, d := range a.Domains[:limit] {
		fmt.Fprintf(&b, "  %-40s %5d  %-18s %-7s %s\n", d.Domain, d.Queries, d.Category, d.Confidence, d.Disposition)
	}
	return b.String()
}
func empty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

var analysisDomainRE = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var analysisCategories = map[string]bool{
	"core_service": true, "cdn": true, "authentication": true, "software_update": true,
	"streaming_service": true, "telemetry": true, "advertising": true, "acr": true,
	"content_recognition": true, "crash_reporting": true, "vendor_analytics": true, "unknown": true,
}

var analysisCandidateCategories = map[string]bool{
	"telemetry": true, "advertising": true, "acr": true,
	"content_recognition": true, "crash_reporting": true, "vendor_analytics": true,
}

func validateAnalysis(a model.Analysis) error {
	if a.EventCount < 0 || a.EventCount > maxAnalysisEvents || len(a.Domains) > maxAnalysisEvents {
		return fmt.Errorf("invalid event/domain count")
	}
	seen := map[string]bool{}
	total := 0
	for i, d := range a.Domains {
		name := strings.ToLower(strings.TrimSpace(d.Domain))
		if name != d.Domain || len(name) < 1 || len(name) > 253 || !analysisDomainRE.MatchString(name) || strings.Contains(name, "..") || seen[name] {
			return fmt.Errorf("domain finding %d has invalid or duplicate domain %q", i, d.Domain)
		}
		seen[name] = true
		if d.Queries <= 0 {
			return fmt.Errorf("domain finding %q has non-positive query count", name)
		}
		total += d.Queries
		if total < 0 || total > maxAnalysisEvents {
			return fmt.Errorf("analysis query count is unreasonable")
		}
		if !d.FirstSeen.IsZero() && !d.LastSeen.IsZero() && d.FirstSeen.After(d.LastSeen) {
			return fmt.Errorf("domain finding %q has first_seen after last_seen", name)
		}
		if !analysisCategories[d.Category] {
			return fmt.Errorf("domain finding %q has invalid category %q", name, d.Category)
		}
		if d.Confidence != "high" && d.Confidence != "medium" && d.Confidence != "low" && d.Confidence != "unknown" {
			return fmt.Errorf("domain finding %q has invalid confidence %q", name, d.Confidence)
		}
		if d.Disposition != "block_candidate" && d.Disposition != "protect" && d.Disposition != "observe" {
			return fmt.Errorf("domain finding %q has invalid disposition %q", name, d.Disposition)
		}
		if d.Disposition == "block_candidate" {
			if !analysisCandidateCategories[d.Category] || (d.Confidence != "high" && d.Confidence != "medium") {
				return fmt.Errorf("domain finding %q has unsafe block-candidate semantics", name)
			}
			if len(d.Evidence) == 0 {
				return fmt.Errorf("domain finding %q is a block candidate without evidence", name)
			}
			if a.EvidenceStale {
				return fmt.Errorf("analysis marks stale evidence but still contains block candidate %q", name)
			}
		}
		if d.Disposition == "protect" && len(d.Evidence) == 0 {
			return fmt.Errorf("protected domain finding %q has no evidence", name)
		}
		for j, src := range d.Evidence {
			if strings.TrimSpace(src.Title) == "" || !validAnalysisEvidenceURL(src.URL) {
				return fmt.Errorf("domain finding %q evidence %d is incomplete or unsafe", name, j)
			}
		}
	}
	if total != a.EventCount {
		return fmt.Errorf("event_count %d does not equal summed domain queries %d", a.EventCount, total)
	}
	if hasCandidate(a.Domains) {
		if a.EvidenceReviewedAt == "" {
			return fmt.Errorf("block candidates require evidence_reviewed_at")
		}
		reviewed, err := time.Parse("2006-01-02", a.EvidenceReviewedAt)
		if err != nil {
			return fmt.Errorf("invalid evidence_reviewed_at: %w", err)
		}
		now := time.Now().UTC()
		if reviewed.After(now.Add(24*time.Hour)) || now.Sub(reviewed) > 365*24*time.Hour {
			return fmt.Errorf("block-candidate evidence review date is not current enough")
		}
	}
	return nil
}

func hasCandidate(ds []model.DomainFinding) bool {
	for _, d := range ds {
		if d.Disposition == "block_candidate" {
			return true
		}
	}
	return false
}

func validAnalysisEvidenceURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified()
	}
	return analysisDomainRE.MatchString(host) && len(host) <= 253 && !strings.Contains(host, "..")
}
