package evidence

import (
	"embed"
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

//go:embed evidence.seed.json
var embeddedFS embed.FS

type DB struct {
	SchemaVersion        string                 `json:"schema_version"`
	ReviewedAt           string                 `json:"reviewed_at"`
	Records              []model.EvidenceRecord `json:"records"`
	staleBlockCandidates bool
}

var domainRE = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

const maxEvidenceBytes = 5 << 20
const maxBlockCandidateAge = 365 * 24 * time.Hour

var categories = map[string]bool{
	"core_service": true, "cdn": true, "authentication": true, "software_update": true,
	"streaming_service": true, "telemetry": true, "advertising": true, "acr": true,
	"content_recognition": true, "crash_reporting": true, "vendor_analytics": true, "unknown": true,
}

var blockCandidateCategories = map[string]bool{
	"telemetry": true, "advertising": true, "acr": true,
	"content_recognition": true, "crash_reporting": true, "vendor_analytics": true,
}

func Load(path string) (*DB, error) {
	b, err := safeio.ReadFileLimit(path, maxEvidenceBytes)
	if err != nil {
		return nil, err
	}
	return loadBytes(b)
}

func LoadDefault() (*DB, error) {
	b, err := embeddedFS.ReadFile("evidence.seed.json")
	if err != nil {
		return nil, err
	}
	return loadBytes(b)
}

func loadBytes(b []byte) (*DB, error) {
	var db DB
	if err := safejson.DecodeStrict(b, &db); err != nil {
		return nil, fmt.Errorf("parse evidence: %w", err)
	}
	if db.SchemaVersion != "1" {
		return nil, fmt.Errorf("unsupported evidence schema_version %q", db.SchemaVersion)
	}
	reviewed, err := time.Parse("2006-01-02", db.ReviewedAt)
	if err != nil {
		return nil, fmt.Errorf("evidence reviewed_at must be YYYY-MM-DD: %w", err)
	}
	now := time.Now().UTC()
	if reviewed.After(now.Add(24 * time.Hour)) {
		return nil, fmt.Errorf("evidence reviewed_at %s is in the future", db.ReviewedAt)
	}
	db.staleBlockCandidates = now.Sub(reviewed) > maxBlockCandidateAge
	seen := map[string]bool{}
	for i, r := range db.Records {
		db.Records[i].Pattern = normalize(r.Pattern)
		r = db.Records[i]
		if len(r.Pattern) < 1 || len(r.Pattern) > 253 || !domainRE.MatchString(r.Pattern) || strings.Contains(r.Pattern, "..") {
			return nil, fmt.Errorf("evidence record %d has invalid domain pattern %q", i, r.Pattern)
		}
		if r.Match != "exact" && r.Match != "suffix" {
			return nil, fmt.Errorf("evidence record %d has invalid match %q", i, r.Match)
		}
		if !categories[r.Category] {
			return nil, fmt.Errorf("evidence record %d has invalid category %q", i, r.Category)
		}
		if r.Confidence != "high" && r.Confidence != "medium" && r.Confidence != "low" {
			return nil, fmt.Errorf("evidence record %d has invalid confidence %q", i, r.Confidence)
		}
		if r.Disposition != "block_candidate" && r.Disposition != "protect" && r.Disposition != "observe" {
			return nil, fmt.Errorf("evidence record %d has invalid disposition %q", i, r.Disposition)
		}
		if r.Disposition == "block_candidate" {
			if !blockCandidateCategories[r.Category] {
				return nil, fmt.Errorf("evidence record %d uses unsafe block_candidate category %q", i, r.Category)
			}
			if r.Confidence != "high" && r.Confidence != "medium" {
				return nil, fmt.Errorf("evidence record %d block_candidate requires high or medium confidence", i)
			}
		}
		if len(r.Sources) == 0 {
			return nil, fmt.Errorf("evidence record %d requires at least one auditable source", i)
		}
		key := r.Match + "\x00" + r.Pattern
		if seen[key] {
			return nil, fmt.Errorf("duplicate evidence record for %s %q", r.Match, r.Pattern)
		}
		seen[key] = true
		if len(r.Notes) > 4000 {
			return nil, fmt.Errorf("evidence record %d notes exceed 4000 bytes", i)
		}
		if len(r.Sources) > 50 {
			return nil, fmt.Errorf("evidence record %d has too many sources", i)
		}
		for j, src := range r.Sources {
			title := strings.TrimSpace(src.Title)
			if title == "" || len(title) > 500 {
				return nil, fmt.Errorf("evidence record %d source %d has invalid title", i, j)
			}
			if len(src.URL) > 2048 {
				return nil, fmt.Errorf("evidence record %d source %d URL is too long", i, j)
			}
			u, err := url.Parse(src.URL)
			if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") || !publicEvidenceHost(u.Hostname()) {
				return nil, fmt.Errorf("evidence record %d source %d has unsafe URL %q", i, j, src.URL)
			}
		}
	}
	sort.SliceStable(db.Records, func(i, j int) bool {
		if db.Records[i].Match == db.Records[j].Match {
			return len(db.Records[i].Pattern) > len(db.Records[j].Pattern)
		}
		return db.Records[i].Match == "exact"
	})
	return &db, nil
}

func normalize(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (db *DB) Classify(domain string) (model.EvidenceRecord, bool) {
	d := normalize(domain)
	var first *model.EvidenceRecord
	for _, candidate := range db.Records {
		matched := false
		switch candidate.Match {
		case "exact":
			matched = d == candidate.Pattern
		case "suffix":
			matched = d == candidate.Pattern || strings.HasSuffix(d, "."+candidate.Pattern)
		}
		if !matched {
			continue
		}

		r := candidate
		if db.staleBlockCandidates && r.Disposition == "block_candidate" {
			r.Disposition = "observe"
			r.Confidence = "low"
			if r.Notes != "" {
				r.Notes += " "
			}
			r.Notes += "Evidence review is older than one year; automatic block-candidate eligibility is disabled until re-reviewed."
		}

		// Safety beats specificity: if multiple records match the same observed
		// hostname, any protect record wins over a candidate/observe record.
		// Without a protect conflict, the pre-sorted exact/longest match remains
		// the classification returned.
		if r.Disposition == "protect" {
			return r, true
		}
		if first == nil {
			copy := r
			first = &copy
		}
	}
	if first != nil {
		return *first, true
	}
	return model.EvidenceRecord{}, false
}

func (db *DB) IsStaleForBlocking() bool { return db.staleBlockCandidates }

func publicEvidenceHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified()
	}
	return domainRE.MatchString(host) && !strings.Contains(host, "..")
}
