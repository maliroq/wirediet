package analyze

import (
	"sort"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/evidence"
	"github.com/maliroq/wirediet/internal/model"
)

type agg struct {
	count int
	first time.Time
	last  time.Time
}

func Run(events []model.Event, db *evidence.DB, device, sourceFormat string) model.Analysis {
	m := map[string]*agg{}
	for _, e := range events {
		// When the user asks for a specific device, never attribute events with
		// missing client identity to that device.  Mixing resolver-global events
		// into a device-specific analysis could teach an unsafe policy.
		if device != "" && !sameClient(e.Client, device) {
			continue
		}
		a := m[e.Domain]
		if a == nil {
			a = &agg{}
			m[e.Domain] = a
		}
		a.count++
		if !e.Time.IsZero() {
			if a.first.IsZero() || e.Time.Before(a.first) {
				a.first = e.Time
			}
			if a.last.IsZero() || e.Time.After(a.last) {
				a.last = e.Time
			}
		}
	}
	findings := make([]model.DomainFinding, 0, len(m))
	for domain, a := range m {
		f := model.DomainFinding{Domain: domain, Queries: a.count, FirstSeen: a.first, LastSeen: a.last, Category: "unknown", Confidence: "unknown", Disposition: "observe"}
		if r, ok := db.Classify(domain); ok {
			f.Category = r.Category
			f.Confidence = r.Confidence
			f.Disposition = r.Disposition
			f.Evidence = append([]model.EvidenceSource(nil), r.Sources...)
			f.Notes = r.Notes
		}
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Queries != findings[j].Queries {
			return findings[i].Queries > findings[j].Queries
		}
		return findings[i].Domain < findings[j].Domain
	})
	warnings := []string{
		"DNS visibility is incomplete if a device uses hard-coded IPs, encrypted DNS, QUIC endpoints, or traffic that never reaches the selected resolver.",
		"A domain classification describes evidence about that endpoint, not proof that blocking it is safe for every firmware, region, app, or feature.",
	}
	if db.IsStaleForBlocking() {
		warnings = append(warnings, "The evidence database review is older than one year; stale block candidates were downgraded to observe until re-reviewed.")
	}
	return model.Analysis{SchemaVersion: "1", GeneratedAt: time.Now().UTC(), Device: device, SourceFormat: sourceFormat, EvidenceReviewedAt: db.ReviewedAt, EvidenceStale: db.IsStaleForBlocking(), EventCount: sumCounts(findings), Domains: findings, Warnings: warnings}
}

func sameClient(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
func sumCounts(f []model.DomainFinding) int {
	n := 0
	for _, x := range f {
		n += x.Queries
	}
	return n
}
