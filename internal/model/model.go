package model

import "time"

type Event struct {
	Time   time.Time `json:"time"`
	Client string    `json:"client,omitempty"`
	Domain string    `json:"domain"`
	Status string    `json:"status,omitempty"`
	Source string    `json:"source,omitempty"`
}

type EvidenceSource struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type EvidenceRecord struct {
	Pattern     string           `json:"pattern"`
	Match       string           `json:"match"` // exact|suffix
	Category    string           `json:"category"`
	Confidence  string           `json:"confidence"`  // high|medium|low
	Disposition string           `json:"disposition"` // block_candidate|protect|observe
	Notes       string           `json:"notes,omitempty"`
	Sources     []EvidenceSource `json:"sources,omitempty"`
}

type DomainFinding struct {
	Domain      string           `json:"domain"`
	Queries     int              `json:"queries"`
	FirstSeen   time.Time        `json:"first_seen,omitempty"`
	LastSeen    time.Time        `json:"last_seen,omitempty"`
	Category    string           `json:"category"`
	Confidence  string           `json:"confidence"`
	Disposition string           `json:"disposition"`
	Evidence    []EvidenceSource `json:"evidence,omitempty"`
	Notes       string           `json:"notes,omitempty"`
}

type Analysis struct {
	SchemaVersion      string          `json:"schema_version"`
	GeneratedAt        time.Time       `json:"generated_at"`
	Device             string          `json:"device,omitempty"`
	SourceFormat       string          `json:"source_format"`
	EvidenceReviewedAt string          `json:"evidence_reviewed_at,omitempty"`
	EvidenceStale      bool            `json:"evidence_stale,omitempty"`
	EventCount         int             `json:"event_count"`
	Domains            []DomainFinding `json:"domains"`
	Warnings           []string        `json:"warnings,omitempty"`
}

type FeatureResult struct {
	Feature string `json:"feature"`
	Result  string `json:"result"` // pass|fail|skip
}

type Trial struct {
	ID             string          `json:"id"`
	Domains        []string        `json:"domains"`
	FeatureResults []FeatureResult `json:"feature_results,omitempty"`
	Status         string          `json:"status"` // pending|pass|fail|inconclusive|superseded
	CreatedAt      time.Time       `json:"created_at"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	ParentID       string          `json:"parent_id,omitempty"`
}

type Session struct {
	SchemaVersion      string              `json:"schema_version"`
	ID                 string              `json:"id"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
	AnalysisPath       string              `json:"analysis_path"`
	Device             string              `json:"device,omitempty"`
	Features           []string            `json:"features"`
	Candidates         []string            `json:"candidates"`
	Protected          []string            `json:"protected,omitempty"`
	Unknown            []string            `json:"unknown,omitempty"`
	Trials             []Trial             `json:"trials"`
	Queue              [][]string          `json:"queue"`
	SafeToBlock        map[string][]string `json:"safe_to_block"` // domain -> features verified pass
	RequiredForFeature map[string][]string `json:"required_for_feature"`
	FinalVerification  string              `json:"final_verification"` // not_started|pending|passed|failed
	InteractionWarning bool                `json:"interaction_warning"`
}
