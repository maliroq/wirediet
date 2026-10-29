package ingest

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/model"
	"github.com/maliroq/wirediet/internal/safejson"
)

const maxInputBytes = 50 << 20
const maxEvents = 1_000_000

var domainRE = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$`)
var dnsmasqRE = regexp.MustCompile(`(?i)(?:query\[[A-Z0-9]+\]\s+)([^\s]+)\s+from\s+([^\s]+)`)

type Adapter interface {
	Name() string
	Detect(path string, b []byte) bool
	Parse(b []byte) ([]model.Event, error)
}

type adapter struct {
	name   string
	detect func(string, []byte) bool
	parse  func([]byte) ([]model.Event, error)
}

func (a adapter) Name() string                          { return a.name }
func (a adapter) Detect(path string, b []byte) bool     { return a.detect(path, b) }
func (a adapter) Parse(b []byte) ([]model.Event, error) { return a.parse(b) }

var registry = []Adapter{
	adapter{name: "pihole", detect: func(_ string, b []byte) bool { return detectObjectArrayWithKey(b, "queries", "domain") }, parse: parsePiHole},
	adapter{name: "adguard", detect: func(_ string, b []byte) bool { return detectAdGuard(b) }, parse: parseAdGuard},
	adapter{name: "json", detect: func(path string, b []byte) bool {
		t := bytes.TrimSpace(b)
		return strings.HasSuffix(strings.ToLower(path), ".json") || (len(t) > 0 && (t[0] == '[' || t[0] == '{'))
	}, parse: parseGenericJSON},
	adapter{name: "dnsmasq", detect: func(_ string, b []byte) bool { return bytes.Contains(b, []byte(" query[")) }, parse: parseDnsmasq},
	adapter{name: "csv", detect: func(path string, _ []byte) bool { return strings.HasSuffix(strings.ToLower(path), ".csv") }, parse: parseCSV},
}

func ReadFile(path, format string) ([]model.Event, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if st.Size() > maxInputBytes {
		return nil, "", fmt.Errorf("input exceeds %d MiB safety limit", maxInputBytes>>20)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxInputBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxInputBytes {
		return nil, "", fmt.Errorf("input exceeds %d MiB safety limit", maxInputBytes>>20)
	}

	var chosen Adapter
	if format == "generic-json" {
		format = "json"
	}
	if format == "auto" || format == "" {
		for _, a := range registry {
			if a.Detect(path, b) {
				chosen = a
				break
			}
		}
		if chosen == nil {
			chosen = adapter{name: "csv", detect: func(string, []byte) bool { return true }, parse: parseCSV}
		}
	} else {
		for _, a := range registry {
			if a.Name() == format {
				chosen = a
				break
			}
		}
		if chosen == nil {
			return nil, format, fmt.Errorf("unsupported format %q", format)
		}
	}
	if chosen.Name() == "json" || chosen.Name() == "pihole" || chosen.Name() == "adguard" {
		if err := safejson.ValidateNoDuplicateKeys(b); err != nil {
			return nil, chosen.Name(), fmt.Errorf("ambiguous JSON input: %w", err)
		}
	}
	events, err := chosen.Parse(b)
	if err != nil {
		return nil, chosen.Name(), err
	}
	if len(events) > maxEvents {
		return nil, chosen.Name(), fmt.Errorf("too many events: %d > %d", len(events), maxEvents)
	}
	out := events[:0]
	for _, e := range events {
		e.Domain = normalizeDomain(e.Domain)
		if validDomain(e.Domain) {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, chosen.Name(), errors.New("no valid DNS domain events found")
	}
	return out, chosen.Name(), nil
}

func detectObjectArrayWithKey(b []byte, field, itemKey string) bool {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || t[0] != '{' {
		return false
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(t, &probe) != nil {
		return false
	}
	raw, ok := probe[field]
	if !ok {
		return false
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(raw, &items) != nil || len(items) == 0 {
		return false
	}
	_, ok = items[0][itemKey]
	return ok
}

func detectAdGuard(b []byte) bool {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || t[0] != '{' {
		return false
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(t, &probe) != nil {
		return false
	}
	raw, ok := probe["data"]
	if !ok {
		return false
	}
	var items []struct {
		Question map[string]json.RawMessage `json:"question"`
	}
	if json.Unmarshal(raw, &items) != nil || len(items) == 0 {
		return false
	}
	_, hasName := items[0].Question["name"]
	_, hasHost := items[0].Question["host"]
	return hasName || hasHost
}

func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
func validDomain(s string) bool {
	return len(s) >= 1 && len(s) <= 253 && domainRE.MatchString(s) && !strings.Contains(s, "..")
}

func parseCSV(b []byte) ([]model.Event, error) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.ReuseRecord = false
	head, err := r.Read()
	if err != nil {
		return nil, err
	}
	idx := map[string]int{}
	for i, h := range head {
		key := strings.ToLower(strings.TrimSpace(h))
		if key == "" {
			continue
		}
		if _, exists := idx[key]; exists {
			return nil, fmt.Errorf("CSV contains duplicate column %q", key)
		}
		idx[key] = i
	}
	if _, ok := idx["domain"]; !ok {
		return nil, errors.New("CSV requires a domain column")
	}
	var out []model.Event
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		e := model.Event{Source: "csv"}
		e.Domain = field(rec, idx, "domain")
		e.Client = field(rec, idx, "client")
		if e.Client == "" {
			// Common exported DNS-log CSVs (including NextDNS downloads) use
			// client_ip rather than client.  Treat it as a generic alias without
			// introducing any cloud/API dependency.
			e.Client = field(rec, idx, "client_ip")
		}
		e.Status = field(rec, idx, "status")
		t := field(rec, idx, "timestamp")
		if t == "" {
			t = field(rec, idx, "time")
		}
		e.Time = parseTime(t)
		out = append(out, e)
		if len(out) > maxEvents {
			return nil, fmt.Errorf("too many events: > %d", maxEvents)
		}
	}
	return out, nil
}
func field(rec []string, idx map[string]int, key string) string {
	i, ok := idx[key]
	if !ok || i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func parseGenericJSON(b []byte) ([]model.Event, error) {
	var arr []map[string]any
	if err := json.Unmarshal(b, &arr); err != nil {
		var wrap struct {
			Events []map[string]any `json:"events"`
		}
		if err2 := json.Unmarshal(b, &wrap); err2 != nil {
			return nil, err
		}
		arr = wrap.Events
	}
	if len(arr) > maxEvents {
		return nil, fmt.Errorf("too many events: %d > %d", len(arr), maxEvents)
	}
	out := make([]model.Event, 0, len(arr))
	for _, m := range arr {
		out = append(out, eventFromMap(m, "json"))
	}
	return out, nil
}

func parseAdGuard(b []byte) ([]model.Event, error) {
	var root struct {
		Data []struct {
			Client   string `json:"client"`
			Status   string `json:"status"`
			Time     string `json:"time"`
			Question struct {
				Name string `json:"name"`
				Host string `json:"host"`
				Type string `json:"type"`
			} `json:"question"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	if len(root.Data) > maxEvents {
		return nil, fmt.Errorf("too many events: %d > %d", len(root.Data), maxEvents)
	}
	out := make([]model.Event, 0, len(root.Data))
	for i, q := range root.Data {
		domain := strings.TrimSpace(q.Question.Name)
		legacyHost := strings.TrimSpace(q.Question.Host)
		if domain != "" && legacyHost != "" && !strings.EqualFold(strings.TrimSuffix(domain, "."), strings.TrimSuffix(legacyHost, ".")) {
			return nil, fmt.Errorf("adguard data[%d] has conflicting question.name and question.host", i)
		}
		if domain == "" {
			domain = legacyHost
		}
		out = append(out, model.Event{Time: parseTime(q.Time), Client: q.Client, Domain: domain, Status: q.Status, Source: "adguard"})
	}
	return out, nil
}

func parsePiHole(b []byte) ([]model.Event, error) {
	var root struct {
		Queries []map[string]any `json:"queries"`
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	if len(root.Queries) > maxEvents {
		return nil, fmt.Errorf("too many events: %d > %d", len(root.Queries), maxEvents)
	}
	out := make([]model.Event, 0, len(root.Queries))
	for _, m := range root.Queries {
		out = append(out, eventFromMap(m, "pihole"))
	}
	return out, nil
}

func eventFromMap(m map[string]any, src string) model.Event {
	e := model.Event{Source: src}
	e.Domain = asString(m["domain"])
	e.Client = asClient(m["client"])
	if e.Client == "" {
		e.Client = asString(m["client_ip"])
	}
	e.Status = asString(m["status"])
	if v, ok := m["time"]; ok {
		e.Time = parseAnyTime(v)
	} else if v, ok := m["timestamp"]; ok {
		e.Time = parseAnyTime(v)
	}
	return e
}
func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Pi-hole v6 /api/queries represents client as an object with ip/name, while
// generic imports and some older/exported fixtures may use a plain string.
// Accept both so saved API responses are portable across versions.
func asClient(v any) string {
	if s := asString(v); s != "" {
		return s
	}
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	if ip := asString(m["ip"]); ip != "" {
		return ip
	}
	return asString(m["name"])
}
func parseAnyTime(v any) time.Time {
	switch x := v.(type) {
	case string:
		return parseTime(x)
	case float64:
		return time.Unix(int64(x), 0).UTC()
	case json.Number:
		i, _ := x.Int64()
		return time.Unix(i, 0).UTC()
	}
	return time.Time{}
}

func parseDnsmasq(b []byte) ([]model.Event, error) {
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 64*1024), 1<<20)
	var out []model.Event
	for s.Scan() {
		line := s.Text()
		m := dnsmasqRE.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		out = append(out, model.Event{Domain: m[1], Client: m[2], Source: "dnsmasq"})
		if len(out) > maxEvents {
			return nil, fmt.Errorf("too many events: > %d", maxEvents)
		}
	}
	return out, s.Err()
}

func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC()
	}
	layouts := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "Jan 2 15:04:05", "Jan _2 15:04:05"}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
