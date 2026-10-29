package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormats(t *testing.T) {
	tests := []struct {
		name, format string
		want         int
	}{
		{"generic.csv", "csv", 8}, {"adguard.json", "adguard", 4}, {"pihole.json", "pihole", 3}, {"dnsmasq.log", "dnsmasq", 4}, {"generic.json", "json", 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join("..", "..", "examples", "synthetic", tc.name)
			ev, _, err := ReadFile(p, tc.format)
			if err != nil {
				t.Fatal(err)
			}
			if len(ev) != tc.want {
				t.Fatalf("got %d events want %d", len(ev), tc.want)
			}
		})
	}
}

func TestAdGuardCurrentQueryLogShape(t *testing.T) {
	p := filepath.Join(t.TempDir(), "adguard-current.json")
	data := `{"data":[{"client":"192.0.2.42","status":"NOERROR","time":"2026-10-27T01:15:00Z","question":{"class":"IN","type":"A","name":"telemetry.example.com"}}]}`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	ev, gotFormat, err := ReadFile(p, "adguard")
	if err != nil {
		t.Fatal(err)
	}
	if gotFormat != "adguard" {
		t.Fatalf("format = %q, want adguard", gotFormat)
	}
	if len(ev) != 1 || ev[0].Domain != "telemetry.example.com" || ev[0].Client != "192.0.2.42" {
		t.Fatalf("current AdGuard query-log shape not parsed: %#v", ev)
	}
}

func TestAdGuardLegacyHostCompatibility(t *testing.T) {
	p := filepath.Join(t.TempDir(), "adguard-legacy.json")
	data := `{"data":[{"client":"192.0.2.42","status":"NOERROR","time":"2026-10-27T01:15:00Z","question":{"type":"A","host":"legacy.example.com"}}]}`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	ev, _, err := ReadFile(p, "adguard")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Domain != "legacy.example.com" {
		t.Fatalf("legacy AdGuard host shape not parsed: %#v", ev)
	}
}

func TestAdGuardRejectsConflictingQuestionFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "adguard-conflict.json")
	data := `{"data":[{"client":"192.0.2.42","status":"NOERROR","time":"2026-10-27T01:15:00Z","question":{"type":"A","name":"one.example.com","host":"two.example.com"}}]}`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadFile(p, "adguard"); err == nil {
		t.Fatal("expected conflicting AdGuard question fields to be rejected")
	}
}

func TestPiHoleV6NestedClientShape(t *testing.T) {
	p := filepath.Join("..", "..", "examples", "synthetic", "pihole.json")
	ev, gotFormat, err := ReadFile(p, "pihole")
	if err != nil {
		t.Fatal(err)
	}
	if gotFormat != "pihole" {
		t.Fatalf("format = %q, want pihole", gotFormat)
	}
	if len(ev) == 0 || ev[0].Client != "192.0.2.42" {
		t.Fatalf("nested Pi-hole client IP not extracted: %#v", ev)
	}
}

func TestMalformedJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(p, []byte(`{"queries":[`), 0o644)
	if _, _, err := ReadFile(p, "pihole"); err == nil {
		t.Fatal("expected parse error")
	}
}
func TestRejectsOversizeFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "huge.csv")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxInputBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, _, err := ReadFile(p, "csv"); err == nil {
		t.Fatal("expected size-limit error")
	}
}

func TestCSVClientIPAlias(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nextdns-like.csv")
	data := "timestamp,domain,client_ip,status\n2026-10-26T12:00:00Z,telemetry.example.com,192.0.2.42,blocked\n"
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	ev, _, err := ReadFile(p, "csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Client != "192.0.2.42" {
		t.Fatalf("client_ip alias not parsed: %#v", ev)
	}
}

func TestRejectsDuplicateJSONKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dup-adguard.json")
	data := `{"data":[{"client":"192.0.2.42","client":"192.0.2.99","question":{"name":"telemetry.example.com"}}]}`
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadFile(p, "adguard"); err == nil {
		t.Fatal("expected duplicate JSON key rejection")
	}
}

func TestCSVRejectsDuplicateNormalizedHeaders(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dup.csv")
	data := "domain, Domain ,client\none.example.com,two.example.com,192.0.2.42\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadFile(p, "csv"); err == nil {
		t.Fatal("expected duplicate normalized CSV header rejection")
	}
}

func TestRejectsOverlongDomain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "long.csv")
	label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	domain := label + "." + label + "." + label + "." + label + ".example"
	data := "domain,client\n" + domain + ",192.0.2.42\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadFile(p, "csv"); err == nil {
		t.Fatal("expected overlong DNS name rejection")
	}
}
