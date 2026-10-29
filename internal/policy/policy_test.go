package policy

import (
	"github.com/maliroq/wirediet/internal/model"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCandidatesExcludeProtectedUnknown(t *testing.T) {
	a := model.Analysis{Domains: []model.DomainFinding{{Domain: "telemetry.example.com", Category: "telemetry", Confidence: "high", Disposition: "block_candidate"}, {Domain: "update.example.com", Category: "software_update", Confidence: "high", Disposition: "protect"}, {Domain: "mystery.example.com", Category: "unknown", Confidence: "unknown", Disposition: "observe"}}}
	c, p, u := CandidateDomains(a)
	if len(c) != 1 || len(p) != 1 || len(u) != 1 {
		t.Fatalf("unexpected split %v %v %v", c, p, u)
	}
}
func TestBundleAndRollback(t *testing.T) {
	d := t.TempDir()
	if err := WriteBundle(d, []string{"telemetry.example.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(d, "rollback.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "telemetry.example.com") {
		t.Fatal("rollback missing domain")
	}
	if _, err := os.Stat(filepath.Join(d, ".complete")); err != nil {
		t.Fatal("completed bundle missing .complete marker")
	}
	adg, err := os.ReadFile(filepath.Join(d, "adguard.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(adg), "||telemetry.example.com^") || !strings.Contains(string(adg), "\ntelemetry.example.com\n") {
		t.Fatalf("AdGuard export must preserve exact-host semantics:\n%s", adg)
	}
	dm, err := os.ReadFile(filepath.Join(d, "dnsmasq.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(dm), "\naddress=/") || !strings.Contains(string(dm), "host-record=telemetry.example.com,0.0.0.0,::") {
		t.Fatalf("dnsmasq export broadened hostname semantics:\n%s", dm)
	}
	unb, err := os.ReadFile(filepath.Join(d, "unbound.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unb), "always_nxdomain") || !strings.Contains(string(unb), `local-zone: "telemetry.example.com." transparent`) {
		t.Fatalf("Unbound export broadened hostname semantics:\n%s", unb)
	}
}
func TestRejectsPolicyInjection(t *testing.T) {
	if err := WriteBundle(t.TempDir(), []string{"good.example.com\naddress=/evil/0.0.0.0"}, "bad"); err == nil {
		t.Fatal("expected unsafe domain rejection")
	}
}

func TestExactHostNeighborNamesRemainUnblockedByExportSyntax(t *testing.T) {
	target := "telemetry.example.com"
	d := t.TempDir()
	if err := WriteBundle(d, []string{target}, "exactness-probe"); err != nil {
		t.Fatal(err)
	}

	neighbors := []string{
		"other.telemetry.example.com",
		"example.com",
		"sub.example.com",
	}

	plainFiles := []string{"domains.txt", "pihole-exact.txt"}
	for _, name := range plainFiles {
		b, err := os.ReadFile(filepath.Join(d, name))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Fields(string(b))
		if len(lines) != 1 || lines[0] != target {
			t.Fatalf("%s must contain only the exact target: %q", name, b)
		}
		for _, n := range neighbors {
			for _, line := range lines {
				if line == n {
					t.Fatalf("%s unexpectedly contains neighbor %s", name, n)
				}
			}
		}
	}

	adg, err := os.ReadFile(filepath.Join(d, "adguard.txt"))
	if err != nil {
		t.Fatal(err)
	}
	adgText := string(adg)
	if !strings.Contains(adgText, "\n"+target+"\n") {
		t.Fatalf("AdGuard export missing exact bare-domain rule: %s", adgText)
	}
	if strings.Contains(adgText, "||"+target+"^") || strings.Contains(adgText, "*"+target) {
		t.Fatalf("AdGuard export widened target semantics: %s", adgText)
	}

	dm, err := os.ReadFile(filepath.Join(d, "dnsmasq.conf"))
	if err != nil {
		t.Fatal(err)
	}
	dmText := string(dm)
	if !strings.Contains(dmText, "host-record="+target+",0.0.0.0,::") {
		t.Fatalf("dnsmasq exact host-record missing: %s", dmText)
	}
	if strings.Contains(dmText, "address=/"+target+"/") {
		t.Fatalf("dnsmasq suffix-style rule found: %s", dmText)
	}

	unb, err := os.ReadFile(filepath.Join(d, "unbound.conf"))
	if err != nil {
		t.Fatal(err)
	}
	unbText := string(unb)
	if !strings.Contains(unbText, `local-zone: "`+target+`." transparent`) {
		t.Fatalf("Unbound transparent exact zone missing: %s", unbText)
	}
	if !strings.Contains(unbText, `local-data: "`+target+`. A 0.0.0.0"`) {
		t.Fatalf("Unbound exact local-data missing: %s", unbText)
	}

	hosts, err := os.ReadFile(filepath.Join(d, "hosts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	hostsText := string(hosts)
	if !strings.Contains(hostsText, "0.0.0.0 "+target+"\n") || !strings.Contains(hostsText, ":: "+target+"\n") {
		t.Fatalf("hosts export missing exact target: %s", hostsText)
	}
	for _, n := range neighbors {
		if strings.Contains(hostsText, " "+n+"\n") {
			t.Fatalf("hosts export unexpectedly contains neighbor %s", n)
		}
	}
}

func TestBundleUsesPrivatePermissionsAndRejectsSymlinkDir(t *testing.T) {
	if runtime.GOOS != "windows" {
		d := filepath.Join(t.TempDir(), "bundle")
		if err := WriteBundle(d, []string{"telemetry.example.com"}, "test"); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Mode().Perm(); got != 0o700 {
			t.Fatalf("bundle directory permissions = %o, want 700", got)
		}
		for _, name := range []string{"adguard.txt", "rollback.json", "README.txt"} {
			st, err := os.Stat(filepath.Join(d, name))
			if err != nil {
				t.Fatal(err)
			}
			if got := st.Mode().Perm(); got != 0o600 {
				t.Fatalf("%s permissions = %o, want 600", name, got)
			}
		}
	}

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation unavailable on this Windows runner")
		}
		t.Fatal(err)
	}
	if err := WriteBundle(link, []string{"telemetry.example.com"}, "test"); err == nil {
		t.Fatal("expected symlink output directory rejection")
	}
}

func TestBundleRejectsNonEmptyDirectory(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "stale-rule.txt"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(d, []string{"telemetry.example.com"}, "test"); err == nil {
		t.Fatal("expected non-empty policy directory to be rejected")
	}
}

func TestBundleRejectsRelativeParentSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("relative symlink behavior is platform-specific on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-parent")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if err := WriteBundle(filepath.Join("linked-parent", "bundle"), []string{"telemetry.example.com"}, "test"); err == nil {
		t.Fatal("expected relative parent symlink to be rejected")
	}
}
