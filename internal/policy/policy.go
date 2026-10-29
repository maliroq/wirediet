package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/model"
	"github.com/maliroq/wirediet/internal/safeio"
)

var safeDomainRE = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var blockCategories = map[string]bool{
	"telemetry":           true,
	"advertising":         true,
	"acr":                 true,
	"content_recognition": true,
	"vendor_analytics":    true,
	"crash_reporting":     true,
}

func CandidateDomains(a model.Analysis) (candidates, protected, unknown []string) {
	for _, d := range a.Domains {
		switch d.Disposition {
		case "protect":
			protected = append(protected, d.Domain)
		case "block_candidate":
			if blockCategories[d.Category] && (d.Confidence == "high" || d.Confidence == "medium") {
				candidates = append(candidates, d.Domain)
			}
		default:
			unknown = append(unknown, d.Domain)
		}
	}
	sort.Strings(candidates)
	sort.Strings(protected)
	sort.Strings(unknown)
	return
}

type RollbackManifest struct {
	SchemaVersion string   `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Mode          string   `json:"mode"`
	RemoveDomains []string `json:"remove_domains"`
	Notice        string   `json:"notice"`
}

func WriteBundle(dir string, domains []string, label string) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains to export")
	}
	if err := safeio.RejectUnsafeSymlinkParents(filepath.Join(dir, ".wirediet-policy-output")); err != nil {
		return err
	}
	if st, err := os.Lstat(dir); err == nil {
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return fmt.Errorf("refusing non-directory or symlink policy output path %q", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("refusing non-empty policy output directory %q", dir)
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	} else {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	domains = uniqueSorted(domains)
	for _, d := range domains {
		if len(d) < 1 || len(d) > 253 || !safeDomainRE.MatchString(d) || strings.Contains(d, "..") {
			return fmt.Errorf("refusing unsafe domain in policy: %q", d)
		}
	}
	files := map[string]string{
		"domains.txt":          plain(domains),
		"adguard.txt":          adguard(domains),
		"hosts.txt":            hosts(domains),
		"dnsmasq.conf":         dnsmasq(domains),
		"unbound.conf":         unbound(domains),
		"openwrt-dnsmasq.conf": dnsmasq(domains),
		"pihole-exact.txt":     plain(domains),
		"README.txt":           bundleReadme(label, domains),
	}
	for name, body := range files {
		if err := safeio.AtomicWritePrivate(filepath.Join(dir, name), []byte(body)); err != nil {
			return err
		}
	}
	rb := RollbackManifest{SchemaVersion: "1", GeneratedAt: time.Now().UTC().Format(time.RFC3339), Mode: "manual-test-rules", RemoveDomains: domains, Notice: "WireDiet v0.1 does not mutate your resolver. Rollback means remove exactly the temporary rules you manually added from this bundle; restore any resolver backup you created before testing."}
	b, err := json.MarshalIndent(rb, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := safeio.AtomicWritePrivate(filepath.Join(dir, "rollback.json"), b); err != nil {
		return err
	}
	// Written last. An interrupted/partial bundle must not look complete.
	return safeio.AtomicWritePrivate(filepath.Join(dir, ".complete"), []byte("WireDiet policy bundle complete\n"))
}

func plain(ds []string) string { return strings.Join(ds, "\n") + "\n" }
func adguard(ds []string) string {
	var b strings.Builder
	b.WriteString("! WireDiet exact-host experimental rules. Scope to the test device/client when your resolver supports it.\n")
	b.WriteString("! Bare-domain AdGuard syntax is intentional: unlike ||domain^ it does NOT include subdomains.\n")
	for _, d := range ds {
		fmt.Fprintf(&b, "%s\n", d)
	}
	return b.String()
}
func hosts(ds []string) string {
	var b strings.Builder
	b.WriteString("# WireDiet experimental block targets. Hosts files are NOT device-scoped.\n")
	for _, d := range ds {
		fmt.Fprintf(&b, "0.0.0.0 %s\n", d)
		fmt.Fprintf(&b, ":: %s\n", d)
	}
	return b.String()
}
func dnsmasq(ds []string) string {
	var b strings.Builder
	b.WriteString("# WireDiet exact-host experimental rules. Use only in a device-scoped resolver/view where possible.\n")
	b.WriteString("# host-record is intentional: address=/domain/ would also match subdomains.\n")
	for _, d := range ds {
		fmt.Fprintf(&b, "host-record=%s,0.0.0.0,::\n", d)
	}
	return b.String()
}
func unbound(ds []string) string {
	var b strings.Builder
	b.WriteString("# WireDiet exact-host experimental rules. Generic Unbound config is global unless you isolate views.\n")
	b.WriteString("# transparent + local-data blocks only the learned hostname; subdomains resolve normally.\nserver:\n")
	for _, d := range ds {
		fmt.Fprintf(&b, "  local-zone: \"%s.\" transparent\n", d)
		fmt.Fprintf(&b, "  local-data: \"%s. A 0.0.0.0\"\n", d)
		fmt.Fprintf(&b, "  local-data: \"%s. AAAA ::\"\n", d)
	}
	return b.String()
}
func bundleReadme(label string, ds []string) string {
	return fmt.Sprintf("WireDiet experimental policy: %s\n\nDomains: %d\n\nSemantics:\n- Rules target the exact observed hostnames. They intentionally do not broaden a learned hostname to all of its subdomains.\n- Resolver-specific files may still be global unless you explicitly scope them to the intended client/group/view.\n\nSafety:\n- Apply only to the intended test device/client when possible.\n- If your resolver cannot scope a test to one client, understand that temporary rules can affect other devices using that resolver.\n- Do not merge this into a household-wide blocklist without separate testing.\n- Keep software-update, authentication, DRM, payment, emergency, and safety endpoints reachable.\n- Test the features you care about, record the result, then roll back before the next trial if instructed.\n- rollback.json lists exactly the temporary domains to remove.\n", label, len(ds))
}

func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	for _, d := range in {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" {
			m[d] = struct{}{}
		}
	}
	out := make([]string, 0, len(m))
	for d := range m {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}
