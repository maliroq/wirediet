package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maliroq/wirediet/internal/analyze"
	"github.com/maliroq/wirediet/internal/evidence"
	"github.com/maliroq/wirediet/internal/experiment"
	"github.com/maliroq/wirediet/internal/ingest"
	"github.com/maliroq/wirediet/internal/model"
	"github.com/maliroq/wirediet/internal/policy"
	"github.com/maliroq/wirediet/internal/redact"
	"github.com/maliroq/wirediet/internal/report"
	"github.com/maliroq/wirediet/internal/webui"
)

var version = "v0.1.0-preview.5"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "scan":
		err = cmdScan(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "experiment":
		err = cmdExperiment(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "redact":
		err = cmdRedact(os.Args[2:])
	case "version", "--version", "-version":
		fmt.Println("wirediet", version)
		return
	case "help", "--help", "-h":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `WireDiet - learn what a smart device can stop talking to without breaking the features you use.

Commands:
  scan        Ingest DNS logs and create an evidence-based analysis.
  serve       View an analysis in a local-only web UI.
  experiment  Create/advance/record a reversible feature test session.
  export      Export a learned final policy (or explicit unverified candidates).
  redact      Create an identifier-redacted analysis; review domains before sharing.
  version     Print version.

Run "wirediet <command> -h" for command flags.
`)
}

func cmdScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	input := fs.String("input", "", "input log/export file")
	format := fs.String("format", "auto", "auto|csv|json|dnsmasq|adguard|pihole")
	device := fs.String("device", "", "client IP/name to isolate; blank analyzes all imported clients")
	evidencePath := fs.String("evidence", "", "optional evidence JSON; embedded audited seed is used by default")
	out := fs.String("out", "analysis.json", "analysis JSON output; blank disables file output")
	publicOut := fs.String("public-out", "", "optional identifier-redacted analysis JSON; domains remain visible")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("--input is required")
	}
	db, err := loadEvidence(*evidencePath)
	if err != nil {
		return err
	}
	events, detected, err := ingest.ReadFile(*input, *format)
	if err != nil {
		return err
	}
	a := analyze.Run(events, db, *device, detected)
	if a.EventCount == 0 {
		return fmt.Errorf("no events matched device %q", *device)
	}
	fmt.Print(report.Summary(a))
	if *out != "" {
		if err := report.WriteJSON(*out, a); err != nil {
			return err
		}
		fmt.Printf("\nAnalysis written to %s\n", *out)
	}
	if *publicOut != "" {
		r := redact.Analysis(a)
		if err := report.WriteJSON(*publicOut, r); err != nil {
			return err
		}
		fmt.Printf("Redacted analysis written to %s\n", *publicOut)
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("analysis", "analysis.json", "analysis JSON")
	sessionPath := fs.String("session", "", "optional experiment session JSON for read-only Test/Verify state")
	addr := fs.String("listen", "127.0.0.1:8787", "loopback listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := report.ReadAnalysis(*path)
	if err != nil {
		return err
	}
	var s *model.Session
	if strings.TrimSpace(*sessionPath) != "" {
		loaded, err := experiment.Load(*sessionPath)
		if err != nil {
			return err
		}
		s = &loaded
	}
	return webui.Serve(a, s, *addr)
}

func cmdExperiment(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("experiment requires init, next, record, or status")
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("experiment init", flag.ContinueOnError)
		ap := fs.String("analysis", "analysis.json", "analysis JSON")
		features := fs.String("features", "", "comma-separated features that must keep working")
		sp := fs.String("session", ".wirediet/session.json", "session state path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		a, err := report.ReadAnalysis(*ap)
		if err != nil {
			return err
		}
		s, err := experiment.Init(*ap, *sp, a, splitCSV(*features))
		if err != nil {
			return err
		}
		fmt.Printf("Created %s with %d candidate domains and %d protected domains.\n", s.ID, len(s.Candidates), len(s.Protected))
		fmt.Printf("Next: wirediet experiment next --session %s --out-dir .wirediet/policies\n", *sp)
		return nil
	case "next":
		fs := flag.NewFlagSet("experiment next", flag.ContinueOnError)
		sp := fs.String("session", ".wirediet/session.json", "session state path")
		out := fs.String("out-dir", ".wirediet/policies", "directory for reversible policy bundles")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		t, err := experiment.Next(*sp, *out)
		if err != nil {
			return err
		}
		fmt.Printf("Trial %s: temporarily block %d domain(s).\nPolicy bundle: %s\n", t.ID, len(t.Domains), filepath.Join(*out, t.ID))
		fmt.Println("Test every required feature, then record pass/fail/skip for each feature.")
		return nil
	case "record":
		fs := flag.NewFlagSet("experiment record", flag.ContinueOnError)
		sp := fs.String("session", ".wirediet/session.json", "session state path")
		trial := fs.String("trial", "", "trial ID")
		results := fs.String("results", "", "comma-separated Feature=pass|fail|skip entries")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *trial == "" || *results == "" {
			return fmt.Errorf("--trial and --results are required")
		}
		s, err := experiment.Record(*sp, *trial, experiment.ParseResults(*results))
		if err != nil {
			return err
		}
		printSessionStatus(s)
		return nil
	case "status":
		fs := flag.NewFlagSet("experiment status", flag.ContinueOnError)
		sp := fs.String("session", ".wirediet/session.json", "session state path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		s, err := experiment.Load(*sp)
		if err != nil {
			return err
		}
		printSessionStatus(s)
		return nil
	default:
		return fmt.Errorf("unknown experiment subcommand %q", args[0])
	}
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	sp := fs.String("session", "", "completed experiment session")
	ap := fs.String("analysis", "", "analysis JSON (exports UNVERIFIED candidates only)")
	out := fs.String("out-dir", "wirediet-policy", "policy output directory")
	allowUnverified := fs.Bool("allow-unverified", false, "required when exporting directly from analysis")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sp != "" && *ap != "" {
		return fmt.Errorf("choose --session or --analysis, not both")
	}
	if *sp != "" {
		s, err := experiment.Load(*sp)
		if err != nil {
			return err
		}
		ds, err := experiment.FinalDomains(s)
		if err != nil {
			return err
		}
		if err := policy.WriteBundle(*out, ds, "learned-final-policy"); err != nil {
			return err
		}
		fmt.Printf("Exported %d learned domains to %s\n", len(ds), *out)
		return nil
	}
	if *ap != "" {
		if !*allowUnverified {
			return fmt.Errorf("analysis candidates have not passed your feature tests; add --allow-unverified only to create an experimental trial bundle")
		}
		a, err := report.ReadAnalysis(*ap)
		if err != nil {
			return err
		}
		ds, _, _ := policy.CandidateDomains(a)
		if err := policy.WriteBundle(*out, ds, "UNVERIFIED-candidate-policy"); err != nil {
			return err
		}
		fmt.Printf("Exported %d UNVERIFIED candidate domains to %s\n", len(ds), *out)
		return nil
	}
	return fmt.Errorf("--session or --analysis is required")
}

func cmdRedact(args []string) error {
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
	in := fs.String("analysis", "analysis.json", "analysis JSON")
	out := fs.String("out", "analysis.public.json", "redacted output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := report.ReadAnalysis(*in)
	if err != nil {
		return err
	}
	return report.WriteJSON(*out, redact.Analysis(a))
}

func loadEvidence(path string) (*evidence.DB, error) {
	if strings.TrimSpace(path) == "" {
		return evidence.LoadDefault()
	}
	return evidence.Load(path)
}
func splitCSV(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
func printSessionStatus(s model.Session) {
	pending := 0
	done := 0
	for _, t := range s.Trials {
		if t.Status == "pending" {
			pending++
		} else {
			done++
		}
	}
	fmt.Printf("Session %s\nCandidates: %d | trials completed: %d | pending: %d | queued groups: %d\n", s.ID, len(s.Candidates), done, pending, len(s.Queue))
	fmt.Printf("Final verification: %s\n", s.FinalVerification)
	if len(s.RequiredForFeature) > 0 {
		fmt.Println("Known required domains:")
		for _, f := range s.Features {
			if ds := s.RequiredForFeature[f]; len(ds) > 0 {
				fmt.Printf("  %s: %s\n", f, strings.Join(ds, ", "))
			}
		}
	}
	if s.InteractionWarning {
		fmt.Println("WARNING: the aggregate policy failed after narrower tests passed; interaction risk remains. Final export is disabled.")
	}
}
