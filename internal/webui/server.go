package webui

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/model"
)

const favicon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#0b1720"/><path d="M7 18c10 0 13 8 23 8" fill="none" stroke="#8aa0ad" stroke-width="5" stroke-linecap="round"/><path d="M7 31c10 0 13 0 23 0" fill="none" stroke="#2b8bdc" stroke-width="5" stroke-linecap="round"/><path d="M7 44c10 0 13-8 23-8" fill="none" stroke="#d79a3b" stroke-width="5" stroke-linecap="round"/><path d="M33 13v38" stroke="#d8e3e9" stroke-width="5" stroke-linecap="round"/><path d="M38 31h15" stroke="#65d58b" stroke-width="5" stroke-linecap="round"/><path d="m49 24 7 7-7 7" fill="none" stroke="#65d58b" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>`

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireDiet · Observe → Test → Verify</title><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
:root{color-scheme:light dark;--bg:#f5f7f8;--surface:#fff;--surface2:#f0f3f4;--ink:#13212a;--muted:#60717c;--line:#d8e0e4;--blue:#1f78c8;--green:#278a52;--amber:#a86d18;--red:#a8473d;--shadow:0 10px 30px #0d1b2412;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
@media(prefers-color-scheme:dark){:root{--bg:#0c1318;--surface:#111b22;--surface2:#17242c;--ink:#eef4f6;--muted:#9eb0ba;--line:#273640;--blue:#65adf0;--green:#72d99a;--amber:#e7b765;--red:#ed8c82;--shadow:0 12px 36px #0006}}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--bg);color:var(--ink);line-height:1.5}a{color:var(--blue)}a:focus-visible,button:focus-visible,[tabindex]:focus-visible{outline:3px solid color-mix(in srgb,var(--blue) 55%,transparent);outline-offset:3px}.skip{position:absolute;left:-9999px}.skip:focus{left:16px;top:12px;background:var(--surface);padding:8px 12px;border-radius:8px;z-index:5}.shell{max-width:1180px;margin:auto;padding:28px 22px 64px}.top{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:22px}.brand{display:flex;align-items:center;gap:12px}.brand svg{width:42px;height:42px;flex:none}.brand strong{font-size:1.1rem}.brand small{display:block;color:var(--muted);font-size:.82rem}.privacy{font-size:.8rem;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:6px 10px;background:var(--surface)}.hero{display:grid;grid-template-columns:1.35fr .65fr;gap:18px;margin-bottom:18px}.hero-card,.trust-card,.stage,.panel,.metric,.notice{background:var(--surface);border:1px solid var(--line);box-shadow:var(--shadow);border-radius:16px}.hero-card{padding:26px}.eyebrow{text-transform:uppercase;letter-spacing:.12em;color:var(--blue);font-weight:750;font-size:.72rem}.hero h1{font-size:clamp(2rem,5vw,3.25rem);line-height:1.02;margin:8px 0}.tagline{font-size:1.15rem;font-weight:700;margin:0 0 10px}.hero p{color:var(--muted);max-width:62ch;margin:0}.trust-card{padding:20px}.trust-card b{display:block;margin-bottom:8px}.trust-card p{font-size:.92rem;color:var(--muted);margin:0}.stage-rail{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.stage{padding:18px;border-top:4px solid var(--line)}.stage.observe{border-top-color:var(--blue)}.stage.test{border-top-color:var(--amber)}.stage.verify{border-top-color:var(--green)}.stage-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.stage-kicker{font-weight:800;font-size:.78rem;letter-spacing:.08em}.stage-state{font-size:.75rem;border:1px solid var(--line);border-radius:999px;padding:3px 8px;color:var(--muted)}.stage h2{margin:6px 0 6px;font-size:1.2rem}.stage p{margin:0;color:var(--muted);font-size:.9rem}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}.metric{padding:17px}.metric .n{font-size:1.75rem;font-weight:800;line-height:1}.metric .label{margin-top:6px;font-weight:700}.metric .sub{margin-top:3px;color:var(--muted);font-size:.82rem}.panel{padding:20px;margin-top:16px}.panel h2{font-size:1.25rem;margin:0 0 4px}.panel .intro{color:var(--muted);margin:0 0 16px}.unknown-note{background:color-mix(in srgb,var(--amber) 10%,var(--surface));border:1px solid color-mix(in srgb,var(--amber) 40%,var(--line));border-radius:12px;padding:14px 16px;margin:14px 0}.unknown-note strong{color:var(--amber)}.unknown-note p{margin:4px 0 0;color:var(--muted)}.warnings{display:grid;gap:8px;margin:12px 0}.warn{border-left:3px solid var(--amber);padding:9px 12px;background:var(--surface2);border-radius:8px}.meta{display:flex;flex-wrap:wrap;gap:8px 18px;color:var(--muted);font-size:.85rem;margin:12px 0}.meta code{color:var(--ink)}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}.domains{border-collapse:collapse;width:100%;min-width:780px;font-size:.9rem}.domains th,.domains td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top}.domains th{background:var(--surface2);font-size:.76rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);position:sticky;top:0}.domains tr:last-child td{border-bottom:0}.domain{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere;word-break:break-word;max-width:340px}.pill{display:inline-flex;align-items:center;border-radius:999px;padding:3px 8px;font-size:.76rem;font-weight:750;border:1px solid var(--line)}.pill.unknown{color:var(--amber);background:color-mix(in srgb,var(--amber) 9%,transparent)}.pill.candidate{color:var(--blue);background:color-mix(in srgb,var(--blue) 9%,transparent)}.pill.protect{color:var(--green);background:color-mix(in srgb,var(--green) 9%,transparent)}.evidence{display:grid;gap:3px}.evidence a{overflow-wrap:anywhere}.empty{border:1px dashed var(--line);border-radius:12px;padding:18px;color:var(--muted)}.session-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.session-card{border:1px solid var(--line);border-radius:12px;padding:15px;background:var(--surface2)}.session-card h3{margin:0 0 7px;font-size:1rem}.session-card p{margin:3px 0;color:var(--muted);font-size:.88rem}.features{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}.feature{border:1px solid var(--line);background:var(--surface);border-radius:8px;padding:4px 7px;font-size:.78rem}.footer{margin-top:22px;color:var(--muted);font-size:.8rem;display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px}
@media(max-width:820px){.hero{grid-template-columns:1fr}.stage-rail,.metrics,.session-grid{grid-template-columns:1fr 1fr}.top{align-items:flex-start}.privacy{display:none}}
@media(max-width:560px){.shell{padding:18px 14px 44px}.stage-rail,.metrics,.session-grid{grid-template-columns:1fr}.hero-card{padding:20px}.panel{padding:15px}.brand small{display:none}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
</style></head><body><a class="skip" href="#observe">Skip to analysis</a>
<div class="shell"><header class="top"><div class="brand"><svg aria-hidden="true" viewBox="0 0 64 64"><rect width="64" height="64" rx="15" fill="#0b1720"/><path d="M7 18c10 0 13 8 23 8" fill="none" stroke="#8aa0ad" stroke-width="5" stroke-linecap="round"/><path d="M7 31c10 0 13 0 23 0" fill="none" stroke="#2b8bdc" stroke-width="5" stroke-linecap="round"/><path d="M7 44c10 0 13-8 23-8" fill="none" stroke="#d79a3b" stroke-width="5" stroke-linecap="round"/><path d="M33 13v38" stroke="#d8e3e9" stroke-width="5" stroke-linecap="round"/><path d="M38 31h15" stroke="#65d58b" stroke-width="5" stroke-linecap="round"/><path d="m49 24 7 7-7 7" fill="none" stroke="#65d58b" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg><div><strong>WireDiet</strong><small>Cut the chatter. Keep the features.</small></div></div><div class="privacy">Local only · no remote assets · no telemetry</div></header>
<section class="hero"><div class="hero-card"><div class="eyebrow">DNS policy discovery</div><h1>Observe. Test. Verify.</h1><p class="tagline">Build minimal, device-specific DNS policies through real experiments.</p><p>WireDiet doesn’t replace AdGuard Home or Pi-hole. It helps you decide what to put in them.</p></div><aside class="trust-card"><b>Unknown is a valid result.</b><p>WireDiet classifies only what the loaded evidence supports. Insufficient evidence means leave the domain alone—not “probably tracking.”</p></aside></section>
<div class="stage-rail" aria-label="WireDiet workflow"><div class="stage observe"><div class="stage-head"><span class="stage-kicker">OBSERVE</span><span class="stage-state">{{len .Analysis.Domains}} domains</span></div><h2>See what talks</h2><p>Import resolver data and separate evidence-backed findings from unknowns.</p></div><div class="stage test"><div class="stage-head"><span class="stage-kicker">TEST</span><span class="stage-state">{{if .Session}}{{.TestState}}{{else}}{{.Candidates}} candidates{{end}}</span></div><h2>Try exact-host changes</h2><p>Generate reversible trials and record whether required features still work.</p></div><div class="stage verify"><div class="stage-head"><span class="stage-kicker">VERIFY</span><span class="stage-state">{{.VerifyState}}</span></div><h2>Keep only what passed</h2><p>Require aggregate verification before treating a learned policy as final.</p></div></div>
<main id="observe"><section class="metrics" aria-label="Analysis summary"><div class="metric"><div class="n">{{.Analysis.EventCount}}</div><div class="label">Queries observed</div><div class="sub">Parsed events for this analysis</div></div><div class="metric"><div class="n">{{len .Analysis.Domains}}</div><div class="label">Domains observed</div><div class="sub">Unique normalized hostnames</div></div><div class="metric"><div class="n">{{.Candidates}}</div><div class="label">Evidence-backed candidates</div><div class="sub">Eligible for reversible testing</div></div><div class="metric"><div class="n">{{.Unknown}}</div><div class="label">Unknown</div><div class="sub">Insufficient evidence; leave alone</div></div></section>
<section class="panel"><h2>Observe</h2><p class="intro">What this device actually queried, with evidence and confidence kept separate from observation.</p>{{if eq .Candidates 0}}<div class="unknown-note"><strong>No candidates is a valid result.</strong><p>Nothing in this analysis has enough evidence to justify a block trial. Unknown domains remain untouched.</p></div>{{end}}{{if .Analysis.Warnings}}<div class="warnings">{{range .Analysis.Warnings}}<div class="warn">{{.}}</div>{{end}}</div>{{end}}<div class="meta"><span><b>Device:</b> <code>{{if .Analysis.Device}}{{.Analysis.Device}}{{else}}all imported clients{{end}}</code></span><span><b>Input:</b> {{.Analysis.SourceFormat}}</span>{{if .Analysis.EvidenceReviewedAt}}<span><b>Evidence reviewed:</b> {{.Analysis.EvidenceReviewedAt}}</span>{{end}}</div>
<div class="table-wrap" role="region" aria-label="Observed domains" tabindex="0"><table class="domains"><thead><tr><th>Domain</th><th>Queries</th><th>Category</th><th>Confidence</th><th>Disposition</th><th>Evidence</th></tr></thead><tbody>{{range .Analysis.Domains}}<tr><td class="domain">{{.Domain}}</td><td>{{.Queries}}</td><td>{{.Category}}</td><td>{{.Confidence}}</td><td><span class="pill {{class .Disposition}}">{{label .Disposition}}</span></td><td><div class="evidence">{{if .Evidence}}{{range .Evidence}}<a href="{{.URL}}" rel="noreferrer noopener">{{.Title}}</a>{{end}}{{else}}<span class="muted">Insufficient evidence</span>{{end}}</div></td></tr>{{end}}</tbody></table></div></section>
<section id="test" class="panel"><h2>Test</h2><p class="intro">Reversible exact-host trials. This page is read-only; WireDiet never applies resolver changes from the browser.</p>{{if .Session}}<div class="session-grid"><div class="session-card"><h3>Required features</h3><div class="features">{{range .Session.Features}}<span class="feature">{{.}}</span>{{end}}</div></div><div class="session-card"><h3>Trial state</h3>{{if .Pending}}<p><b>{{.Pending.ID}}</b> is pending with {{len .Pending.Domains}} hostname(s).</p><p>Apply only the generated test bundle to the intended client, test every required feature, then record results in the CLI.</p>{{else}}<p>{{.CompletedTrials}} trial(s) completed. No trial is currently pending.</p>{{end}}</div></div>{{else}}<div class="empty">No experiment session loaded. Start one with <code>wirediet experiment init</code>, then reopen the UI with <code>--session .wirediet/session.json</code> to see live trial state here.</div>{{end}}</section>
<section id="verify" class="panel"><h2>Verify</h2><p class="intro">A policy is not learned until the required features pass together under the aggregate rule set.</p>{{if .Session}}<div class="session-grid"><div class="session-card"><h3>Aggregate verification</h3><p><span class="pill {{verifyClass .Session.FinalVerification}}">{{verifyLabel .Session.FinalVerification}}</span></p><p>{{.SafeCount}} hostname(s) have passed narrower feature tests.</p></div><div class="session-card"><h3>Rollback</h3><p>Every generated trial bundle includes <code>rollback.json</code>. Resolver application remains manual in v0.1.</p>{{if .Session.InteractionWarning}}<p style="color:var(--red)"><b>Interaction warning:</b> the aggregate result conflicts with narrower trials. Final export remains blocked.</p>{{end}}</div></div>{{else}}<div class="empty">Verification has not started in this analysis-only view. That is not a failure state; it means no experiment session was supplied.</div>{{end}}</section></main>
<footer class="footer"><span>WireDiet local UI · no cloud upload</span><span><a href="/analysis.json">Raw analysis JSON</a> · evidence links open only when you choose them</span></footer></div></body></html>`

type view struct {
	Analysis                       model.Analysis
	Session                        *model.Session
	Pending                        *model.Trial
	Candidates, Protected, Unknown int
	CompletedTrials, SafeCount     int
	TestState, VerifyState         string
}

func newTemplate() *template.Template {
	return template.Must(template.New("page").Funcs(template.FuncMap{
		"class": func(s string) string {
			switch s {
			case "protect":
				return "protect"
			case "block_candidate":
				return "candidate"
			default:
				return "unknown"
			}
		},
		"label": func(s string) string {
			switch s {
			case "protect":
				return "Protected"
			case "block_candidate":
				return "Candidate"
			default:
				return "Unknown"
			}
		},
		"verifyLabel": func(s string) string {
			switch s {
			case "passed":
				return "Verified"
			case "failed":
				return "Failed"
			case "pending":
				return "Pending"
			default:
				return "Not started"
			}
		},
		"verifyClass": func(s string) string {
			switch s {
			case "passed":
				return "protect"
			case "failed":
				return "unknown"
			case "pending":
				return "candidate"
			default:
				return "unknown"
			}
		},
	}).Parse(page))
}

func Serve(a model.Analysis, s *model.Session, addr string) error {
	if err := loopbackOnly(addr); err != nil {
		return err
	}
	t := newTemplate()
	v := makeView(a, s)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		headers(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = t.Execute(w, v)
	})
	mux.HandleFunc("/analysis.json", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	})
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte(favicon))
	})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host, addr) {
			http.Error(w, "invalid Host header", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	fmt.Printf("WireDiet local UI: http://%s\n", addr)
	return srv.ListenAndServe()
}

func makeView(a model.Analysis, s *model.Session) view {
	v := view{Analysis: a, Session: s, TestState: fmt.Sprintf("%d candidates", countDisposition(a, "block_candidate")), VerifyState: "not started"}
	v.Candidates = countDisposition(a, "block_candidate")
	v.Protected = countDisposition(a, "protect")
	v.Unknown = len(a.Domains) - v.Candidates - v.Protected
	if s == nil {
		return v
	}
	v.SafeCount = len(s.SafeToBlock)
	v.VerifyState = strings.ReplaceAll(s.FinalVerification, "_", " ")
	for i := range s.Trials {
		tr := &s.Trials[i]
		if tr.Status == "pending" {
			v.Pending = tr
		} else {
			v.CompletedTrials++
		}
	}
	if v.Pending != nil {
		v.TestState = "trial pending"
	} else if v.CompletedTrials > 0 {
		v.TestState = fmt.Sprintf("%d completed", v.CompletedTrials)
	} else {
		v.TestState = fmt.Sprintf("%d candidates", len(s.Candidates))
	}
	return v
}

func countDisposition(a model.Analysis, disposition string) int {
	n := 0
	for _, d := range a.Domains {
		if d.Disposition == disposition {
			n++
		}
	}
	return n
}

func headers(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}

func allowedHost(requestHost, addr string) bool {
	listenHost, listenPort, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	requestHost = strings.ToLower(strings.TrimSpace(requestHost))
	listenHost = strings.Trim(strings.ToLower(listenHost), "[]")
	allowed := map[string]bool{
		net.JoinHostPort(listenHost, listenPort):  true,
		net.JoinHostPort("localhost", listenPort): true,
	}
	if ip := net.ParseIP(listenHost); ip != nil && ip.IsLoopback() {
		allowed[net.JoinHostPort("127.0.0.1", listenPort)] = true
		allowed[net.JoinHostPort("::1", listenPort)] = true
	}
	return allowed[requestHost]
}

func loopbackOnly(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing non-loopback bind %q; WireDiet UI is local-only", host)
	}
	return nil
}
