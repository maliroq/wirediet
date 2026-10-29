package redact

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/maliroq/wirediet/internal/model"
)

var macRE = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
var ipv4TokenRE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
var ipv6TokenRE = regexp.MustCompile(`(?i)[0-9a-f:]{2,39}`)

func Text(s string) string {
	s = macRE.ReplaceAllString(s, "[redacted-mac]")
	replaceIP := func(token string) string {
		a, err := netip.ParseAddr(strings.Trim(token, "[]"))
		if err != nil {
			return token
		}
		if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
			return "[redacted-local-ip]"
		}
		return token
	}
	s = ipv4TokenRE.ReplaceAllStringFunc(s, replaceIP)
	s = ipv6TokenRE.ReplaceAllStringFunc(s, func(token string) string {
		if !strings.Contains(token, ":") {
			return token
		}
		return replaceIP(token)
	})
	return s
}

func Analysis(a model.Analysis) model.Analysis {
	if a.Device != "" {
		a.Device = "[redacted-device]"
	}
	// A public/identifier-redacted report does not need the household run time.
	a.GeneratedAt = time.Time{}
	for i := range a.Warnings {
		a.Warnings[i] = Text(a.Warnings[i])
	}
	for i := range a.Domains {
		// Exact household timing is not needed for a identifier-redacted evidence report.
		a.Domains[i].FirstSeen = time.Time{}
		a.Domains[i].LastSeen = time.Time{}
		a.Domains[i].Notes = Text(a.Domains[i].Notes)
		for j := range a.Domains[i].Evidence {
			a.Domains[i].Evidence[j].Title = Text(a.Domains[i].Evidence[j].Title)
			a.Domains[i].Evidence[j].URL = Text(a.Domains[i].Evidence[j].URL)
		}
	}
	return a
}
