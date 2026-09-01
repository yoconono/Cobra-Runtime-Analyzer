package osvmatch

import (
	"strings"
	"testing"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

const sample = `[
  {"id":"GHSA-lib-pq","aliases":["CVE-2024-PQ"],
   "summary":"lib/pq flaw.",
   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
   "affected":[{"package":{"ecosystem":"Go","name":"github.com/lib/pq"},
     "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.11.0"}]}]}]},
  {"id":"CVE-2018-LEFT","summary":"leftpad issue.",
   "affected":[{"package":{"ecosystem":"npm","name":"leftpad"},
     "versions":["0.0.9"]}]},
  {"id":"CVE-2020-DEMOLIB","summary":"demo-lib rce.",
   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
   "affected":[{"package":{"ecosystem":"PyPI","name":"demo-lib"},
     "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}
]`

type mapSource map[string][]model.LangAdvisory

func (m mapSource) ForLangPackage(eco, name string) []model.LangAdvisory { return m[eco+"|"+name] }

func indexToSource(advs []model.LangAdvisory) mapSource {
	s := mapSource{}
	for _, a := range advs {
		k := a.Ecosystem + "|" + a.Package
		s[k] = append(s[k], a)
	}
	return s
}

func TestParseAndMatch(t *testing.T) {
	advs, err := ParseIndex(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	src := indexToSource(advs)

	pkgs := []model.LangPackage{
		{Ecosystem: "Go", Name: "github.com/lib/pq", Version: "1.10.9", Running: true}, // < 1.11.0 -> vuln
		{Ecosystem: "npm", Name: "leftpad", Version: "0.0.9"},                          // exact match -> vuln
		{Ecosystem: "PyPI", Name: "demo-lib", Version: "1.0.0"},                        // < 1.2.0 -> vuln
		{Ecosystem: "npm", Name: "leftpad", Version: "1.0.0"},                          // not listed -> safe
		{Ecosystem: "Go", Name: "github.com/lib/pq", Version: "1.11.0"},                // == fixed -> safe
	}
	got := Match(pkgs, src)
	found := map[string]model.Finding{}
	for _, f := range got {
		found[f.SourcePackage] = f
	}
	if f, ok := found["github.com/lib/pq"]; !ok || f.CVE != "CVE-2024-PQ" || f.FixedVersion != "1.11.0" {
		t.Errorf("lib/pq: %+v ok=%v", f, ok)
	}
	if !found["github.com/lib/pq"].Running {
		t.Error("lib/pq finding should be running")
	}
	if f, ok := found["leftpad"]; !ok || f.CVE != "CVE-2018-LEFT" {
		t.Errorf("leftpad: %+v ok=%v", f, ok)
	}
	if f, ok := found["demo-lib"]; !ok || f.Ecosystem != "PyPI" {
		t.Errorf("demo-lib: %+v ok=%v", f, ok)
	}
	// lib/pq@1.11.0 and leftpad@1.0.0 must NOT produce extra findings.
	if len(got) != 3 {
		t.Errorf("expected 3 findings, got %d: %+v", len(got), got)
	}
}

func TestEnrichment(t *testing.T) {
	advs, _ := ParseIndex(strings.NewReader(sample))
	src := indexToSource(advs)
	adv := src["PyPI|demo-lib"][0]
	e := Enrichment(adv)
	if e.CVE != "CVE-2020-DEMOLIB" || e.CVSSSeverity != "CRITICAL" {
		t.Errorf("enrichment: %+v", e)
	}
}
