package enrich

import (
	"strings"
	"testing"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

const nvdSample = `{
  "vulnerabilities": [
    {"cve": {
      "id": "CVE-2023-1000",
      "published": "2023-05-01T00:00:00.000",
      "lastModified": "2023-06-01T00:00:00.000",
      "descriptions": [{"lang":"en","value":"Example NVD description."}],
      "metrics": {"cvssMetricV31": [
        {"type":"Primary","cvssData":{"version":"3.1",
          "vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
      "references": [{"url":"https://example.com/advisory"}]
    }}
  ]
}`

func TestParseNVD(t *testing.T) {
	es, err := ParseNVD(strings.NewReader(nvdSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(es))
	}
	e := es[0]
	if e.CVE != "CVE-2023-1000" || e.CVSSScore != 9.8 || e.CVSSSeverity != "CRITICAL" {
		t.Errorf("bad parse: %+v", e)
	}
	if e.Summary == "" || len(e.References) != 1 {
		t.Errorf("missing summary/references: %+v", e)
	}
	if e.Published.IsZero() {
		t.Error("published time not parsed")
	}
}

// NVD entry with only a v3 vector (no baseScore/severity) should be computed.
const nvdVectorOnly = `{"vulnerabilities":[{"cve":{"id":"CVE-2023-2000",
 "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{
   "vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]}}}]}`

func TestParseNVDComputesFromVector(t *testing.T) {
	es, _ := ParseNVD(strings.NewReader(nvdVectorOnly))
	if es[0].CVSSScore != 7.5 || es[0].CVSSSeverity != "HIGH" {
		t.Errorf("expected computed 7.5/HIGH, got %.1f/%s", es[0].CVSSScore, es[0].CVSSSeverity)
	}
}

const osvSample = `[
  {"id":"CVE-2023-1000","summary":"Example OSV summary.",
   "aliases":["GHSA-xxxx-yyyy-zzzz"],
   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
   "references":[{"type":"WEB","url":"https://osv.dev/CVE-2023-1000"}]},
  {"id":"GHSA-only-record","aliases":["CVE-2023-3000"],
   "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}]}
]`

func TestParseOSVList(t *testing.T) {
	m, err := ParseOSVList(strings.NewReader(osvSample))
	if err != nil {
		t.Fatal(err)
	}
	// First record is keyed by its CVE id (C:L over network => 5.3 MEDIUM).
	if e, ok := m["CVE-2023-1000"]; !ok || e.CVSSSeverity != "MEDIUM" {
		t.Errorf("CVE-2023-1000 parse: %+v ok=%v", e, ok)
	}
	// Second record is a GHSA whose CVE alias becomes the key.
	if e, ok := m["CVE-2023-3000"]; !ok || e.CVSSSeverity != "MEDIUM" {
		t.Errorf("CVE-2023-3000 (via alias) parse: %+v ok=%v", e, ok)
	}
}

func TestMergePrefersNVDForCVSS(t *testing.T) {
	nvd := &model.Enrichment{CVE: "CVE-1", CVSSScore: 9.8, CVSSSeverity: "CRITICAL", CVSSVector: "v-nvd", Summary: "nvd"}
	osv := &model.Enrichment{CVE: "CVE-1", CVSSScore: 3.1, CVSSSeverity: "LOW", CVSSVector: "v-osv", Aliases: []string{"GHSA-1"}}
	m, ok := Merge("CVE-1", nvd, osv)
	if !ok || m.CVSSSeverity != "CRITICAL" || m.CVSSVector != "v-nvd" {
		t.Errorf("merge should prefer NVD CVSS: %+v", m)
	}
	if len(m.Aliases) != 1 || m.Aliases[0] != "GHSA-1" {
		t.Errorf("merge should union OSV aliases: %+v", m.Aliases)
	}
	if m.Source != "nvd+osv" {
		t.Errorf("source should be nvd+osv, got %q", m.Source)
	}
}

func TestMergeFallsBackToOSV(t *testing.T) {
	osv := &model.Enrichment{CVE: "CVE-2", CVSSScore: 7.5, CVSSSeverity: "HIGH", CVSSVector: "v-osv"}
	m, ok := Merge("CVE-2", nil, osv)
	if !ok || m.CVSSSeverity != "HIGH" || m.Source != "osv" {
		t.Errorf("merge should use OSV when NVD absent: %+v", m)
	}
}
