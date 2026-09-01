package enrich

import (
	"strings"
	"testing"
)

const kevSample = `{
  "title":"CISA KEV","catalogVersion":"2025.01.01","count":2,
  "vulnerabilities":[
    {"cveID":"CVE-2025-DEMO-0001","vendorProject":"OpenSSL","product":"openssl",
     "dateAdded":"2025-02-05","dueDate":"2025-02-26","knownRansomwareCampaignUse":"Known"},
    {"cveID":"CVE-2024-DEMO-PQ","vendorProject":"lib","product":"pq",
     "dateAdded":"2024-11-01","dueDate":"2024-11-22","knownRansomwareCampaignUse":"Unknown"}
  ]
}`

func TestParseKEV(t *testing.T) {
	m, err := ParseKEV(strings.NewReader(kevSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("want 2, got %d", len(m))
	}
	a := m["CVE-2025-DEMO-0001"]
	if !a.Ransomware {
		t.Error("CVE-2025-DEMO-0001 should be flagged ransomware")
	}
	if a.DateAdded.IsZero() || a.DueDate.IsZero() {
		t.Error("dates not parsed")
	}
	if m["CVE-2024-DEMO-PQ"].Ransomware {
		t.Error("CVE-2024-DEMO-PQ should not be ransomware")
	}
}

const epssSample = `#model_version:v2025.03.14,score_date:2025-08-20T00:00:00Z
cve,epss,percentile
CVE-2025-DEMO-0001,0.94210,0.99850
CVE-2024-DEMO-PQ,0.12300,0.85000
CVE-2020-DEMO-LIB,0.00042,0.09000
`

func TestParseEPSS(t *testing.T) {
	m, err := ParseEPSS(strings.NewReader(epssSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 3 {
		t.Fatalf("want 3, got %d", len(m))
	}
	if got := m["CVE-2025-DEMO-0001"]; got.Score < 0.94 || got.Percentile < 0.99 {
		t.Errorf("bad epss for demo-0001: %+v", got)
	}
	if got := m["CVE-2020-DEMO-LIB"].Score; got > 0.01 {
		t.Errorf("expected low epss, got %v", got)
	}
}
