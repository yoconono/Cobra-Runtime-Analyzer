package store

import (
	"testing"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

func TestCatalogSearch(t *testing.T) {
	m := NewMemory()
	m.ReplaceTracker([]model.Advisory{
		{CVE: "CVE-2025-1", SourcePackage: "openssl", Release: "noble", Status: "resolved", FixedVersion: "3.0.13-1"},
		{CVE: "CVE-2025-1", SourcePackage: "openssl", Release: "bookworm", Status: "resolved", FixedVersion: "3.0.11-1"},
		{CVE: "CVE-2025-2", SourcePackage: "curl", Release: "noble", Status: "open"},
	})
	m.UpsertEnrichment(model.Enrichment{CVE: "CVE-2025-1", CVSSSeverity: "HIGH", CVSSScore: 7.5, Summary: "openssl bug"})
	m.UpsertKEV("CVE-2025-2", timeZero(), timeZero(), false)
	m.UpsertEnrichment(model.Enrichment{CVE: "CVE-2025-2", CVSSSeverity: "CRITICAL", CVSSScore: 9.8, Summary: "curl rce"})
	m.UpsertKEV("CVE-2025-2", timeZero(), timeZero(), false)

	// Advisory text search
	advs, total, _ := m.SearchAdvisories(AdvisoryQuery{Text: "openssl"})
	if total != 2 || len(advs) != 2 {
		t.Errorf("openssl advisories: total=%d len=%d want 2", total, len(advs))
	}
	// Release filter
	_, total, _ = m.SearchAdvisories(AdvisoryQuery{Release: "noble"})
	if total != 2 {
		t.Errorf("noble advisories total=%d want 2", total)
	}
	// AdvisoriesForCVE
	forCVE, _ := m.AdvisoriesForCVE("CVE-2025-1")
	if len(forCVE) != 2 {
		t.Errorf("advisories for CVE-2025-1 = %d want 2", len(forCVE))
	}
	// Releases
	rels, _ := m.TrackerReleases()
	if len(rels) != 2 {
		t.Errorf("releases=%v want 2", rels)
	}
	// CVE catalog search
	cves, ctotal, _ := m.SearchCVEs(CVEQuery{Text: "curl"})
	if ctotal != 1 || len(cves) != 1 || cves[0].CVE != "CVE-2025-2" {
		t.Errorf("cve search curl: total=%d %v", ctotal, cves)
	}
	// Severity filter
	_, ctotal, _ = m.SearchCVEs(CVEQuery{Severity: "CRITICAL"})
	if ctotal != 1 {
		t.Errorf("CRITICAL cves=%d want 1", ctotal)
	}
	// KEV filter
	kev, _, _ := m.SearchCVEs(CVEQuery{KEVOnly: true})
	if len(kev) != 1 || kev[0].CVE != "CVE-2025-2" {
		t.Errorf("kev-only=%v", kev)
	}
}

func timeZero() time.Time { return time.Time{} }
