package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/store"
)

func TestDashboardRenders(t *testing.T) {
	st := store.NewMemory()
	// Two hosts on different OS types.
	u, _ := st.UpsertAgent(model.Agent{ID: "agent-u1", MachineID: "u1", Hostname: "u1", OSID: "ubuntu", OSVersionID: "24.04"})
	_, _ = st.UpsertAgent(model.Agent{ID: "agent-d1", MachineID: "d1", Hostname: "d1", OSID: "debian", OSVersionID: "12"})

	// One HIGH finding on the ubuntu host, backed by an enriched CVE.
	_ = st.UpsertEnrichment(model.Enrichment{CVE: "CVE-2024-1000", CVSSSeverity: "HIGH", CVSSScore: 7.5})
	if _, _, err := st.ReconcileFindings(u.ID, []model.Finding{
		{CVE: "CVE-2024-1000", SourcePackage: "openssl", Running: true, Status: "open"},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}

	d := New(st, "admin", "pw", []byte("k"), "0.1.1") // also parses all templates
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	d.dashboard(rr, req)

	body := rr.Body.String()
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	for _, want := range []string{
		"Findings by OS", "Impacted hosts", "Top flaws",
		"ubuntu 24.04", "debian 12", "Total",
		"CVE-2024-1000", // top flaw listed
		"1/2",           // donut: 1 of 2 hosts impacted
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}
