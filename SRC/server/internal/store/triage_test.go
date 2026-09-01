package store

import (
	"testing"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

func TestMemoryTriageSuppression(t *testing.T) {
	m := NewMemory()
	ag := &model.Agent{ID: "agent-1", Hostname: "host-a", OSID: "debian", OSVersionID: "12"}
	m.agents[ag.ID] = ag

	m.enrich["CVE-A"] = model.Enrichment{CVE: "CVE-A", CVSSSeverity: "CRITICAL", CVSSScore: 9.8}
	m.enrich["CVE-B"] = model.Enrichment{CVE: "CVE-B", CVSSSeverity: "HIGH", CVSSScore: 7.5}

	findings := []model.Finding{
		{CVE: "CVE-A", SourcePackage: "openssl", InstalledVersion: "1.0", Running: true, Status: "open"},
		{CVE: "CVE-B", SourcePackage: "bash", InstalledVersion: "5.0", Status: "open"},
	}
	if _, _, err := m.ReconcileFindings(ag.ID, findings, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Baseline: both findings count.
	agents, _ := m.ListAgents()
	if agents[0].FindingCount != 2 {
		t.Fatalf("baseline finding count = %d, want 2", agents[0].FindingCount)
	}
	if cves, _ := m.ListCVEs(); len(cves) != 2 {
		t.Fatalf("baseline cve count = %d, want 2", len(cves))
	}

	// Mute CVE-A -> it drops from counts and the CVE list.
	if err := m.SetTriage(model.Triage{
		AgentID: ag.ID, CVE: "CVE-A", SourcePackage: "openssl", State: model.TriageMuted,
		Actor: "alice", Note: "false positive",
	}); err != nil {
		t.Fatal(err)
	}
	agents, _ = m.ListAgents()
	if agents[0].FindingCount != 1 || agents[0].SeverityCounts["CRITICAL"] != 0 {
		t.Errorf("after mute: count=%d crit=%d, want 1 and 0", agents[0].FindingCount, agents[0].SeverityCounts["CRITICAL"])
	}
	cves, _ := m.ListCVEs()
	if len(cves) != 1 || cves[0].CVE != "CVE-B" {
		t.Errorf("after mute: cves=%v, want only CVE-B", cves)
	}

	// ListFindings still returns the muted finding (for the agent page) with state.
	fs, _ := m.ListFindings(ag.ID)
	var seenMuted bool
	for _, f := range fs {
		if f.CVE == "CVE-A" && f.TriageState == model.TriageMuted {
			seenMuted = true
		}
	}
	if !seenMuted {
		t.Error("ListFindings should still expose the muted finding with its triage state")
	}

	// Snooze that lapses should NOT suppress.
	past := time.Now().Add(-time.Hour)
	if err := m.SetTriage(model.Triage{
		AgentID: ag.ID, CVE: "CVE-A", SourcePackage: "openssl", State: model.TriageSnoozed,
		Until: past, Actor: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	agents, _ = m.ListAgents()
	if agents[0].FindingCount != 2 {
		t.Errorf("expired snooze should not suppress: count=%d want 2", agents[0].FindingCount)
	}

	// Audit log records each action, newest first.
	events, _ := m.AuditLog(0)
	if len(events) != 2 {
		t.Fatalf("audit events = %d, want 2", len(events))
	}
	if events[0].Actor != "bob" || events[0].Action != model.TriageSnoozed {
		t.Errorf("newest event = %+v", events[0])
	}
	if events[1].Actor != "alice" || events[1].Hostname != "host-a" {
		t.Errorf("older event = %+v", events[1])
	}
}
