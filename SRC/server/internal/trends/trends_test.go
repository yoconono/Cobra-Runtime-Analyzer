package trends

import (
	"testing"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

func day(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

func TestSeriesBucketsOpenByDay(t *testing.T) {
	now := day("2026-01-10")
	lcs := []model.FindingLifecycle{
		// Open the whole window (first seen before, never resolved).
		{CVE: "CVE-A", CVSSSeverity: "CRITICAL", FirstSeen: day("2026-01-01")},
		// Appeared mid-window and resolved before the end.
		{CVE: "CVE-B", CVSSSeverity: "HIGH", FirstSeen: day("2026-01-05"), ResolvedAt: day("2026-01-08")},
	}
	s := Series(lcs, 10, now)
	if len(s) != 10 {
		t.Fatalf("want 10 days, got %d", len(s))
	}
	// Day index: s[0]=Jan-01 ... s[9]=Jan-10.
	// Jan-04: only CVE-A open.
	if s[3].Total != 1 || s[3].Counts["CRITICAL"] != 1 {
		t.Errorf("Jan-04 expected 1 critical, got %+v", s[3])
	}
	// Jan-06: both open (CVE-B appeared Jan-05, resolves Jan-08).
	if s[5].Total != 2 || s[5].Counts["HIGH"] != 1 {
		t.Errorf("Jan-06 expected A+B open, got %+v", s[5])
	}
	// Jan-09: CVE-B resolved on Jan-08, so only A remains.
	if s[8].Total != 1 || s[8].Counts["HIGH"] != 0 {
		t.Errorf("Jan-09 expected only A open, got %+v", s[8])
	}
}

func TestSummaryCountsAppearedAndResolved(t *testing.T) {
	now := day("2026-01-10")
	lcs := []model.FindingLifecycle{
		{CVE: "CVE-A", CVSSSeverity: "CRITICAL", FirstSeen: day("2026-01-09"), Running: true}, // open, appeared in last 7d
		{CVE: "CVE-B", CVSSSeverity: "LOW", FirstSeen: day("2025-12-01")},                     // open, old
		{CVE: "CVE-C", CVSSSeverity: "HIGH", FirstSeen: day("2025-12-20"), ResolvedAt: day("2026-01-06")}, // resolved 4d ago
	}
	s := Summary(lcs, now)
	if s.OpenTotal != 2 || s.OpenRunning != 1 {
		t.Errorf("open total/running wrong: %+v", s)
	}
	if s.OpenBySeverity["CRITICAL"] != 1 || s.OpenBySeverity["LOW"] != 1 {
		t.Errorf("open by severity wrong: %+v", s.OpenBySeverity)
	}
	if s.Appeared7d != 1 {
		t.Errorf("appeared7d expected 1, got %d", s.Appeared7d)
	}
	if s.Resolved7d != 1 || s.Resolved30d != 1 {
		t.Errorf("resolved windows wrong: %+v", s)
	}
}

func TestActivityNewestFirst(t *testing.T) {
	now := day("2026-01-10")
	_ = now
	lcs := []model.FindingLifecycle{
		{CVE: "CVE-A", FirstSeen: day("2026-01-01"), ResolvedAt: day("2026-01-09")},
		{CVE: "CVE-B", FirstSeen: day("2026-01-05")},
	}
	ev := Activity(lcs, 10)
	if len(ev) != 3 { // A appeared, A resolved, B appeared
		t.Fatalf("expected 3 events, got %d", len(ev))
	}
	if ev[0].Kind != "resolved" || ev[0].CVE != "CVE-A" {
		t.Errorf("newest event should be A resolved, got %+v", ev[0])
	}
}
