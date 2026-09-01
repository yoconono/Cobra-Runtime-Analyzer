// Package trends derives history views from finding lifecycles: a daily
// open-findings time series (by severity), summary stats, and an activity feed.
// All functions are pure so they can be unit-tested and shared by both stores.
package trends

import (
	"sort"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Severities in display order (worst first).
var Severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// Day is the count of open findings at the end of one calendar day, by severity.
type Day struct {
	Date   time.Time
	Counts map[string]int // severity -> open count
	Total  int
}

// Series returns one Day per calendar day for the last `days` days ending on
// `now` (UTC). A finding is "open at end of day D" when it was first seen on or
// before D and not yet resolved as of the end of D.
func Series(lcs []model.FindingLifecycle, days int, now time.Time) []Day {
	now = now.UTC()
	out := make([]Day, 0, days)
	for i := days - 1; i >= 0; i-- {
		day := dayStart(now.AddDate(0, 0, -i))
		end := day.AddDate(0, 0, 1) // exclusive end of day
		d := Day{Date: day, Counts: map[string]int{}}
		for _, l := range lcs {
			if !l.FirstSeen.Before(end) {
				continue // first seen after this day
			}
			if !l.ResolvedAt.IsZero() && !l.ResolvedAt.After(end) {
				continue // resolved on or before end of this day
			}
			d.Counts[norm(l.CVSSSeverity)]++
			d.Total++
		}
		out = append(out, d)
	}
	return out
}

// Stats summarizes current and recent lifecycle activity.
type Stats struct {
	OpenTotal      int
	OpenBySeverity map[string]int
	OpenRunning    int
	Appeared7d     int
	Resolved7d     int
	Resolved30d    int
}

func Summary(lcs []model.FindingLifecycle, now time.Time) Stats {
	now = now.UTC()
	d7 := now.AddDate(0, 0, -7)
	d30 := now.AddDate(0, 0, -30)
	s := Stats{OpenBySeverity: map[string]int{}}
	for _, l := range lcs {
		if l.FirstSeen.After(d7) {
			s.Appeared7d++
		}
		if l.ResolvedAt.IsZero() {
			s.OpenTotal++
			s.OpenBySeverity[norm(l.CVSSSeverity)]++
			if l.Running {
				s.OpenRunning++
			}
		} else {
			if l.ResolvedAt.After(d7) {
				s.Resolved7d++
			}
			if l.ResolvedAt.After(d30) {
				s.Resolved30d++
			}
		}
	}
	return s
}

// Event is one lifecycle transition (a finding appearing or being resolved).
type Event struct {
	When         time.Time
	Kind         string // "appeared" | "resolved"
	Hostname     string
	AgentID      string
	CVE          string
	SourcePackage string
	CVSSSeverity string
}

// Activity returns the most recent lifecycle events, newest first.
func Activity(lcs []model.FindingLifecycle, limit int) []Event {
	var ev []Event
	for _, l := range lcs {
		ev = append(ev, Event{
			When: l.FirstSeen, Kind: "appeared", Hostname: l.Hostname, AgentID: l.AgentID,
			CVE: l.CVE, SourcePackage: l.SourcePackage, CVSSSeverity: norm(l.CVSSSeverity),
		})
		if !l.ResolvedAt.IsZero() {
			ev = append(ev, Event{
				When: l.ResolvedAt, Kind: "resolved", Hostname: l.Hostname, AgentID: l.AgentID,
				CVE: l.CVE, SourcePackage: l.SourcePackage, CVSSSeverity: norm(l.CVSSSeverity),
			})
		}
	}
	sort.Slice(ev, func(i, j int) bool { return ev[i].When.After(ev[j].When) })
	if limit > 0 && len(ev) > limit {
		ev = ev[:limit]
	}
	return ev
}

func dayStart(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func norm(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return sev
	default:
		return "UNKNOWN"
	}
}
