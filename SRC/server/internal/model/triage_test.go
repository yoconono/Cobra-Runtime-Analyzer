package model

import (
	"testing"
	"time"
)

func TestEffectiveTriage(t *testing.T) {
	now := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		state string
		until time.Time
		want  string
	}{
		{TriageMuted, time.Time{}, TriageMuted},
		{TriageAcknowledged, time.Time{}, TriageAcknowledged},
		{TriageSnoozed, future, TriageSnoozed},   // not yet expired
		{TriageSnoozed, past, TriageActive},      // expired -> active
		{TriageRiskAccepted, future, TriageRiskAccepted},
		{TriageRiskAccepted, past, TriageActive}, // expired -> re-review
		{TriageRiskAccepted, time.Time{}, TriageRiskAccepted}, // permanent accept
		{"", time.Time{}, TriageActive},
	}
	for _, c := range cases {
		if got := EffectiveTriage(c.state, c.until, now); got != c.want {
			t.Errorf("EffectiveTriage(%q, until=%v)=%q want %q", c.state, c.until, got, c.want)
		}
	}
}

func TestIsSuppressed(t *testing.T) {
	for _, s := range []string{TriageMuted, TriageSnoozed, TriageRiskAccepted} {
		if !IsSuppressed(s) {
			t.Errorf("%s should be suppressed", s)
		}
	}
	for _, s := range []string{TriageActive, TriageAcknowledged, ""} {
		if IsSuppressed(s) {
			t.Errorf("%s should NOT be suppressed", s)
		}
	}
}
