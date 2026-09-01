package cvss

import (
	"math"
	"testing"
)

func TestBaseScore(t *testing.T) {
	cases := []struct {
		vector string
		score  float64
		sev    string
	}{
		// Canonical examples with well-known scores.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5, "HIGH"},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "MEDIUM"},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1, "LOW"},
		// Scope changed raises the score.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL"},
		// v3.0 uses the same base formula.
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL"},
	}
	for _, c := range cases {
		got, sev, err := BaseScore(c.vector)
		if err != nil {
			t.Errorf("BaseScore(%q) error: %v", c.vector, err)
			continue
		}
		if math.Abs(got-c.score) > 0.05 {
			t.Errorf("BaseScore(%q)=%.1f want %.1f", c.vector, got, c.score)
		}
		if sev != c.sev {
			t.Errorf("BaseScore(%q) severity=%s want %s", c.vector, sev, c.sev)
		}
	}
}

func TestBaseScoreRejectsNonV3(t *testing.T) {
	if _, _, err := BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"); err == nil {
		t.Error("expected error for CVSS:4.0 vector")
	}
}

func TestSeverityBands(t *testing.T) {
	for _, c := range []struct {
		s   float64
		sev string
	}{{0, "NONE"}, {0.1, "LOW"}, {3.9, "LOW"}, {4.0, "MEDIUM"}, {6.9, "MEDIUM"}, {7.0, "HIGH"}, {8.9, "HIGH"}, {9.0, "CRITICAL"}, {10, "CRITICAL"}} {
		if got := Severity(c.s); got != c.sev {
			t.Errorf("Severity(%.1f)=%s want %s", c.s, got, c.sev)
		}
	}
}
