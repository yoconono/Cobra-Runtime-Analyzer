package semver

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical
		{"2.0.0", "1.9.9", 1},
		{"v1.2.3", "1.2.3", 0}, // leading v tolerated
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0+build1", "1.0.0+build2", 0}, // build metadata ignored
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestInRange(t *testing.T) {
	if !InRange("1.10.9", "0", "1.11.0") {
		t.Error("1.10.9 should be in [0,1.11.0)")
	}
	if InRange("1.11.0", "0", "1.11.0") {
		t.Error("1.11.0 should NOT be in [0,1.11.0) (fixed is exclusive)")
	}
	if !InRange("2.5.0", "2.0.0", "") {
		t.Error("2.5.0 should be in [2.0.0, inf)")
	}
	if InRange("1.9.0", "2.0.0", "") {
		t.Error("1.9.0 should NOT be in [2.0.0, inf)")
	}
}
