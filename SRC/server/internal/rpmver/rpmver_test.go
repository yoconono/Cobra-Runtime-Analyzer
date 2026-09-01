package rpmver

import "testing"

// Cases cross-checked against `rpmdev-vercmp` / librpm's own test suite.
func TestRpmvercmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1},
		// alpha vs numeric
		{"2.0.1a", "2.0.1a", 0},
		{"2.0.1a", "2.0.1", 1},
		{"2.0.1", "2.0.1a", -1},
		// leading zeros / numeric length
		{"5.5p1", "5.5p1", 0},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"xyz10", "xyz10", 0},
		{"xyz10", "xyz10.1", -1},
		{"0.0.1", "0.0.1", 0},
		{"1.0", "1.0.0", -1}, // longer continuation is newer
		// separators are equivalent
		{"2a", "2.0", -1},
		{"1_0", "1.0", 0},
		// digit beats alpha across differing separators
		{"5.5p1", "5.6p1", -1},
		// tilde sorts before release/version
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc1", "1.0~rc1", 0},
		// caret sorts after a version
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^20240101", "1.0", 1},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); got != c.want {
			t.Errorf("rpmvercmp(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
		// antisymmetry
		if got := rpmvercmp(c.b, c.a); got != -c.want {
			t.Errorf("rpmvercmp(%q,%q)=%d want %d (antisym)", c.b, c.a, got, -c.want)
		}
	}
}

func TestCompareEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// realistic RHEL EVRs
		{"0:1.2.3-4.el9", "0:1.2.3-4.el9", 0},
		{"1.2.3-4.el9", "1.2.3-5.el9", -1},
		{"1.2.3-5.el9", "1.2.3-4.el9", 1},
		{"1.2.3-4.el9_2", "1.2.3-4.el9_1", 1},
		// epoch dominates
		{"2:1.0-1", "10:0.1-1", -1},
		{"1:1.0-1", "1.0-9", 1},
		// missing release on the query side matches any release
		{"1.2.3", "1.2.3-4.el9", 0},
		{"1.2.3-4.el9", "1.2.3", 0},
		// openssl-style
		{"1:3.0.7-27.el9", "1:3.0.7-28.el9", -1},
		{"1:3.2.2-6.el9", "1:3.0.7-28.el9", 1},
	}
	for _, c := range cases {
		if got := CompareEVR(c.a, c.b); got != c.want {
			t.Errorf("CompareEVR(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParseEVR(t *testing.T) {
	e := ParseEVR("1:3.0.7-27.el9_2")
	if e.Epoch != 1 || e.Version != "3.0.7" || e.Release != "27.el9_2" {
		t.Fatalf("ParseEVR wrong: %+v", e)
	}
	e = ParseEVR("2.3.4")
	if e.Epoch != 0 || e.Version != "2.3.4" || e.Release != "" {
		t.Fatalf("ParseEVR no-release wrong: %+v", e)
	}
}
