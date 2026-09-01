package debver

import (
	"os/exec"
	"testing"
)

func TestCompareTable(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"2.0", "1.9", 1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-10", "1.0-9", 1}, // numeric, not lexical
		{"1:0", "2.0", 1},      // epoch wins
		{"1.0", "1:0", -1},
		{"1.0~rc1", "1.0", -1},      // ~ is pre-release
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~~", "1.0~", -1},       // more ~ is older
		{"1.0", "1.0~", 1},
		{"1.0a", "1.0", 1},          // letters sort after end-of-string
		{"3.0.11-1~deb12u1", "3.0.12-1", -1}, // typical upstream vs distro
		// The key backport case: a Debian point release IS the fix, even though
		// its upstream number looks older than a later upstream release.
		{"3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
		{"1.2.3-4+deb12u1", "1.2.3-4", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestAgainstDpkg cross-checks our implementation against the real dpkg on a
// wide range of pairs. Skips automatically where dpkg is unavailable.
func TestAgainstDpkg(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg not available")
	}
	versions := []string{
		"0", "1", "1.0", "1.0.0", "1.0-1", "1.0-2", "1.0-10", "1.1",
		"2:1.0", "1:1.0", "1.0~rc1", "1.0~rc2", "1.0~~", "1.0~", "1.0a",
		"3.0.11-1", "3.0.11-1~deb12u1", "3.0.11-1~deb12u2", "3.0.12-1",
		"1.2.3-4", "1.2.3-4+deb12u1", "2.38-1", "2.38+dfsg-1", "9.8p1-1",
		"0:0", "1.0+really1.1", "1.0+really1.0",
	}
	for _, a := range versions {
		for _, b := range versions {
			got := Compare(a, b)
			want := dpkgCompare(t, a, b)
			if got != want {
				t.Errorf("mismatch Compare(%q,%q)=%d dpkg=%d", a, b, got, want)
			}
		}
	}
}

func dpkgCompare(t *testing.T, a, b string) int {
	t.Helper()
	if run(a, "lt", b) {
		return -1
	}
	if run(a, "gt", b) {
		return 1
	}
	return 0
}

func run(a, op, b string) bool {
	return exec.Command("dpkg", "--compare-versions", a, op, b).Run() == nil
}
