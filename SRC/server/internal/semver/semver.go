// Package semver provides a small, dependency-free semantic-version comparison
// used to evaluate OSV affected ranges (introduced/fixed). It handles the common
// MAJOR.MINOR.PATCH[-prerelease] form used by npm and Go; build metadata is
// ignored. It is not a full PEP 440 implementation, but OSV PyPI records usually
// carry explicit affected `versions` lists, which the matcher checks directly.
package semver

import (
	"strconv"
	"strings"
)

// Compare returns -1, 0, or 1 as a is less than, equal to, or greater than b.
// A leading 'v' is tolerated. Unparseable numeric parts compare as 0.
func Compare(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")

	aCore, aPre := splitPre(a)
	bCore, bPre := splitPre(b)

	if c := compareCore(aCore, bCore); c != 0 {
		return c
	}
	// A version with a pre-release is lower than the same without one.
	switch {
	case aPre == "" && bPre == "":
		return 0
	case aPre == "":
		return 1
	case bPre == "":
		return -1
	default:
		return comparePre(aPre, bPre)
	}
}

func splitPre(v string) (core, pre string) {
	if i := strings.IndexByte(v, '+'); i >= 0 { // drop build metadata
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func compareCore(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if c := cmpInt(at(as, i), at(bs, i)); c != 0 {
			return c
		}
	}
	return 0
}

func comparePre(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, aok := at(as, i), i < len(as)
		bi, bok := at(bs, i), i < len(bs)
		if !aok {
			return -1 // fewer identifiers => lower precedence
		}
		if !bok {
			return 1
		}
		an, aNum := strconv.Atoi(ai)
		bn, bNum := strconv.Atoi(bi)
		switch {
		case aNum == nil && bNum == nil: // both numeric
			if an != bn {
				return sign(an - bn)
			}
		case aNum == nil: // numeric < alphanumeric
			return -1
		case bNum == nil:
			return 1
		default:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		}
	}
	return 0
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

func cmpInt(a, b string) int {
	ai, _ := strconv.Atoi(a)
	bi, _ := strconv.Atoi(b)
	return sign(ai - bi)
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}

// InRange reports whether version v is within [introduced, fixed): v >=
// introduced and (fixed == "" or v < fixed). An introduced value of "0" or ""
// means "from the beginning".
func InRange(v, introduced, fixed string) bool {
	if introduced != "" && introduced != "0" && Compare(v, introduced) < 0 {
		return false
	}
	if fixed != "" && Compare(v, fixed) >= 0 {
		return false
	}
	return true
}
