// Package rpmver implements RPM version comparison (epoch:version-release, "EVR")
// following the same algorithm as librpm's rpmvercmp / rpmVersionCompare. It is
// the Red Hat–family counterpart to the debver package used for Debian/Ubuntu.
//
// The rules (from librpm):
//   - An EVR is epoch:version-release. Missing epoch means 0. Release is
//     optional and compared only when both sides have one.
//   - version and release are each compared by rpmvercmp: walk both strings,
//     skipping any run of non-alphanumeric (and non-'~','^') separators; then
//     compare the next segment, which is either all-digit or all-alpha.
//   - Digit segments always beat alpha segments (1.0 > 1.a). Digit segments are
//     compared numerically with leading zeros stripped; longer (after strip)
//     wins. Alpha segments are compared bytewise.
//   - '~' (tilde) sorts *before* everything, even the empty string, so
//     1.0~rc1 < 1.0. '^' sorts *after* the end of a version but before a longer
//     one continues (used for post-release snapshots); 1.0^ > 1.0.
package rpmver

import "strconv"

// EVR holds a parsed epoch:version-release.
type EVR struct {
	Epoch   int
	Version string
	Release string
}

// ParseEVR parses "1:2.3.4-5.el9" / "2.3.4-5" / "2.3.4" into an EVR.
func ParseEVR(s string) EVR {
	e := EVR{}
	// epoch
	if i := indexByte(s, ':'); i >= 0 {
		if n, err := strconv.Atoi(s[:i]); err == nil {
			e.Epoch = n
		}
		s = s[i+1:]
	}
	// release (last '-')
	if i := lastIndexByte(s, '-'); i >= 0 {
		e.Version = s[:i]
		e.Release = s[i+1:]
	} else {
		e.Version = s
	}
	return e
}

// CompareEVR compares two full EVR strings. Returns -1, 0, or +1.
func CompareEVR(a, b string) int {
	ea, eb := ParseEVR(a), ParseEVR(b)
	if ea.Epoch != eb.Epoch {
		if ea.Epoch < eb.Epoch {
			return -1
		}
		return 1
	}
	if c := rpmvercmp(ea.Version, eb.Version); c != 0 {
		return c
	}
	// Release is only compared when both sides provide one (librpm behaviour):
	// a query with no release ("2.3.4") matches any release of that version.
	if ea.Release == "" || eb.Release == "" {
		return 0
	}
	return rpmvercmp(ea.Release, eb.Release)
}

// LessThanEVR reports whether a sorts before b.
func LessThanEVR(a, b string) bool { return CompareEVR(a, b) < 0 }

// rpmvercmp is a faithful port of librpm's rpmvercmp for a single version or
// release segment.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Skip separators (anything not alphanumeric and not '~' or '^').
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}

		// Tilde: sorts before everything, including empty.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// Caret: sorts after the end of a version, but before a continuation.
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if !aCaret { // a ended, b has '^' -> a is older (b is newer snapshot)
				if i >= len(a) {
					return -1
				}
				return 1
			}
			if !bCaret {
				if j >= len(b) {
					return 1
				}
				return -1
			}
			i++
			j++
			continue
		}

		// If either string is exhausted here, the longer one wins.
		if i >= len(a) || j >= len(b) {
			break
		}

		// Compare the next alnum segment; it is either all digits or all alpha.
		startI, startJ := i, j
		isNum := isDigit(a[i])
		if isNum {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlphaByte(a[i]) {
				i++
			}
			for j < len(b) && isAlphaByte(b[j]) {
				j++
			}
		}
		segA := a[startI:i]
		segB := b[startJ:j]

		// b's segment is empty => the types differ at this position.
		if segB == "" {
			if isNum {
				return 1 // numeric > alpha (b had an alpha segment)
			}
			return -1
		}
		// Type mismatch: numeric always beats alpha.
		if isNum && !isDigit(segB[0]) {
			return 1
		}
		if !isNum && isDigit(segB[0]) {
			return -1
		}

		if isNum {
			// Strip leading zeros, then longer number wins, else lexical.
			segA = stripLeadingZeros(segA)
			segB = stripLeadingZeros(segB)
			if len(segA) != len(segB) {
				if len(segA) < len(segB) {
					return -1
				}
				return 1
			}
		}
		if c := cmpStr(segA, segB); c != 0 {
			return c
		}
	}

	// All compared segments equal; whichever still has characters is newer.
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

func stripLeadingZeros(s string) string {
	k := 0
	for k < len(s)-1 && s[k] == '0' {
		k++
	}
	return s[k:]
}

func cmpStr(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isAlphaByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isAlnum(c byte) bool { return isDigit(c) || isAlphaByte(c) }

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
