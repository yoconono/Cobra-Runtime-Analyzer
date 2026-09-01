// Package debver implements Debian package version comparison, matching the
// algorithm used by dpkg (verrevcmp). This is the core of accurate matching:
// vulnerability status is decided by comparing the installed Debian version
// against the version in which Debian fixed the issue, so the comparison must
// agree with dpkg exactly (including epochs and the '~' pre-release rule).
package debver

import "strings"

// Compare returns -1, 0, or 1 as version a is less than, equal to, or greater
// than version b, using Debian version ordering.
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)

	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// split parses "[epoch:]upstream[-revision]".
func split(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		// leading digits form the epoch; anything else means epoch 0.
		e := 0
		valid := i > 0
		for k := 0; k < i; k++ {
			if v[k] < '0' || v[k] > '9' {
				valid = false
				break
			}
			e = e*10 + int(v[k]-'0')
		}
		if valid {
			epoch = e
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream = v[:i]
		revision = v[i+1:]
	} else {
		upstream = v
		revision = ""
	}
	return epoch, upstream, revision
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// order maps a character to its sort weight. '~' sorts before everything
// (including end-of-string), letters sort before other punctuation.
func order(c byte) int {
	switch {
	case isDigit(c):
		return 0 // digits are handled in a separate numeric pass
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

// verrevcmp compares two version segments (upstream or revision) the way dpkg does.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0

		// Compare the non-digit run, char by char, using order().
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			var ac, bc int
			if i < len(a) {
				ac = order(a[i])
			} else {
				ac = order(0)
			}
			if j < len(b) {
				bc = order(b[j])
			} else {
				bc = order(0)
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}

		// Skip leading zeros so numbers compare by magnitude.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}

		// Compare the digit run.
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1 // a has more digits -> larger number
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
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

// LessThan reports whether a is strictly older than b.
func LessThan(a, b string) bool { return Compare(a, b) < 0 }
