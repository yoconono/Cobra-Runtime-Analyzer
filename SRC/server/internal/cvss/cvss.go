// Package cvss computes CVSS v3.0/v3.1 base scores from a vector string, and
// maps scores to qualitative severity ratings. This lets us derive a numeric
// score when a source (e.g. OSV) provides only a vector, and normalize severity
// across NVD and OSV.
package cvss

import (
	"fmt"
	"math"
	"strings"
)

// Severity returns the qualitative rating for a CVSS base score (v3.x bands).
func Severity(score float64) string {
	switch {
	case score <= 0:
		return "NONE"
	case score < 4.0:
		return "LOW"
	case score < 7.0:
		return "MEDIUM"
	case score < 9.0:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// SeverityRank orders severities for sorting/counting (higher = worse).
func SeverityRank(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NONE":
		return 1
	default:
		return 0 // UNKNOWN
	}
}

// BaseScore parses a CVSS v3.0/v3.1 vector and returns the base score and
// severity. Non-v3 vectors (e.g. CVSS:4.0) return an error.
func BaseScore(vector string) (float64, string, error) {
	m, err := parse(vector)
	if err != nil {
		return 0, "UNKNOWN", err
	}

	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scopeChanged := m["S"] == "C"

	var pr float64
	if scopeChanged {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	}

	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, i, a := cia[m["C"]], cia[m["I"]], cia[m["A"]]

	if av == 0 || ac == 0 || pr == 0 || ui == 0 {
		return 0, "UNKNOWN", fmt.Errorf("cvss: missing/invalid metric in %q", vector)
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	expl := 8.22 * av * ac * pr * ui

	var score float64
	if impact <= 0 {
		score = 0
	} else if scopeChanged {
		score = roundUp(math.Min(1.08*(impact+expl), 10))
	} else {
		score = roundUp(math.Min(impact+expl, 10))
	}
	return score, Severity(score), nil
}

// parse extracts metric=value pairs from a CVSS:3.x vector.
func parse(vector string) (map[string]string, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return nil, fmt.Errorf("cvss: not a v3 vector: %q", vector)
	}
	m := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			m[k] = v
		}
	}
	for _, req := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, ok := m[req]; !ok {
			return nil, fmt.Errorf("cvss: vector missing %s: %q", req, vector)
		}
	}
	return m, nil
}

// roundUp implements the CVSS v3.1 "Roundup" function (round to 1 decimal,
// always up at the 5th decimal boundary).
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
