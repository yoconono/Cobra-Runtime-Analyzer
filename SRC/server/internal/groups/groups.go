// Package groups computes per-tag rollups over agent summaries: given a tag key
// (e.g. "env"), it buckets hosts by that tag's value and aggregates their finding
// counts. Pure and dependency-free so it's easy to test.
package groups

import (
	"sort"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Untagged is the bucket for hosts missing the grouping key.
const Untagged = "(untagged)"

// Rollup is one group's aggregated posture.
type Rollup struct {
	Value        string
	Hosts        int
	Findings     int
	Running      int
	KEV          int
	SeverityCounts map[string]int
}

// By buckets summaries by the value of tag `key` and aggregates counts. Groups
// are sorted by risk: most critical, then high, then total findings, then name.
func By(summaries []model.AgentSummary, key string) []Rollup {
	idx := map[string]*Rollup{}
	order := []string{}
	for _, s := range summaries {
		val, ok := s.EffectiveTags()[key]
		if !ok || val == "" {
			val = Untagged
		}
		r := idx[val]
		if r == nil {
			r = &Rollup{Value: val, SeverityCounts: map[string]int{}}
			idx[val] = r
			order = append(order, val)
		}
		r.Hosts++
		r.Findings += s.FindingCount
		r.Running += s.RunningCount
		r.KEV += s.KEVCount
		for sev, n := range s.SeverityCounts {
			r.SeverityCounts[sev] += n
		}
	}
	out := make([]Rollup, 0, len(order))
	for _, v := range order {
		out = append(out, *idx[v])
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].SeverityCounts["CRITICAL"], out[j].SeverityCounts["CRITICAL"]; a != b {
			return a > b
		}
		if a, b := out[i].SeverityCounts["HIGH"], out[j].SeverityCounts["HIGH"]; a != b {
			return a > b
		}
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		// Untagged sinks to the bottom on ties.
		if (out[i].Value == Untagged) != (out[j].Value == Untagged) {
			return out[j].Value == Untagged
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// Keys returns the distinct tag keys present across summaries, sorted.
func Keys(summaries []model.AgentSummary) []string {
	set := map[string]bool{}
	for _, s := range summaries {
		for k := range s.EffectiveTags() {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Filter returns summaries whose effective tag `key` equals `value`.
func Filter(summaries []model.AgentSummary, key, value string) []model.AgentSummary {
	var out []model.AgentSummary
	for _, s := range summaries {
		if s.EffectiveTags()[key] == value {
			out = append(out, s)
		}
	}
	return out
}
