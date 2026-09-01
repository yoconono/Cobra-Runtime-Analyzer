package groups

import (
	"testing"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

func mk(host string, tags, reported map[string]string, crit, high, findings, running, kev int) model.AgentSummary {
	return model.AgentSummary{
		Agent:          model.Agent{ID: host, Hostname: host, Tags: tags, ReportedTags: reported},
		FindingCount:   findings,
		RunningCount:   running,
		KEVCount:       kev,
		SeverityCounts: map[string]int{"CRITICAL": crit, "HIGH": high},
	}
}

func TestEffectiveTagsMerge(t *testing.T) {
	a := model.Agent{
		ReportedTags: map[string]string{"env": "staging", "team": "core"},
		Tags:         map[string]string{"env": "prod"}, // operator overrides env
	}
	eff := a.EffectiveTags()
	if eff["env"] != "prod" {
		t.Errorf("operator tag should win: env=%q", eff["env"])
	}
	if eff["team"] != "core" {
		t.Errorf("reported tag should survive: team=%q", eff["team"])
	}
}

func TestByRollup(t *testing.T) {
	sums := []model.AgentSummary{
		mk("web1", map[string]string{"env": "prod"}, nil, 1, 2, 5, 3, 1),
		mk("web2", nil, map[string]string{"env": "prod"}, 0, 1, 2, 1, 0), // reported tag
		mk("db1", map[string]string{"env": "staging"}, nil, 0, 0, 1, 0, 0),
		mk("misc", nil, nil, 3, 0, 4, 2, 2), // untagged
	}
	rs := By(sums, "env")
	if len(rs) != 3 {
		t.Fatalf("want 3 groups, got %d", len(rs))
	}
	// prod: 2 hosts, findings 7, crit 1, high 3
	byval := map[string]Rollup{}
	for _, r := range rs {
		byval[r.Value] = r
	}
	prod := byval["prod"]
	if prod.Hosts != 2 || prod.Findings != 7 || prod.SeverityCounts["CRITICAL"] != 1 || prod.SeverityCounts["HIGH"] != 3 || prod.KEV != 1 {
		t.Errorf("prod rollup wrong: %+v", prod)
	}
	// untagged should sort last even though it has 3 criticals? No: sort is by
	// CRITICAL desc, so untagged (3 crit) actually sorts FIRST. Verify ordering.
	if rs[0].Value != Untagged {
		t.Errorf("expected untagged first (3 criticals), got %q", rs[0].Value)
	}
}

func TestKeysAndFilter(t *testing.T) {
	sums := []model.AgentSummary{
		mk("a", map[string]string{"env": "prod", "team": "pay"}, nil, 0, 0, 0, 0, 0),
		mk("b", map[string]string{"env": "staging"}, nil, 0, 0, 0, 0, 0),
	}
	keys := Keys(sums)
	if len(keys) != 2 || keys[0] != "env" || keys[1] != "team" {
		t.Errorf("keys wrong: %v", keys)
	}
	prod := Filter(sums, "env", "prod")
	if len(prod) != 1 || prod[0].Hostname != "a" {
		t.Errorf("filter wrong: %+v", prod)
	}
}
