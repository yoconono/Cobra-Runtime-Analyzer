package notify

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// capture is a Notifier that records the alerts it receives.
type capture struct {
	mu     sync.Mutex
	name   string
	alerts []Alert
}

func (c *capture) Name() string { return c.name }
func (c *capture) Notify(_ context.Context, a []Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a...)
	return nil
}
func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.alerts)
}

func TestRuleMatch(t *testing.T) {
	yes := true
	r := Rule{MinSeverity: "HIGH", Ecosystems: []string{"Go", "deb"}, Running: &yes, Kinds: []string{"new"}}
	if !r.match(Alert{Severity: "CRITICAL", Ecosystem: "Go", Running: true, Kind: "new"}) {
		t.Error("should match")
	}
	if r.match(Alert{Severity: "MEDIUM", Ecosystem: "Go", Running: true, Kind: "new"}) {
		t.Error("severity below min should not match")
	}
	if r.match(Alert{Severity: "HIGH", Ecosystem: "npm", Running: true, Kind: "new"}) {
		t.Error("ecosystem not in list should not match")
	}
	if r.match(Alert{Severity: "HIGH", Ecosystem: "Go", Running: false, Kind: "new"}) {
		t.Error("running mismatch should not match")
	}
	if r.match(Alert{Severity: "HIGH", Ecosystem: "Go", Running: true, Kind: "resolved"}) {
		t.Error("kind mismatch should not match")
	}
	// "deb" alias: empty ecosystem should match a "debian" list entry.
	rd := Rule{Ecosystems: []string{"debian"}}
	if !rd.match(Alert{Ecosystem: "", Severity: "LOW"}) {
		t.Error("empty ecosystem should match 'debian' alias")
	}
}

func TestRouterFirstMatchWins(t *testing.T) {
	pager := &capture{name: "pager"}
	slack := &capture{name: "slack"}
	rt := &Router{
		Channels: map[string]Notifier{"pager": pager, "slack": slack},
		Rules: []Rule{
			{MinSeverity: "CRITICAL", Channels: []string{"pager"}},
			{MinSeverity: "HIGH", Channels: []string{"slack"}},
		},
		OnResolved: true,
		Log:        log.New(os.Stderr, "", 0),
	}
	appeared := []model.Finding{
		{CVE: "CVE-C", CVSSSeverity: "CRITICAL"}, // -> pager (first match)
		{CVE: "CVE-H", CVSSSeverity: "HIGH"},     // -> slack
		{CVE: "CVE-M", CVSSSeverity: "MEDIUM"},   // -> nobody
	}
	rt.Handle("a1", "host", appeared, nil)

	if !waitFor(func() bool { return pager.count() == 1 && slack.count() == 1 }) {
		t.Fatalf("routing wrong: pager=%d slack=%d", pager.count(), slack.count())
	}
}

func TestLoadRouter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	cfg := `{
      "channels": {
        "hook": {"type":"webhook","url":"https://example.com/h"},
        "mail": {"type":"smtp","host":"smtp.example.com","from":"a@b.c","to":["x@y.z"]}
      },
      "rules": [
        {"min_severity":"CRITICAL","channels":["hook","mail"]},
        {"min_severity":"HIGH","channels":["hook"]}
      ],
      "on_resolved": false,
      "dashboard_url": "https://dash"
    }`
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, err := LoadRouter(path, "", log.New(os.Stderr, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.Rules) != 2 || len(rt.Channels) != 2 || rt.OnResolved != false || rt.DashboardURL != "https://dash" {
		t.Errorf("router loaded wrong: %+v", rt)
	}

	// Undefined channel reference must error.
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"channels":{},"rules":[{"channels":["nope"]}]}`), 0o644)
	if _, err := LoadRouter(bad, "", log.New(os.Stderr, "", 0)); err == nil {
		t.Error("expected error for undefined channel reference")
	}
}
