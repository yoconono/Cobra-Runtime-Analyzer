package notify

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/yourorg/cve-fleet/server/internal/cvss"
	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Rule matches alerts and routes them to one or more named channels. Rules are
// evaluated in order; the first matching rule wins unless it sets Continue.
type Rule struct {
	MinSeverity string   `json:"min_severity"` // e.g. "CRITICAL"; empty = any
	Ecosystems  []string `json:"ecosystems"`   // e.g. ["Go","PyPI","npm","deb"]; empty = any
	Running     *bool    `json:"running"`      // nil = any
	Kinds       []string `json:"kinds"`        // e.g. ["new"] or ["resolved"]; empty = any
	KEV         *bool    `json:"kev"`          // nil = any; true = only known-exploited
	MinEPSS     float64  `json:"min_epss"`     // 0 = any; else require EPSS >= this
	Channels    []string `json:"channels"`     // target channel names
	Continue    bool     `json:"continue"`     // keep evaluating later rules
}

func (r Rule) match(a Alert) bool {
	if r.MinSeverity != "" && cvss.SeverityRank(a.Severity) < cvss.SeverityRank(strings.ToUpper(r.MinSeverity)) {
		return false
	}
	if len(r.Ecosystems) > 0 && !containsFold(r.Ecosystems, ecoOrDeb(a.Ecosystem)) {
		return false
	}
	if r.Running != nil && *r.Running != a.Running {
		return false
	}
	if len(r.Kinds) > 0 && !containsFold(r.Kinds, a.Kind) {
		return false
	}
	if r.KEV != nil && *r.KEV != a.KEVListed {
		return false
	}
	if r.MinEPSS > 0 && a.EPSSScore < r.MinEPSS {
		return false
	}
	return true
}

// Router is the rule-based Engine.
type Router struct {
	Rules        []Rule
	Channels     map[string]Notifier
	DashboardURL string
	OnResolved   bool
	Log          *log.Logger
}

func (rt *Router) Handle(agentID, hostname string, appeared, resolved []model.Finding) {
	if rt == nil || len(rt.Rules) == 0 {
		return
	}
	var alerts []Alert
	alerts = append(alerts, buildAlerts(agentID, hostname, rt.DashboardURL, appeared, KindNew)...)
	if rt.OnResolved {
		alerts = append(alerts, buildAlerts(agentID, hostname, rt.DashboardURL, resolved, KindResolved)...)
	}

	byChan := map[string][]Alert{}
	for _, a := range alerts {
		for _, rule := range rt.Rules {
			if !rule.match(a) {
				continue
			}
			for _, ch := range rule.Channels {
				byChan[ch] = append(byChan[ch], a)
			}
			if !rule.Continue {
				break
			}
		}
	}
	for ch, batch := range byChan {
		if n := rt.Channels[ch]; n != nil && len(batch) > 0 {
			dispatch(n, batch, rt.Log)
		}
	}
}

// ---- Config file ----

type channelSpec struct {
	Type string   `json:"type"` // "webhook" | "smtp" | "log"
	URL  string   `json:"url"`
	Host string   `json:"host"`
	Port string   `json:"port"`
	From string   `json:"from"`
	To   []string `json:"to"`
	User string   `json:"user"`
	Pass string   `json:"pass"`
}

type routeConfig struct {
	Channels     map[string]channelSpec `json:"channels"`
	Rules        []Rule                 `json:"rules"`
	OnResolved   *bool                  `json:"on_resolved"`
	DashboardURL string                 `json:"dashboard_url"`
}

// LoadRouter reads a JSON routing config and builds a Router. dashOverride, if
// non-empty, wins over the file's dashboard_url.
func LoadRouter(path, dashOverride string, logger *log.Logger) (*Router, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg routeConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse routing config: %w", err)
	}
	if len(cfg.Rules) == 0 {
		return nil, fmt.Errorf("routing config has no rules")
	}

	channels := map[string]Notifier{}
	for name, spec := range cfg.Channels {
		switch strings.ToLower(spec.Type) {
		case "webhook":
			if spec.URL == "" {
				return nil, fmt.Errorf("channel %q: webhook needs a url", name)
			}
			channels[name] = Webhook{URL: spec.URL}
		case "smtp":
			if spec.Host == "" || spec.From == "" || len(spec.To) == 0 {
				return nil, fmt.Errorf("channel %q: smtp needs host, from, to", name)
			}
			port := spec.Port
			if port == "" {
				port = "587"
			}
			channels[name] = SMTP{Host: spec.Host, Port: port, From: spec.From, To: spec.To, User: spec.User, Pass: spec.Pass}
		case "log", "":
			channels[name] = LogNotifier{Log: logger}
		default:
			return nil, fmt.Errorf("channel %q: unknown type %q", name, spec.Type)
		}
	}

	// Validate that every rule references a defined channel.
	for i, r := range cfg.Rules {
		if len(r.Channels) == 0 {
			return nil, fmt.Errorf("rule %d has no channels", i)
		}
		for _, ch := range r.Channels {
			if _, ok := channels[ch]; !ok {
				return nil, fmt.Errorf("rule %d references undefined channel %q", i, ch)
			}
		}
	}

	onResolved := true
	if cfg.OnResolved != nil {
		onResolved = *cfg.OnResolved
	}
	dash := cfg.DashboardURL
	if dashOverride != "" {
		dash = dashOverride
	}
	return &Router{
		Rules:        cfg.Rules,
		Channels:     channels,
		DashboardURL: dash,
		OnResolved:   onResolved,
		Log:          logger,
	}, nil
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
		// accept "debian"/"os" as aliases for the OS ecosystem token "deb"
		if v == "deb" && (strings.EqualFold(s, "debian") || strings.EqualFold(s, "os")) {
			return true
		}
	}
	return false
}
