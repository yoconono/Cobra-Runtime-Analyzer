// Package notify raises alerts when findings appear or resolve. The report path
// hands newly-opened and newly-resolved findings to an Engine, which filters and
// delivers them to channels (webhook / SMTP / log). Two engines are provided: a
// flag-configured Dispatcher (single channel set + one policy) and a file-driven
// Router (rule-based routing to named channels). Stdlib-only.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/cvss"
	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Kind distinguishes a new finding from a resolved ("all clear") one.
const (
	KindNew      = "new"
	KindResolved = "resolved"
)

// Alert is one notification-worthy finding transition.
type Alert struct {
	Kind             string  `json:"kind"` // "new" | "resolved"
	AgentID          string  `json:"agent_id"`
	Hostname         string  `json:"hostname"`
	CVE              string  `json:"cve"`
	Ecosystem        string  `json:"ecosystem"` // "" = Debian/OS
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvss_score"`
	KEVListed        bool    `json:"kev_listed"`
	EPSSScore        float64 `json:"epss_score"`
	Running          bool    `json:"running"`
	URL              string  `json:"url,omitempty"`
}

// Engine consumes the reconcile diff and delivers alerts. Implementations must
// not block the caller (dispatch happens off the request path).
type Engine interface {
	Handle(agentID, hostname string, appeared, resolved []model.Finding)
}

// Policy decides which findings warrant an alert.
type Policy struct {
	MinSeverity string // NONE|LOW|MEDIUM|HIGH|CRITICAL (default HIGH)
	RunningOnly bool   // only alert on findings backing a live process
}

func (p Policy) min() string {
	if p.MinSeverity == "" {
		return "HIGH"
	}
	return p.MinSeverity
}

// Match applies severity and running filters (used for new findings).
func (p Policy) Match(severity string, running bool) bool {
	if p.RunningOnly && !running {
		return false
	}
	return cvss.SeverityRank(severity) >= cvss.SeverityRank(p.min())
}

// MatchSeverity applies only the severity filter (used for resolved notices,
// where "running" no longer applies).
func (p Policy) MatchSeverity(severity string) bool {
	return cvss.SeverityRank(severity) >= cvss.SeverityRank(p.min())
}

// buildAlerts constructs Alerts (unfiltered) from findings of a given kind.
func buildAlerts(agentID, hostname, dashURL string, fs []model.Finding, kind string) []Alert {
	out := make([]Alert, 0, len(fs))
	for _, f := range fs {
		sev := f.CVSSSeverity
		if sev == "" {
			sev = "UNKNOWN"
		}
		a := Alert{
			Kind: kind, AgentID: agentID, Hostname: hostname, CVE: f.CVE, Ecosystem: f.Ecosystem,
			Package: f.SourcePackage, InstalledVersion: f.InstalledVersion, FixedVersion: f.FixedVersion,
			Severity: sev, CVSSScore: f.CVSSScore, KEVListed: f.KEVListed, EPSSScore: f.EPSSScore, Running: f.Running,
		}
		if dashURL != "" {
			a.URL = strings.TrimRight(dashURL, "/") + "/cves/" + f.CVE
		}
		out = append(out, a)
	}
	return out
}

// dispatch delivers a batch asynchronously with a timeout.
func dispatch(n Notifier, alerts []Alert, logger *log.Logger) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := n.Notify(ctx, alerts); err != nil && logger != nil {
			logger.Printf("alert: %s delivery failed: %v", n.Name(), err)
		}
	}()
}

// Dispatcher is the flag-configured Engine: one channel set, one policy.
type Dispatcher struct {
	Policy       Policy
	Notifier     Notifier
	DashboardURL string
	OnResolved   bool // emit "all clear" notices for resolved findings
	Log          *log.Logger
}

func (d *Dispatcher) Handle(agentID, hostname string, appeared, resolved []model.Finding) {
	if d == nil || d.Notifier == nil {
		return
	}
	var batch []Alert
	for _, a := range buildAlerts(agentID, hostname, d.DashboardURL, appeared, KindNew) {
		// Known-exploited findings always alert, even below the severity floor.
		if a.KEVListed || d.Policy.Match(a.Severity, a.Running) {
			batch = append(batch, a)
		}
	}
	if d.OnResolved {
		for _, a := range buildAlerts(agentID, hostname, d.DashboardURL, resolved, KindResolved) {
			if d.Policy.MatchSeverity(a.Severity) {
				batch = append(batch, a)
			}
		}
	}
	if len(batch) > 0 {
		dispatch(d.Notifier, batch, d.Log)
	}
}

// ---- Notifiers ----

// Notifier delivers a batch of alerts.
type Notifier interface {
	Notify(ctx context.Context, alerts []Alert) error
	Name() string
}

// LogNotifier writes alerts to the server log (default fallback).
type LogNotifier struct{ Log *log.Logger }

func (l LogNotifier) Name() string { return "log" }
func (l LogNotifier) Notify(_ context.Context, alerts []Alert) error {
	for _, a := range alerts {
		tag := "ALERT"
		if a.Kind == KindResolved {
			tag = "RESOLVED"
		}
		l.Log.Printf("%s %s %s%s (%s/%s %s)%s fixed=%s", tag, a.Severity, a.CVE, kevTag(a), ecoOrDeb(a.Ecosystem), a.Package, a.InstalledVersion, running(a.Running), orNone(a.FixedVersion))
	}
	return nil
}

// Webhook POSTs a JSON payload per batch.
type Webhook struct {
	URL    string
	Client *http.Client
}

func (w Webhook) Name() string { return "webhook" }
func (w Webhook) Notify(ctx context.Context, alerts []Alert) error {
	newN, resN := counts(alerts)
	payload := map[string]any{
		"source":         "cve-fleet",
		"count":          len(alerts),
		"new_count":      newN,
		"resolved_count": resN,
		"host":           alerts[0].Hostname,
		"alerts":         alerts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	c := w.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// SMTP sends a plain-text summary email (STARTTLS via net/smtp.SendMail).
type SMTP struct {
	Host, Port string
	From       string
	To         []string
	User, Pass string
}

func (s SMTP) Name() string { return "smtp" }
func (s SMTP) Notify(_ context.Context, alerts []Alert) error {
	newN, resN := counts(alerts)
	var b strings.Builder
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(s.To, ", "))
	fmt.Fprintf(&b, "From: %s\r\n", s.From)
	fmt.Fprintf(&b, "Subject: [CVE Fleet] %d new, %d resolved on %s\r\n\r\n", newN, resN, alerts[0].Hostname)
	for _, a := range alerts {
		tag := "NEW"
		if a.Kind == KindResolved {
			tag = "RESOLVED"
		}
		fmt.Fprintf(&b, "%-8s %s  %s  %s/%s %s -> fixed %s%s\n",
			tag, a.Severity, a.CVE, ecoOrDeb(a.Ecosystem), a.Package, a.InstalledVersion, orNone(a.FixedVersion), running(a.Running))
		if a.URL != "" {
			fmt.Fprintf(&b, "         %s\n", a.URL)
		}
	}
	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Pass, s.Host)
	}
	return smtp.SendMail(s.Host+":"+s.Port, auth, s.From, s.To, []byte(b.String()))
}

// Multi dispatches to several notifiers, collecting errors.
type Multi []Notifier

func (m Multi) Name() string { return "multi" }
func (m Multi) Notify(ctx context.Context, alerts []Alert) error {
	var errs []string
	for _, n := range m {
		if err := n.Notify(ctx, alerts); err != nil {
			errs = append(errs, n.Name()+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func counts(alerts []Alert) (newN, resN int) {
	for _, a := range alerts {
		if a.Kind == KindResolved {
			resN++
		} else {
			newN++
		}
	}
	return
}

func kevTag(a Alert) string {
	if a.KEVListed {
		return " [KEV]"
	}
	return ""
}

func ecoOrDeb(e string) string {
	if e == "" {
		return "deb"
	}
	return e
}
func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
func running(b bool) string {
	if b {
		return " [running]"
	}
	return ""
}
