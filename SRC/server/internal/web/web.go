// Package web serves the operator dashboard (server-rendered HTML, no JS build).
package web

import (
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/auth"
	"github.com/yourorg/cve-fleet/server/internal/groups"
	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/store"
	"github.com/yourorg/cve-fleet/server/internal/trends"
)

type Dashboard struct {
	store   store.Store
	tmpl    *template.Template
	user    string // bootstrap/break-glass basic-auth user (only used when no users exist)
	pass    string
	version string
	signer  *auth.Signer
}

// cobraLogoSVG is the application mark: a "C" formed by a cobra (head at the top
// terminal, tapered tail at the bottom) on a dark rounded badge. Used as the
// browser favicon and the header logo.
const cobraLogoSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="Cobra">` +
	`<defs><linearGradient id="cg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#5fe6a0"/><stop offset="1" stop-color="#199f68"/></linearGradient></defs>` +
	`<rect x="2" y="2" width="60" height="60" rx="15" fill="#0f1115" stroke="#2b3441" stroke-width="2"/>` +
	`<path d="M 42.6 15.0 A 20 20 0 1 0 42.6 49.0" fill="none" stroke="url(#cg)" stroke-width="8" stroke-linecap="round"/>` +
	`<path d="M40.5 46.2 C 49 50, 55 50, 59 44 C 54 47, 48 49, 43.5 51.5 Z" fill="url(#cg)"/>` +
	`<path d="M42.6 15 c6 -3 12 -1 13 4 c1 4 -2 8 -7 8 c-4 0 -7 -2 -8 -5 z" fill="url(#cg)"/>` +
	`<circle cx="49.5" cy="19.2" r="1.5" fill="#0f1115"/>` +
	`<path d="M55.5 21 l5 -1 m-5 1 l4 3" stroke="#ff4d4d" stroke-width="1.6" fill="none" stroke-linecap="round"/>` +
	`</svg>`

const (
	sessionCookie = "cvefleet_session"
	sessionTTL    = 12 * time.Hour
)

func New(s store.Store, basicUser, basicPass string, sessionKey []byte, version string) *Dashboard {
	return &Dashboard{
		store:   s,
		tmpl:    template.Must(template.New("").Funcs(funcs).Parse(pages)),
		user:    basicUser,
		pass:    basicPass,
		version: version,
		signer:  auth.NewSigner(sessionKey),
	}
}

func (d *Dashboard) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", d.loginForm)
	mux.HandleFunc("GET /favicon.svg", d.favicon)
	mux.HandleFunc("GET /favicon.ico", d.favicon)
	mux.HandleFunc("GET /about", d.auth(d.about))
	mux.HandleFunc("POST /login", d.loginSubmit)
	mux.HandleFunc("GET /logout", d.logout)
	mux.HandleFunc("GET /{$}", d.auth(d.dashboard))
	mux.HandleFunc("GET /agents", d.auth(d.index))
	mux.HandleFunc("GET /agents/{id}", d.auth(d.agent))
	mux.HandleFunc("GET /cves", d.auth(d.cves))
	mux.HandleFunc("GET /cves/{id}", d.auth(d.cve))
	mux.HandleFunc("GET /trends", d.auth(d.trends))
	mux.HandleFunc("GET /audit", d.auth(d.audit))
	mux.HandleFunc("GET /groups", d.auth(d.groupsPage))
	mux.HandleFunc("GET /catalog", d.auth(d.catalogCVEs))
	mux.HandleFunc("GET /catalog/advisories", d.auth(d.catalogAdvisories))
	mux.HandleFunc("POST /triage", d.auth(d.triage))
	mux.HandleFunc("POST /agents/{id}/tags", d.auth(d.setTags))
	mux.HandleFunc("GET /admin/users", d.auth(d.adminUsers))
	mux.HandleFunc("POST /admin/users", d.auth(d.adminAddUser))
	mux.HandleFunc("POST /admin/users/{name}", d.auth(d.adminUserAction))
}

type ctxKey int

const userCtxKey ctxKey = 0

type authUser struct{ name string }

func (d *Dashboard) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := d.authenticate(r)
		if !ok {
			// Browsers get the login form; scripts/other methods get 401.
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userCtxKey, au)))
	}
}

// authenticate resolves the caller from (in order) a session cookie, HTTP Basic
// Auth (for scripts), or open mode when nothing is configured.
func (d *Dashboard) authenticate(r *http.Request) (authUser, bool) {
	n, _ := d.store.CountUsers()
	if n == 0 && d.user == "" {
		return authUser{name: "anonymous"}, true // no auth configured
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if user, ok := d.signer.Verify(c.Value); ok {
			return authUser{name: user}, true
		}
	}
	if u, p, ok := r.BasicAuth(); ok && d.checkPassword(u, p) {
		return authUser{name: u}, true
	}
	return authUser{}, false
}

// checkPassword validates a username/password against the user store, or the
// static bootstrap credential while no users exist. Constant-time for the static
// path; PBKDF2 verify is constant-time internally.
func (d *Dashboard) checkPassword(u, p string) bool {
	n, _ := d.store.CountUsers()
	if n == 0 {
		if d.user == "" {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(u), []byte(d.user)) == 1 &&
			subtle.ConstantTimeCompare([]byte(p), []byte(d.pass)) == 1
	}
	usr, found, err := d.store.GetUser(u)
	return err == nil && found && auth.Verify(p, usr.PassHash)
}

// severity ranking for sorting flaws (most critical first).
func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

type osRow struct {
	OS                       string
	Hosts, Crit, High, Med, Low int
}

func (d *Dashboard) dashboard(w http.ResponseWriter, r *http.Request) {
	agents, err := d.store.ListAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Per-OS-type summary + fleet totals.
	byOS := map[string]*osRow{}
	order := []string{}
	impacted := 0
	var tot osRow
	for _, a := range agents {
		os := strings.TrimSpace(a.OSID + " " + a.OSVersionID)
		if os == "" {
			os = "unknown"
		}
		row := byOS[os]
		if row == nil {
			row = &osRow{OS: os}
			byOS[os] = row
			order = append(order, os)
		}
		row.Hosts++
		tot.Hosts++
		row.Crit += a.SeverityCounts["CRITICAL"]
		row.High += a.SeverityCounts["HIGH"]
		row.Med += a.SeverityCounts["MEDIUM"]
		row.Low += a.SeverityCounts["LOW"]
		tot.Crit += a.SeverityCounts["CRITICAL"]
		tot.High += a.SeverityCounts["HIGH"]
		tot.Med += a.SeverityCounts["MEDIUM"]
		tot.Low += a.SeverityCounts["LOW"]
		if a.FindingCount > 0 {
			impacted++
		}
	}
	sort.Strings(order)
	rows := make([]osRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, *byOS[k])
	}

	// Impacted-vs-total donut geometry (r=42).
	const circ = 263.894
	filled := 0.0
	pct := 0
	if tot.Hosts > 0 {
		frac := float64(impacted) / float64(tot.Hosts)
		filled = frac * circ
		pct = int(frac*100 + 0.5)
	}

	// Top flaws: most critical, then most widespread, then highest score. Paged.
	// Optional ?flaws=running keeps only flaws running on at least one host.
	flawFilter := r.URL.Query().Get("flaws") // "" (all, default) | running
	flaws, err := d.store.ListCVEs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if flawFilter == "running" {
		kept := make([]model.CVESummary, 0, len(flaws))
		for _, f := range flaws {
			if f.RunningHosts > 0 {
				kept = append(kept, f)
			}
		}
		flaws = kept
	}
	sort.Slice(flaws, func(i, j int) bool {
		ri, rj := sevRank(flaws[i].CVSSSeverity), sevRank(flaws[j].CVSSSeverity)
		if ri != rj {
			return ri > rj
		}
		if flaws[i].AffectedHosts != flaws[j].AffectedHosts {
			return flaws[i].AffectedHosts > flaws[j].AffectedHosts
		}
		if flaws[i].CVSSScore != flaws[j].CVSSScore {
			return flaws[i].CVSSScore > flaws[j].CVSSScore
		}
		return flaws[i].CVE < flaws[j].CVE
	})
	const pageSize = 10
	page := 1
	if p, e := strconv.Atoi(r.URL.Query().Get("page")); e == nil && p > 1 {
		page = p
	}
	start := (page - 1) * pageSize
	if start > len(flaws) {
		start = len(flaws)
	}
	end := start + pageSize
	if end > len(flaws) {
		end = len(flaws)
	}

	flawQuery := ""
	if flawFilter == "running" {
		flawQuery = "flaws=running&"
	}
	d.render(w, "dashboard", map[string]any{
		"Nav":        "dashboard",
		"OSRows":     rows,
		"Tot":        tot,
		"TotalHosts": tot.Hosts,
		"Impacted":   impacted,
		"Pct":        pct,
		"DonutCirc":  fmt.Sprintf("%.1f", circ),
		"DonutFill":  fmt.Sprintf("%.1f", filled),
		"Flaws":      flaws[start:end],
		"FlawTotal":  len(flaws),
		"FlawFilter": flawFilter,
		"Page":       page,
		"Query":      flawQuery,
		"HasPrev":    page > 1,
		"HasNext":    end < len(flaws),
	})
}

func (d *Dashboard) index(w http.ResponseWriter, r *http.Request) {
	agents, err := d.store.ListAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Optional ?tag=key:value filter.
	filterKey, filterVal := splitTag(r.URL.Query().Get("tag"))
	if filterKey != "" {
		agents = groups.Filter(agents, filterKey, filterVal)
	}
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].RunningCount != agents[j].RunningCount {
			return agents[i].RunningCount > agents[j].RunningCount
		}
		return agents[i].Hostname < agents[j].Hostname
	})
	n, _ := d.store.TrackerCount()
	d.render(w, "index", map[string]any{
		"Nav": "agents", "Agents": agents, "TrackerCount": n,
		"FilterTag": r.URL.Query().Get("tag"),
	})
}

// groupsPage renders per-tag rollups. ?by=<key> selects the grouping key.
func (d *Dashboard) groupsPage(w http.ResponseWriter, r *http.Request) {
	agents, err := d.store.ListAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	keys := groups.Keys(agents)
	by := r.URL.Query().Get("by")
	if by == "" && len(keys) > 0 {
		by = keys[0]
	}
	var rollups []groups.Rollup
	if by != "" {
		rollups = groups.By(agents, by)
	}
	d.render(w, "groups", map[string]any{
		"Nav": "groups", "Keys": keys, "By": by, "Rollups": rollups,
	})
}

// setTags applies operator tag edits from the agent page.
func (d *Dashboard) setTags(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	ag, err := d.store.GetAgent(id)
	if err != nil {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}
	tags := map[string]string{}
	for k, v := range ag.Tags {
		tags[k] = v
	}
	switch r.FormValue("action") {
	case "add":
		k := strings.TrimSpace(r.FormValue("key"))
		v := strings.TrimSpace(r.FormValue("value"))
		if k != "" {
			tags[k] = v
		}
	case "remove":
		delete(tags, strings.TrimSpace(r.FormValue("key")))
	}
	if err := d.store.SetAgentTags(id, tags); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/agents/"+id, http.StatusSeeOther)
}

// splitTag parses a "key:value" filter parameter.
func splitTag(s string) (string, string) {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", ""
}

func (d *Dashboard) agent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ag, err := d.store.GetAgent(id)
	if err != nil {
		http.Error(w, "agent not found", http.StatusNotFound)
		return
	}
	findings, err := d.store.ListFindings(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now()
	showAll := r.URL.Query().Get("show") == "all"
	runFilter := r.URL.Query().Get("run")     // ""/all | running | notrunning
	sevFilter := r.URL.Query().Get("severity") // "" | CRITICAL | HIGH | MEDIUM | LOW
	type row struct {
		model.Finding
		Effective  string
		Suppressed bool
	}
	var rows []row
	suppressedCount := 0
	for _, f := range findings {
		eff := model.EffectiveTriage(f.TriageState, f.TriageUntil, now)
		sup := model.IsSuppressed(eff)
		if sup {
			suppressedCount++
			if !showAll {
				continue
			}
		}
		if runFilter == "running" && !f.Running {
			continue
		}
		if runFilter == "notrunning" && f.Running {
			continue
		}
		if sevFilter != "" && !strings.EqualFold(f.CVSSSeverity, sevFilter) {
			continue
		}
		rows = append(rows, row{Finding: f, Effective: eff, Suppressed: sup})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Suppressed != rows[j].Suppressed {
			return !rows[i].Suppressed // active first, suppressed sink to the bottom
		}
		if rows[i].Running != rows[j].Running {
			return rows[i].Running
		}
		if rows[i].CVSSScore != rows[j].CVSSScore {
			return rows[i].CVSSScore > rows[j].CVSSScore
		}
		return rows[i].CVE > rows[j].CVE
	})
	d.render(w, "agent", map[string]any{
		"Nav": "agents", "Agent": ag, "Rows": rows,
		"ShowAll": showAll, "SuppressedCount": suppressedCount,
		"RunFilter": runFilter, "SevFilter": sevFilter,
	})
}

// triage applies an operator decision from the dashboard and redirects back.
func (d *Dashboard) triage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	agentID := r.FormValue("agent_id")
	action := r.FormValue("action") // acknowledged|snoozed|risk_accepted|muted|active
	t := model.Triage{
		AgentID:       agentID,
		CVE:           r.FormValue("cve"),
		SourcePackage: r.FormValue("source_package"),
		Ecosystem:     r.FormValue("ecosystem"),
		State:         action,
		Note:          strings.TrimSpace(r.FormValue("note")),
		Actor:         d.actor(r),
	}
	if days := r.FormValue("days"); days != "" && (action == model.TriageSnoozed || action == model.TriageRiskAccepted) {
		if n, err := strconv.Atoi(days); err == nil && n > 0 {
			t.Until = time.Now().Add(time.Duration(n) * 24 * time.Hour).UTC()
		}
	}
	if err := d.store.SetTriage(t); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	dest := "/agents/" + agentID
	if r.FormValue("return") == "cve" {
		dest = "/cves/" + t.CVE
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (d *Dashboard) audit(w http.ResponseWriter, r *http.Request) {
	events, err := d.store.AuditLog(200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.render(w, "audit", map[string]any{"Nav": "audit", "Events": events})
}

// actor identifies who performed a triage action (basic-auth user, else "operator").
func (d *Dashboard) actor(r *http.Request) string {
	if au, ok := r.Context().Value(userCtxKey).(authUser); ok && au.name != "" {
		return au.name
	}
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		return u
	}
	return "operator"
}

// ---- Branding + about ----

func (d *Dashboard) favicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte(cobraLogoSVG))
}

func (d *Dashboard) about(w http.ResponseWriter, r *http.Request) {
	v := d.version
	if v == "" {
		v = "dev"
	}
	d.render(w, "about", map[string]any{"Nav": "about", "Version": v})
}

// ---- Login / logout (session cookies) ----
// safeNext returns a local redirect target, defaulting to "/".
func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}
	return "/"
}

func (d *Dashboard) loginForm(w http.ResponseWriter, r *http.Request) {
	if au, ok := d.authenticate(r); ok && au.name != "" {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	d.render(w, "login", map[string]any{"Next": r.URL.Query().Get("next")})
}

func (d *Dashboard) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := strings.TrimSpace(r.FormValue("username"))
	p := r.FormValue("password")
	next := safeNext(r.FormValue("next"))
	if !d.checkPassword(u, p) {
		w.WriteHeader(http.StatusUnauthorized)
		d.render(w, "login", map[string]any{"Next": next, "Err": "invalid username or password"})
		return
	}
	token, exp := d.signer.Issue(u, sessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (d *Dashboard) logout(w http.ResponseWriter, r *http.Request) {
	// Stateless tokens: clearing the cookie logs the browser out. The token stays
	// cryptographically valid until it expires; rotate the session key to force
	// all sessions to end immediately.
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- Admin: user management ----

func (d *Dashboard) adminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := d.store.ListUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bootstrap := len(users) == 0 && d.user != ""
	d.render(w, "admin_users", map[string]any{
		"Nav": "admin", "Users": users, "Me": d.actor(r),
		"Bootstrap": bootstrap, "Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err"),
	})
}

func (d *Dashboard) adminAddUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	if name == "" || len(pass) < 8 {
		redirectAdmin(w, r, "", "username required and password must be at least 8 characters")
		return
	}
	hash, err := auth.Hash(pass)
	if err != nil {
		redirectAdmin(w, r, "", err.Error())
		return
	}
	if err := d.store.CreateUser(model.User{Username: name, PassHash: hash, IsAdmin: true}); err != nil {
		if err == store.ErrExists {
			redirectAdmin(w, r, "", "user "+name+" already exists")
		} else {
			redirectAdmin(w, r, "", err.Error())
		}
		return
	}
	redirectAdmin(w, r, "created user "+name, "")
}

func (d *Dashboard) adminUserAction(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	switch r.FormValue("action") {
	case "password":
		pass := r.FormValue("password")
		if len(pass) < 8 {
			redirectAdmin(w, r, "", "password must be at least 8 characters")
			return
		}
		hash, err := auth.Hash(pass)
		if err != nil {
			redirectAdmin(w, r, "", err.Error())
			return
		}
		if err := d.store.SetUserPassword(name, hash); err != nil {
			redirectAdmin(w, r, "", err.Error())
			return
		}
		redirectAdmin(w, r, "reset password for "+name, "")
	case "delete":
		// Never allow removing the last account (would lock everyone out).
		if n, _ := d.store.CountUsers(); n <= 1 {
			redirectAdmin(w, r, "", "cannot delete the last user")
			return
		}
		if err := d.store.DeleteUser(name); err != nil {
			redirectAdmin(w, r, "", err.Error())
			return
		}
		redirectAdmin(w, r, "deleted user "+name, "")
	default:
		redirectAdmin(w, r, "", "unknown action")
	}
}

func redirectAdmin(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	v := url.Values{}
	if msg != "" {
		v.Set("msg", msg)
	}
	if errMsg != "" {
		v.Set("err", errMsg)
	}
	dest := "/admin/users"
	if e := v.Encode(); e != "" {
		dest += "?" + e
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (d *Dashboard) cves(w http.ResponseWriter, r *http.Request) {
	cves, err := d.store.ListCVEs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	sortKey := q.Get("sort")
	dir := q.Get("dir")
	if dir != "asc" {
		dir = "desc"
	}

	// lessDesc reports whether i sorts before j in DESCENDING order for the
	// chosen column; ascending simply swaps the operands. CVE id is the stable
	// tiebreak. sortKey "" keeps the default composite (exposure) ordering.
	lessDesc := func(i, j int) bool {
		a, b := cves[i], cves[j]
		switch sortKey {
		case "cve":
			if a.CVE != b.CVE {
				return a.CVE > b.CVE
			}
		case "severity":
			if ra, rb := severityRank(a.CVSSSeverity), severityRank(b.CVSSSeverity); ra != rb {
				return ra > rb
			}
			if a.CVSSScore != b.CVSSScore {
				return a.CVSSScore > b.CVSSScore
			}
		case "exploit":
			if a.KEVListed != b.KEVListed {
				return a.KEVListed
			}
			if a.EPSSScore != b.EPSSScore {
				return a.EPSSScore > b.EPSSScore
			}
		case "hosts":
			if a.AffectedHosts != b.AffectedHosts {
				return a.AffectedHosts > b.AffectedHosts
			}
		case "running":
			if a.RunningHosts != b.RunningHosts {
				return a.RunningHosts > b.RunningHosts
			}
		case "summary":
			if a.Summary != b.Summary {
				return a.Summary > b.Summary
			}
		default: // composite default: KEV, severity, EPSS, running, hosts
			if a.KEVListed != b.KEVListed {
				return a.KEVListed
			}
			if ra, rb := severityRank(a.CVSSSeverity), severityRank(b.CVSSSeverity); ra != rb {
				return ra > rb
			}
			if a.EPSSScore != b.EPSSScore {
				return a.EPSSScore > b.EPSSScore
			}
			if a.RunningHosts != b.RunningHosts {
				return a.RunningHosts > b.RunningHosts
			}
			if a.AffectedHosts != b.AffectedHosts {
				return a.AffectedHosts > b.AffectedHosts
			}
		}
		return a.CVE > b.CVE
	}
	sort.Slice(cves, func(i, j int) bool {
		if sortKey != "" && dir == "asc" {
			return lessDesc(j, i)
		}
		return lessDesc(i, j)
	})

	// Paginate, 50 per page.
	const perPage = 50
	total := len(cves)
	page := atoiDefault(q.Get("page"), 1)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	// Pager query prefix preserves the active sort across pages.
	qs := url.Values{}
	if sortKey != "" {
		qs.Set("sort", sortKey)
		qs.Set("dir", dir)
	}
	prefix := qs.Encode()
	if prefix != "" {
		prefix += "&"
	}

	// Column headers with toggle links + active arrow.
	type colHdr struct {
		Label, Class string
		Href         template.URL
		Arrow        string
	}
	cols := []struct{ Key, Label, Class string }{
		{"cve", "CVE", ""}, {"severity", "Severity (CVSS)", ""}, {"exploit", "Exploit", ""},
		{"hosts", "Hosts", "count"}, {"running", "Running", "count"}, {"summary", "Summary", ""},
	}
	hdrs := make([]colHdr, 0, len(cols))
	for _, c := range cols {
		nextDir := "desc"
		arrow := ""
		if sortKey == c.Key {
			if dir == "desc" {
				nextDir, arrow = "asc", " ↓"
			} else {
				nextDir, arrow = "desc", " ↑"
			}
		}
		hdrs = append(hdrs, colHdr{
			Label: c.Label, Class: c.Class,
			Href:  template.URL("?sort=" + c.Key + "&dir=" + nextDir),
			Arrow: arrow,
		})
	}

	d.render(w, "cves", map[string]any{
		"Nav": "cves", "CVEs": cves[start:end], "Cols": hdrs,
		"Total": total, "Page": page,
		"HasPrev": page > 1, "HasNext": end < total, "Query": prefix,
	})
}

func (d *Dashboard) cve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	hosts, err := d.store.HostsForCVE(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enr, haveEnr, _ := d.store.EnrichmentFor(id)
	enr.CVE = id
	advs, _ := d.store.AdvisoriesForCVE(id)
	// 404 only if we know nothing about this CVE at all.
	if len(hosts) == 0 && !haveEnr && len(advs) == 0 {
		http.Error(w, "unknown CVE (not in findings, enrichment, or tracker)", http.StatusNotFound)
		return
	}
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Running != hosts[j].Running {
			return hosts[i].Running
		}
		return hosts[i].Hostname < hosts[j].Hostname
	})
	d.render(w, "cve", map[string]any{"Nav": "cves", "CVE": id, "Enr": enr, "Hosts": hosts, "Advs": advs})
}

// distroForRelease labels a release codename by distro for display/filtering.
func distroForRelease(rel string) string {
	switch rel {
	case "xenial", "bionic", "focal", "jammy", "kinetic", "lunar", "mantic", "noble", "oracular", "plucky", "questing":
		return "ubuntu"
	case "buster", "bullseye", "bookworm", "trixie", "forky", "sid":
		return "debian"
	default:
		return ""
	}
}

func (d *Dashboard) catalogAdvisories(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 1)
	const perPage = 50
	release := q.Get("release")
	// A distro filter maps to its releases; if both distro and release given, release wins.
	aq := store.AdvisoryQuery{
		Text:          strings.TrimSpace(q.Get("q")),
		SourcePackage: q.Get("pkg"),
		Release:       release,
		Status:        q.Get("status"),
		Limit:         perPage,
		Offset:        (page - 1) * perPage,
	}
	advs, total, err := d.store.SearchAdvisories(aq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// If a distro filter is set (and no explicit release), filter in-handler by codename.
	distro := q.Get("distro")
	if distro != "" && release == "" {
		filtered := advs[:0]
		for _, a := range advs {
			if distroForRelease(a.Release) == distro {
				filtered = append(filtered, a)
			}
		}
		advs = filtered
	}
	type row struct {
		model.Advisory
		Distro string
	}
	rows := make([]row, 0, len(advs))
	for _, a := range advs {
		rows = append(rows, row{Advisory: a, Distro: distroForRelease(a.Release)})
	}
	releases, _ := d.store.TrackerReleases()
	qs := url.Values{}
	for _, kv := range [][2]string{{"q", aq.Text}, {"pkg", aq.SourcePackage}, {"distro", distro}, {"release", release}, {"status", aq.Status}} {
		if kv[1] != "" {
			qs.Set(kv[0], kv[1])
		}
	}
	prefix := qs.Encode()
	if prefix != "" {
		prefix += "&"
	}
	d.render(w, "catalog_advisories", map[string]any{
		"Nav": "catalog", "Rows": rows, "Total": total, "Page": page, "PerPage": perPage,
		"Q": aq.Text, "Release": release, "Status": aq.Status, "Pkg": aq.SourcePackage, "Distro": distro,
		"Releases": releases, "HasNext": page*perPage < total, "HasPrev": page > 1, "Query": prefix,
	})
}

func (d *Dashboard) catalogCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := atoiDefault(q.Get("page"), 1)
	const perPage = 50
	cq := store.CVEQuery{
		Text:     strings.TrimSpace(q.Get("q")),
		Severity: q.Get("severity"),
		KEVOnly:  q.Get("kev") == "1",
		Limit:    perPage,
		Offset:   (page - 1) * perPage,
	}
	cves, total, err := d.store.SearchCVEs(cq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	qs := url.Values{}
	if cq.Text != "" {
		qs.Set("q", cq.Text)
	}
	if cq.Severity != "" {
		qs.Set("severity", cq.Severity)
	}
	if cq.KEVOnly {
		qs.Set("kev", "1")
	}
	prefix := qs.Encode()
	if prefix != "" {
		prefix += "&"
	}
	d.render(w, "catalog_cves", map[string]any{
		"Nav": "catalog", "CVEs": cves, "Total": total, "Page": page, "PerPage": perPage,
		"Q": cq.Text, "Severity": cq.Severity, "KEV": cq.KEVOnly,
		"HasNext": page*perPage < total, "HasPrev": page > 1, "Query": prefix,
	})
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

func (d *Dashboard) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// chartSeg / chartBar / chartData carry pre-computed SVG geometry so the
// template stays free of arithmetic.
type chartSeg struct {
	Class string
	Y, H  int
}
type chartBar struct {
	X, W  int
	Segs  []chartSeg
	Label string
	Total int
}
type chartData struct {
	W, H, Base int
	MaxTotal   int
	Bars       []chartBar
}

var sevClassForChart = map[string]string{
	"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "unknown",
}

func buildChart(days []trends.Day) chartData {
	const w, h = 920, 190
	const padL, padTop, padBottom = 6, 10, 20
	plotH := h - padTop - padBottom
	c := chartData{W: w, H: h, Base: padTop + plotH}

	maxT := 1
	for _, d := range days {
		if d.Total > maxT {
			maxT = d.Total
		}
	}
	c.MaxTotal = maxT
	n := len(days)
	if n == 0 {
		return c
	}
	const gap = 2
	barW := (w-padL*2)/n - gap
	if barW < 1 {
		barW = 1
	}
	for i, d := range days {
		x := padL + i*(barW+gap)
		bar := chartBar{X: x, W: barW, Total: d.Total}
		if i%5 == 0 || i == n-1 {
			bar.Label = d.Date.Format("01/02")
		}
		yCursor := padTop + plotH
		for _, sev := range trends.Severities { // stack worst at the bottom
			cnt := d.Counts[sev]
			if cnt == 0 {
				continue
			}
			segH := cnt * plotH / maxT
			if segH < 1 {
				segH = 1
			}
			yCursor -= segH
			bar.Segs = append(bar.Segs, chartSeg{Class: sevClassForChart[sev], Y: yCursor, H: segH})
		}
		c.Bars = append(c.Bars, bar)
	}
	return c
}

func (d *Dashboard) trends(w http.ResponseWriter, r *http.Request) {
	lcs, err := d.store.FindingLifecycles()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	series := trends.Series(lcs, 30, now)
	d.render(w, "trends", map[string]any{
		"Nav":      "trends",
		"Chart":    buildChart(series),
		"Stats":    trends.Summary(lcs, now),
		"Activity": trends.Activity(lcs, 25),
	})
}

// severityRank orders CVSS severities (higher = worse) for sorting.
func severityRank(sev string) int {
	switch sev {
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
		return 0
	}
}

var funcs = template.FuncMap{
	"distro": distroForRelease,
	"list":   func(xs ...string) []string { return xs },
	"inc":    func(n int) int { return n + 1 },
	"dec":    func(n int) int { return n - 1 },
	"trunc": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "…"
	},
	"since": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return time.Since(t).Round(time.Second).String() + " ago"
	},
	"date": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format("2006-01-02")
	},
	// sevclass maps a CVSS severity to a CSS class name.
	"sevclass": func(sev string) string {
		switch sev {
		case "CRITICAL":
			return "critical"
		case "HIGH":
			return "high"
		case "MEDIUM":
			return "medium"
		case "LOW":
			return "low"
		default:
			return "unknown"
		}
	},
	"score": func(f float64) string {
		if f <= 0 {
			return ""
		}
		return fmt.Sprintf("%.1f", f)
	},
	"epss": func(f float64) string {
		if f <= 0 {
			return ""
		}
		return fmt.Sprintf("%.0f%%", f*100)
	},
	// pageurl builds a pager link as a single template.URL so the query prefix
	// (which legitimately contains '&' and '=') is emitted verbatim instead of
	// being percent-escaped by html/template's query-context escaper.
	"pageurl": func(query string, page int) template.URL {
		return template.URL("?" + query + "page=" + strconv.Itoa(page))
	},
}

const pages = `
{{define "login"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cobra — sign in</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
:root{--bg:#0f1115;--card:#171a21;--line:#242833;--fg:#e6e8ee;--mut:#8b93a7;--accent:#5a8cff}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;width:320px}
h1{font-size:18px;margin:0 0 4px}p.sub{color:var(--mut);font-size:12px;margin:0 0 18px}
label{display:block;font-size:12px;color:var(--mut);margin:12px 0 4px}
input{width:100%;padding:9px 11px;background:#0f1319;color:var(--fg);border:1px solid var(--line);border-radius:7px;font-size:14px}
button{width:100%;margin-top:18px;padding:10px;background:var(--accent);color:#fff;border:0;border-radius:7px;font-weight:700;font-size:14px;cursor:pointer}
.err{background:rgba(255,90,90,.15);color:#ff7b7b;padding:8px 10px;border-radius:6px;font-size:13px;margin-bottom:12px}
</style></head><body>
<form class="card" method="post" action="/login">
<h1>CVE Fleet</h1><p class="sub">Sign in to continue</p>
{{if .Err}}<div class="err">{{.Err}}</div>{{end}}
<input type="hidden" name="next" value="{{.Next}}">
<label>Username</label><input name="username" autofocus autocomplete="username">
<label>Password</label><input type="password" name="password" autocomplete="current-password">
<button>Sign in</button>
</form></body></html>{{end}}

{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cobra</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
:root{--bg:#0f1115;--panel:#171a21;--line:#242833;--fg:#e6e8ee;--mut:#8b93a7;--crit:#ff3b6b;--hi:#ff5d5d;--md:#ffb84d;--lo:#6cc6ff;--ok:#4ec38a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
a{color:inherit}.wrap{max-width:1080px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 20px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}tr:hover td{background:#1c2029}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600}
.critical{background:rgba(255,59,107,.18);color:var(--crit)}.high{background:rgba(255,93,93,.15);color:var(--hi)}.medium{background:rgba(255,184,77,.15);color:var(--md)}
.low{background:rgba(108,198,255,.15);color:var(--lo)}.unknown{background:#2a2f3a;color:var(--mut)}
.run{background:rgba(78,195,138,.15);color:var(--ok);font-weight:600}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.mut{color:var(--mut)}
.back{color:var(--mut);text-decoration:none;font-size:13px}.count{font-variant-numeric:tabular-nums}
nav{display:flex;gap:16px;margin:0 0 20px;padding-bottom:12px;border-bottom:1px solid var(--line)}
nav a{color:var(--mut);text-decoration:none;font-weight:600;font-size:13px}nav a.on{color:var(--fg)}
nav a.logout{margin-left:auto;color:var(--mut)}
nav a.brand{display:flex;align-items:center;gap:8px;color:var(--fg);font-size:15px;font-weight:800;margin-right:6px}
nav a.brand img{display:block}
.about{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;max-width:520px}
.about .hd{display:flex;align-items:center;gap:14px;margin-bottom:14px}
.about .hd img{width:44px;height:44px}
.about .hd .nm{font-size:22px;font-weight:800}
.about .hd .ver{color:var(--mut);font-size:13px}
.about dl{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;margin:0}
.about dt{color:var(--mut)}.about dd{margin:0}
.refs a{display:block;color:var(--lo);text-decoration:none;font-size:13px}.vec{font-size:12px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px;min-width:120px}
.card .n{font-size:24px;font-weight:700;font-variant-numeric:tabular-nums}.card .l{color:var(--mut);font-size:12px}
.chart{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;margin:0 0 20px}
.chart text{fill:var(--mut);font-size:10px}
rect.critical{fill:var(--crit)}rect.high{fill:var(--hi)}rect.medium{fill:var(--md)}rect.low{fill:var(--lo)}rect.unknown{fill:#3a4150}
.legend{display:flex;gap:14px;margin-top:6px;font-size:12px;color:var(--mut)}
.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:4px;vertical-align:middle}
.ap{color:var(--md)}.rs{color:var(--ok)}
.eco{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;font-weight:600;background:#2a2f3a;color:var(--mut);margin-left:6px}
.usedby{margin-top:3px;font-size:11px;color:var(--mut);white-space:normal;word-break:break-all}
form.filters{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin:10px 0}
form.filters label{font-size:13px;color:var(--mut)}
form.filters select{margin-left:4px}
table.sortable th:not(.nosort):hover{color:var(--fg)}
table.sortable th.sorted{color:var(--fg)}
table.sortable th.sorted[data-dir=asc]::after{content:" \2191"}
table.sortable th.sorted[data-dir=desc]::after{content:" \2193"}
.dash-top{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.card.grow{flex:1 1 380px}
.card-h{font-weight:700;margin-bottom:12px}
table.sum td,table.sum th{text-align:left}
table.sum td+td,table.sum th+th{text-align:right}
.sev{display:inline-block;min-width:26px;text-align:center;font-weight:700}
.c-crit{color:#ff6b6b}.c-high{color:#ff9f45}.c-med{color:#ffd25a}.c-low{color:#8fb0ff}
tr.totals td{border-top:2px solid var(--line);font-weight:800}
.donut-wrap{display:flex;flex-direction:column;align-items:center;gap:6px}
.flawfilter{float:right;font-weight:600;font-size:12px}
a.sortlink{color:inherit;text-decoration:none;cursor:pointer}
a.sortlink:hover{color:var(--fg)}
.flawfilter a{display:inline-block;padding:2px 10px;border:1px solid var(--line);color:var(--mut);text-decoration:none}
.flawfilter a:first-child{border-radius:6px 0 0 6px}
.flawfilter a:last-child{border-radius:0 6px 6px 0;border-left:0}
.flawfilter a.on{background:#26303f;color:var(--fg)}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px}
.stat{flex:1;min-width:120px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.stat .n{font-size:28px;font-weight:800;line-height:1.1;font-variant-numeric:tabular-nums}
.stat .l{font-size:12px;color:var(--mut);margin-top:2px;text-transform:uppercase;letter-spacing:.04em}
.stat.crit .n{color:#ff6b6b}.stat.high .n{color:#ff9f45}.stat.med .n{color:#ffd25a}.stat.low .n{color:#8fb0ff}
.donut{width:150px;height:150px}
.dnum{fill:var(--fg);font-size:20px;font-weight:800}
.dlbl{fill:var(--mut);font-size:11px}
.center{text-align:center;max-width:220px}
.kev{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;font-weight:700;background:rgba(255,59,107,.2);color:var(--crit);margin-left:6px}
.epss{font-variant-numeric:tabular-nums;color:var(--mut);font-size:12px}
.reach{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;font-weight:700}
form.search{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
form.search input[type=text],form.search input:not([type]){min-width:240px}
form.search input,form.search select,form.search button{font-size:13px;padding:5px 9px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:5px}
form.search button{cursor:pointer;font-weight:600}
form.search .chk{display:flex;gap:5px;align-items:center;color:var(--mut);font-size:12px}
.pager{display:flex;gap:16px;align-items:center;margin:16px 0}
.pager a{color:var(--fg);font-weight:600;text-decoration:none}
.banner{padding:8px 12px;border-radius:6px;font-size:13px;margin:10px 0}
.banner.ok{background:rgba(120,200,140,.15);color:#7cc88c}
.banner.err{background:rgba(255,90,90,.15);color:#ff7b7b}
.banner.warn{background:rgba(255,180,60,.15);color:#e8b04b}
.reach.used{background:rgba(255,90,90,.2);color:#ff7b7b}
.reach.unused{background:rgba(120,200,140,.16);color:#7cc88c}
tr.supp{opacity:.5}
.tri{display:inline-block;padding:0 6px;border-radius:4px;font-size:11px;font-weight:600}
.tri.muted{background:#3a3a3a;color:#bbb}
.tri.snoozed{background:rgba(90,140,255,.2);color:#8ab4ff}
.tri.accepted{background:rgba(255,180,60,.18);color:#e8b04b}
.tri.ack{background:rgba(120,200,140,.18);color:#7cc88c}
.tri.clr{background:#333;color:#999}
td.triage form{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
td.triage select,td.triage input,td.triage button{font-size:11px;padding:2px 6px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:4px}
td.triage input[name=note]{width:110px}
td.triage button{cursor:pointer}
td.triage button.clr{color:var(--mut)}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:600;background:#26303f;color:#9fc2e8;text-decoration:none}
a.tag.on{background:#3a5578;color:#fff}
.tag .tagx{display:inline;margin:0}
.tag .tagx button{background:none;border:none;color:#9fc2e8;cursor:pointer;padding:0 0 0 4px;font-size:11px}
form.tagadd{display:inline-flex;gap:4px;margin-left:6px}
form.tagadd input{font-size:11px;padding:2px 6px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:4px}
form.tagadd input[name=key]{width:70px}form.tagadd input[name=value]{width:90px}
form.tagadd button{font-size:11px;padding:2px 8px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:4px;cursor:pointer}
</style></head><body><div class="wrap">
<nav><a class="brand" href="/"><img src="/favicon.svg" width="24" height="24" alt=""><span>Cobra</span></a><a href="/" class="{{if eq .Nav "dashboard"}}on{{end}}">Overview</a><a href="/agents" class="{{if eq .Nav "agents"}}on{{end}}">Agents</a><a href="/cves" class="{{if eq .Nav "cves"}}on{{end}}">Vulnerabilities</a><a href="/catalog" class="{{if eq .Nav "catalog"}}on{{end}}">Catalog</a><a href="/groups" class="{{if eq .Nav "groups"}}on{{end}}">Groups</a><a href="/trends" class="{{if eq .Nav "trends"}}on{{end}}">Trends</a><a href="/audit" class="{{if eq .Nav "audit"}}on{{end}}">Audit</a><a href="/admin/users" class="{{if eq .Nav "admin"}}on{{end}}">Admin</a><a href="/about" class="{{if eq .Nav "about"}}on{{end}}">About</a><a href="/logout" class="logout">Log out</a></nav>{{end}}
{{define "foot"}}<script>
(function(){
function cellVal(r,i){var c=r.cells[i];if(!c)return "";return (c.getAttribute("data-sort")||c.textContent||"").trim();}
document.querySelectorAll("table.sortable").forEach(function(t){
  if(!t.tHead||!t.tBodies[0])return;
  var ths=t.tHead.rows[0].cells;
  Array.prototype.forEach.call(ths,function(th,idx){
    if(th.classList.contains("nosort"))return;
    th.style.cursor="pointer";th.title="click to sort";
    th.addEventListener("click",function(){
      var tb=t.tBodies[0];
      var rows=Array.prototype.slice.call(tb.rows).filter(function(r){return !r.hasAttribute("data-empty");});
      if(!rows.length)return;
      var asc=th.getAttribute("data-dir")!=="asc";
      Array.prototype.forEach.call(ths,function(h){h.removeAttribute("data-dir");h.classList.remove("sorted");});
      th.setAttribute("data-dir",asc?"asc":"desc");th.classList.add("sorted");
      rows.sort(function(a,b){
        var x=cellVal(a,idx),y=cellVal(b,idx);
        var nx=parseFloat(x),ny=parseFloat(y);
        var num=x!==""&&y!==""&&!isNaN(nx)&&!isNaN(ny);
        if(num)return asc?nx-ny:ny-nx;
        return asc?x.localeCompare(y):y.localeCompare(x);
      });
      rows.forEach(function(r){tb.appendChild(r);});
    });
  });
});
})();
</script></div></body></html>{{end}}

{{define "dashboard"}}{{template "head" .}}
<h1>Overview</h1>
<div class="stats">
  <div class="stat"><div class="n">{{.TotalHosts}}</div><div class="l">Hosts</div></div>
  <div class="stat crit"><div class="n">{{.Tot.Crit}}</div><div class="l">Critical</div></div>
  <div class="stat high"><div class="n">{{.Tot.High}}</div><div class="l">High</div></div>
  <div class="stat med"><div class="n">{{.Tot.Med}}</div><div class="l">Medium</div></div>
  <div class="stat low"><div class="n">{{.Tot.Low}}</div><div class="l">Low</div></div>
</div>
<div class="dash-top">
  <div class="card grow">
    <div class="card-h">Findings by OS</div>
    <table class="sum">
      <thead><tr><th>OS</th><th>Hosts</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
      <tbody>
      {{range .OSRows}}<tr>
        <td class="mono">{{.OS}}</td>
        <td>{{.Hosts}}</td>
        <td><span class="sev c-crit">{{.Crit}}</span></td>
        <td><span class="sev c-high">{{.High}}</span></td>
        <td><span class="sev c-med">{{.Med}}</span></td>
        <td><span class="sev c-low">{{.Low}}</span></td>
      </tr>{{end}}
      {{if not .OSRows}}<tr><td colspan="6" class="mut">No hosts enrolled yet.</td></tr>{{end}}
      </tbody>
      {{if .OSRows}}<tfoot><tr class="totals">
        <td>Total</td><td>{{.Tot.Hosts}}</td>
        <td><span class="sev c-crit">{{.Tot.Crit}}</span></td>
        <td><span class="sev c-high">{{.Tot.High}}</span></td>
        <td><span class="sev c-med">{{.Tot.Med}}</span></td>
        <td><span class="sev c-low">{{.Tot.Low}}</span></td>
      </tr></tfoot>{{end}}
    </table>
  </div>
  <div class="card">
    <div class="card-h">Impacted hosts</div>
    <div class="donut-wrap">
      <svg viewBox="0 0 120 120" class="donut" role="img" aria-label="impacted hosts">
        <circle cx="60" cy="60" r="42" fill="none" stroke="#2a2f3a" stroke-width="14"/>
        <circle cx="60" cy="60" r="42" fill="none" stroke="#e5533c" stroke-width="14" stroke-linecap="round"
                stroke-dasharray="{{.DonutFill}} {{.DonutCirc}}" transform="rotate(-90 60 60)"/>
        <text x="60" y="57" text-anchor="middle" class="dnum">{{.Impacted}}/{{.TotalHosts}}</text>
        <text x="60" y="75" text-anchor="middle" class="dlbl">{{.Pct}}% impacted</text>
      </svg>
      <p class="mut center">{{.Impacted}} of {{.TotalHosts}} host(s) have at least one open finding.</p>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-h">Top flaws — most critical &amp; most widespread <span class="mut">({{.FlawTotal}} total)</span>
    <span class="flawfilter"><a href="?" class="{{if ne .FlawFilter "running"}}on{{end}}">all</a><a href="?flaws=running" class="{{if eq .FlawFilter "running"}}on{{end}}">running</a></span>
  </div>
  <table>
    <thead><tr><th>ID</th><th>Severity (CVSS)</th><th>Hosts</th><th>Running</th><th>Exploit</th></tr></thead>
    <tbody>
    {{range .Flaws}}<tr>
      <td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a></td>
      <td><span class="pill {{sevclass .CVSSSeverity}}">{{.CVSSSeverity}}{{with score .CVSSScore}} {{.}}{{end}}</span></td>
      <td>{{.AffectedHosts}}</td>
      <td>{{if .RunningHosts}}<span class="pill run">{{.RunningHosts}}</span>{{else}}<span class="mut">0</span>{{end}}</td>
      <td>{{if .KEVListed}}<span class="kev">KEV</span> {{end}}{{with epss .EPSSScore}}<span class="epss">EPSS {{.}}</span>{{end}}</td>
    </tr>{{end}}
    {{if not .Flaws}}<tr><td colspan="5" class="mut">No findings yet.</td></tr>{{end}}
    </tbody>
  </table>
  {{template "pager" .}}
</div>
{{template "foot" .}}{{end}}

{{define "index"}}{{template "head" .}}
<h1>Hosts</h1>
<p class="sub">{{len .Agents}} agent(s) · {{.TrackerCount}} Debian advisories loaded{{if .FilterTag}} · filtered by <span class="tag">{{.FilterTag}}</span> <a href="/agents">clear</a>{{end}}</p>
<table><thead><tr>
<th>Host</th><th>OS</th><th>Tags</th><th>Last seen</th>
<th class="count">Running</th><th class="count">Total</th><th>Breakdown</th>
</tr></thead><tbody>
{{range .Agents}}<tr>
<td><a class="mono" href="/agents/{{.ID}}">{{.Hostname}}</a></td>
<td class="mut">{{.OSID}} {{.OSVersionID}}</td>
<td>{{range $k, $v := .EffectiveTags}}<a class="tag" href="/?tag={{$k}}:{{$v}}">{{$k}}:{{$v}}</a> {{else}}<span class="mut">&mdash;</span>{{end}}</td>
<td class="mut">{{since .LastSeenAt}}</td>
<td class="count">{{if .RunningCount}}<span class="pill run">{{.RunningCount}}</span>{{else}}0{{end}}</td>
<td class="count">{{.FindingCount}}</td>
<td>
{{with index .SeverityCounts "CRITICAL"}}<span class="pill critical">{{.}} crit</span> {{end}}
{{with index .SeverityCounts "HIGH"}}<span class="pill high">{{.}} high</span> {{end}}
{{with index .SeverityCounts "MEDIUM"}}<span class="pill medium">{{.}} med</span> {{end}}
{{with index .SeverityCounts "LOW"}}<span class="pill low">{{.}} low</span> {{end}}
{{if .KEVCount}}<span class="kev">{{.KEVCount}} KEV</span>{{end}}
</td></tr>{{else}}
<tr><td colspan="7" class="mut">No agents match.</td></tr>
{{end}}</tbody></table>
{{template "foot" .}}{{end}}

{{define "groups"}}{{template "head" .}}
<h1>Groups</h1>
<p class="sub">group hosts by tag:
{{range .Keys}}<a class="tag {{if eq . $.By}}on{{end}}" href="/groups?by={{.}}">{{.}}</a> {{else}}<span class="mut">no tags yet — add tags on an agent page</span>{{end}}
</p>
{{if .Rollups}}<table><thead><tr>
<th>{{.By}}</th><th class="count">Hosts</th><th class="count">Findings</th><th class="count">Running</th><th>Breakdown</th>
</tr></thead><tbody>
{{range .Rollups}}<tr>
<td>{{if eq .Value "(untagged)"}}<span class="mut">(untagged)</span>{{else}}<a class="tag" href="/?tag={{$.By}}:{{.Value}}">{{.Value}}</a>{{end}}</td>
<td class="count">{{.Hosts}}</td>
<td class="count">{{.Findings}}</td>
<td class="count">{{if .Running}}<span class="pill run">{{.Running}}</span>{{else}}0{{end}}</td>
<td>
{{with index .SeverityCounts "CRITICAL"}}<span class="pill critical">{{.}} crit</span> {{end}}
{{with index .SeverityCounts "HIGH"}}<span class="pill high">{{.}} high</span> {{end}}
{{with index .SeverityCounts "MEDIUM"}}<span class="pill medium">{{.}} med</span> {{end}}
{{if .KEV}}<span class="kev">{{.KEV}} KEV</span>{{end}}
</td></tr>{{end}}
</tbody></table>{{end}}
{{template "foot" .}}{{end}}

{{define "agent"}}{{template "head" .}}
<a class="back" href="/agents">&larr; all agents</a>
<h1 class="mono">{{.Agent.Hostname}}</h1>
<p class="sub">{{.Agent.OSID}} {{.Agent.OSVersionID}} · {{.Agent.Arch}} · kernel {{.Agent.Kernel}} · agent {{.Agent.AgentVersion}} · seen {{since .Agent.LastSeenAt}}</p>
<p class="sub">tags:
{{range $k, $v := .Agent.EffectiveTags}}<span class="tag">{{$k}}:{{$v}}<form method="post" action="/agents/{{$.Agent.ID}}/tags" class="tagx"><input type="hidden" name="action" value="remove"><input type="hidden" name="key" value="{{$k}}"><button title="remove">×</button></form></span> {{else}}<span class="mut">none</span> {{end}}
<form method="post" action="/agents/{{.Agent.ID}}/tags" class="tagadd"><input type="hidden" name="action" value="add"><input name="key" placeholder="key" maxlength="40"><input name="value" placeholder="value" maxlength="60"><button>+ tag</button></form>
</p>
<p class="sub">{{if .SuppressedCount}}{{.SuppressedCount}} finding(s) triaged away · {{if .ShowAll}}<a href="?">hide suppressed</a>{{else}}<a href="?show=all">show suppressed</a>{{end}}{{else}}no suppressed findings{{end}}</p>
<form class="filters" method="get">
{{if .ShowAll}}<input type="hidden" name="show" value="all">{{end}}
<label>Runtime <select name="run" onchange="this.form.submit()">
<option value="">all</option>
<option value="running" {{if eq .RunFilter "running"}}selected{{end}}>running only</option>
<option value="notrunning" {{if eq .RunFilter "notrunning"}}selected{{end}}>not running</option>
</select></label>
<label>Severity <select name="severity" onchange="this.form.submit()">
<option value="">all</option>
<option {{if eq .SevFilter "CRITICAL"}}selected{{end}}>CRITICAL</option>
<option {{if eq .SevFilter "HIGH"}}selected{{end}}>HIGH</option>
<option {{if eq .SevFilter "MEDIUM"}}selected{{end}}>MEDIUM</option>
<option {{if eq .SevFilter "LOW"}}selected{{end}}>LOW</option>
</select></label>
<noscript><button>Apply</button></noscript>
<span class="mut">click a column header to sort</span>
</form>
<table class="sortable"><thead><tr>
<th>CVE</th><th>Package</th><th>PID</th><th>Installed</th><th>Fixed in</th><th>Severity (CVSS)</th><th class="nosort">Exploit</th><th>State</th><th class="nosort">Triage</th>
</tr></thead><tbody>
{{range .Rows}}<tr class="{{if .Suppressed}}supp{{end}}">
<td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a>{{if .Running}} <span class="pill run">running</span>{{end}}{{template "reachBadge" .Reachability}}</td>
<td class="mono">{{.SourcePackage}}{{if .Ecosystem}}<span class="eco">{{.Ecosystem}}</span>{{end}}{{if .RunningBinaries}}<div class="usedby" title="running executables that map this package's code">used by: {{range $i, $b := .RunningBinaries}}{{if $i}}, {{end}}{{$b}}{{end}}</div>{{end}}</td>
<td class="mono" data-sort="{{if .Running}}{{.RunningPID}}{{else}}-1{{end}}">{{if and .Running .RunningPID}}{{.RunningPID}}{{else}}<span class="mut">—</span>{{end}}</td>
<td class="mono mut">{{.InstalledVersion}}</td>
<td class="mono">{{if .FixedVersion}}{{.FixedVersion}}{{else}}<span class="mut">no fix yet</span>{{end}}</td>
<td data-sort="{{.CVSSScore}}"><span class="pill {{sevclass .CVSSSeverity}}">{{.CVSSSeverity}}{{with score .CVSSScore}} {{.}}{{end}}</span></td>
<td>{{if .KEVListed}}<span class="kev">KEV</span> {{end}}{{with epss .EPSSScore}}<span class="epss">EPSS {{.}}</span>{{end}}</td>
<td>{{template "triageBadge" .}}</td>
<td class="triage">
<form method="post" action="/triage">
<input type="hidden" name="agent_id" value="{{$.Agent.ID}}"><input type="hidden" name="cve" value="{{.CVE}}">
<input type="hidden" name="source_package" value="{{.SourcePackage}}"><input type="hidden" name="ecosystem" value="{{.Ecosystem}}">
{{if .Suppressed}}<input type="hidden" name="return" value="agent">{{end}}
<select name="days" title="expiry (days) for snooze / accept"><option value="7">7d</option><option value="30">30d</option><option value="90">90d</option></select>
<input name="note" placeholder="note" maxlength="200">
<button name="action" value="acknowledged">Ack</button>
<button name="action" value="snoozed">Snooze</button>
<button name="action" value="risk_accepted">Accept</button>
<button name="action" value="muted">Mute</button>
<button name="action" value="active" class="clr">Clear</button>
</form>
</td>
</tr>{{else}}
<tr data-empty><td colspan="9" class="mut">No vulnerabilities found. 🎉</td></tr>
{{end}}</tbody></table>
{{template "foot" .}}{{end}}

{{define "reachBadge"}}{{if eq . "symbol_used"}} <span class="reach used" title="a running process imports the flaw's affected symbol">flaw used</span>{{else if eq . "loaded_unused"}} <span class="reach unused" title="library loaded but the affected symbol is never imported — likely not exercised">sym unused</span>{{end}}{{end}}

{{define "triageBadge"}}{{if eq .Effective "muted"}}<span class="tri muted">muted</span>{{else if eq .Effective "snoozed"}}<span class="tri snoozed">snoozed{{with .TriageUntil}} · {{date .}}{{end}}</span>{{else if eq .Effective "risk_accepted"}}<span class="tri accepted">risk-accepted{{with .TriageUntil}} · {{date .}}{{end}}</span>{{else if eq .Effective "acknowledged"}}<span class="tri ack">ack</span>{{else}}<span class="mut">&mdash;</span>{{end}}{{end}}

{{define "cves"}}{{template "head" .}}
<h1>Vulnerabilities</h1>
<p class="sub">{{.Total}} distinct CVE(s) across the fleet · click a column to sort · page {{.Page}}</p>
<table><thead><tr>
{{range .Cols}}<th class="{{.Class}}"><a class="sortlink" href="{{.Href}}">{{.Label}}{{.Arrow}}</a></th>{{end}}
</tr></thead><tbody>
{{range .CVEs}}<tr>
<td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a></td>
<td><span class="pill {{sevclass .CVSSSeverity}}">{{.CVSSSeverity}}{{with score .CVSSScore}} {{.}}{{end}}</span></td>
<td>{{if .KEVListed}}<span class="kev">KEV</span> {{end}}{{with epss .EPSSScore}}<span class="epss">EPSS {{.}}</span>{{end}}</td>
<td class="count">{{.AffectedHosts}}</td>
<td class="count">{{if .RunningHosts}}<span class="pill run">{{.RunningHosts}}</span>{{else}}0{{end}}</td>
<td class="mut">{{.Summary}}</td>
</tr>{{else}}
<tr><td colspan="6" class="mut">No vulnerabilities across the fleet. 🎉</td></tr>
{{end}}</tbody></table>
{{template "pager" .}}
{{template "foot" .}}{{end}}

{{define "cve"}}{{template "head" .}}
<a class="back" href="/cves">&larr; all vulnerabilities</a>
<h1 class="mono">{{.CVE}} <span class="pill {{sevclass .Enr.CVSSSeverity}}">{{.Enr.CVSSSeverity}}{{with score .Enr.CVSSScore}} {{.}}{{end}}</span>{{if .Enr.KEVListed}} <span class="kev">KEV</span>{{end}}</h1>
<p class="sub">
{{if .Enr.KEVListed}}<span class="kev">known exploited</span>{{if not .Enr.KEVDateAdded.IsZero}} · added {{date .Enr.KEVDateAdded}}{{end}}{{if not .Enr.KEVDueDate.IsZero}} · due {{date .Enr.KEVDueDate}}{{end}}{{if .Enr.KEVRansomware}} · ransomware{{end}} · {{end}}
{{with epss .Enr.EPSSScore}}EPSS {{.}} · {{end}}
{{if .Enr.Source}}source {{.Enr.Source}}{{else}}not enriched{{end}}
{{if .Enr.CVSSVector}} · <span class="mono vec">{{.Enr.CVSSVector}}</span>{{end}}
{{if not .Enr.Published.IsZero}} · published {{date .Enr.Published}}{{end}}
{{if not .Enr.Modified.IsZero}} · modified {{date .Enr.Modified}}{{end}}
</p>
{{if .Enr.Summary}}<p>{{.Enr.Summary}}</p>{{end}}
{{if .Enr.Aliases}}<p class="mut">Aliases: {{range $i, $a := .Enr.Aliases}}{{if $i}}, {{end}}<span class="mono">{{$a}}</span>{{end}}</p>{{end}}
<h1 style="font-size:15px;margin-top:20px">Affected hosts ({{len .Hosts}})</h1>
<table><thead><tr>
<th>Host</th><th>OS</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>State</th>
</tr></thead><tbody>
{{range .Hosts}}<tr>
<td class="mono"><a href="/agents/{{.AgentID}}">{{.Hostname}}</a>{{if .Running}} <span class="pill run">running</span>{{end}}{{template "reachBadge" .Reachability}}</td>
<td class="mut">{{.OSID}} {{.OSVersionID}}</td>
<td class="mono">{{.SourcePackage}}{{if .Ecosystem}}<span class="eco">{{.Ecosystem}}</span>{{end}}</td>
<td class="mono mut">{{.InstalledVersion}}</td>
<td class="mono">{{if .FixedVersion}}{{.FixedVersion}}{{else}}<span class="mut">no fix yet</span>{{end}}</td>
<td class="mut">{{.Status}}</td>
</tr>{{end}}</tbody></table>
{{if .Advs}}<h1 style="font-size:15px;margin-top:20px">Tracker advisories ({{len .Advs}})</h1>
<table><thead><tr>
<th>Distro / release</th><th>Package</th><th>Status</th><th>Fixed in</th><th>Urgency</th>
</tr></thead><tbody>
{{range .Advs}}<tr>
<td>{{if eq (distro .Release) "ubuntu"}}<span class="tag">ubuntu</span> {{else if eq (distro .Release) "debian"}}<span class="tag">debian</span> {{end}}<span class="mono">{{.Release}}</span></td>
<td class="mono">{{.SourcePackage}}</td>
<td>{{if eq .Status "resolved"}}<span class="tri ack">resolved</span>{{else}}<span class="mut">{{.Status}}</span>{{end}}</td>
<td class="mono">{{if .FixedVersion}}{{.FixedVersion}}{{else}}<span class="mut">no fix</span>{{end}}</td>
<td class="mut">{{if .Urgency}}{{.Urgency}}{{else}}&mdash;{{end}}</td>
</tr>{{end}}</tbody></table>{{end}}
{{if .Enr.References}}<h1 style="font-size:15px;margin-top:20px">References</h1>
<div class="refs">{{range .Enr.References}}<a href="{{.}}" rel="noreferrer noopener" target="_blank">{{.}}</a>{{end}}</div>{{end}}
{{template "foot" .}}{{end}}

{{define "catalog_cves"}}{{template "head" .}}
<h1>Catalog — Vulnerabilities</h1>
<p class="sub"><a href="/catalog">Vulnerabilities</a> · <a href="/catalog/advisories">Tracker advisories</a> — browsing all enriched CVE records</p>
<form method="get" action="/catalog" class="search">
<input name="q" value="{{.Q}}" placeholder="search CVE id or summary" autofocus>
<select name="severity"><option value="">any severity</option>
{{range $s := (list "CRITICAL" "HIGH" "MEDIUM" "LOW")}}<option value="{{$s}}"{{if eq $s $.Severity}} selected{{end}}>{{$s}}</option>{{end}}</select>
<label class="chk"><input type="checkbox" name="kev" value="1"{{if .KEV}} checked{{end}}> KEV only</label>
<button>Search</button>
</form>
<p class="sub">{{.Total}} match(es){{if or .Q .Severity .KEV}} · <a href="/catalog">clear</a>{{end}} · <span class="mut">click a column header to sort the page</span></p>
<table class="sortable"><thead><tr>
<th>ID</th><th>Severity (CVSS)</th><th class="nosort">Exploit</th><th>Summary</th>
</tr></thead><tbody>
{{range .CVEs}}<tr>
<td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a></td>
<td data-sort="{{.CVSSScore}}"><span class="pill {{sevclass .CVSSSeverity}}">{{.CVSSSeverity}}{{with score .CVSSScore}} {{.}}{{end}}</span></td>
<td>{{if .KEVListed}}<span class="kev">KEV</span> {{end}}{{with epss .EPSSScore}}<span class="epss">EPSS {{.}}</span>{{end}}</td>
<td class="mut">{{if .Summary}}{{trunc .Summary 110}}{{else}}&mdash;{{end}}</td>
</tr>{{else}}
<tr data-empty><td colspan="4" class="mut">No CVE records match. Load enrichment with <span class="mono">enrich</span>/<span class="mono">refresh</span>.</td></tr>
{{end}}</tbody></table>
{{template "pager" .}}
{{template "foot" .}}{{end}}

{{define "catalog_advisories"}}{{template "head" .}}
<h1>Catalog — Tracker advisories</h1>
<p class="sub"><a href="/catalog">CVEs</a> · <a href="/catalog/advisories">Tracker advisories</a> — Debian + Ubuntu security data</p>
<form method="get" action="/catalog/advisories" class="search">
<input name="q" value="{{.Q}}" placeholder="search CVE, package, or description" autofocus>
<input name="pkg" value="{{.Pkg}}" placeholder="package">
<select name="distro"><option value="">any distro</option>
{{range $s := (list "debian" "ubuntu")}}<option value="{{$s}}"{{if eq $s $.Distro}} selected{{end}}>{{$s}}</option>{{end}}</select>
<select name="release"><option value="">any release</option>
{{range .Releases}}<option value="{{.}}"{{if eq . $.Release}} selected{{end}}>{{.}}</option>{{end}}</select>
<select name="status"><option value="">any status</option>
{{range $s := (list "resolved" "open")}}<option value="{{$s}}"{{if eq $s $.Status}} selected{{end}}>{{$s}}</option>{{end}}</select>
<button>Search</button>
</form>
<p class="sub">{{.Total}} advisory row(s){{if or .Q .Pkg .Release .Status .Distro}} · <a href="/catalog/advisories">clear</a>{{end}}</p>
<table><thead><tr>
<th>ID</th><th>Distro / release</th><th>Package</th><th>Status</th><th>Fixed in</th><th>Urgency</th>
</tr></thead><tbody>
{{range .Rows}}<tr>
<td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a></td>
<td>{{if .Distro}}<span class="tag">{{.Distro}}</span> {{end}}<span class="mono">{{.Release}}</span></td>
<td class="mono">{{.SourcePackage}}</td>
<td>{{if eq .Status "resolved"}}<span class="tri ack">resolved</span>{{else}}<span class="mut">{{.Status}}</span>{{end}}</td>
<td class="mono">{{if .FixedVersion}}{{.FixedVersion}}{{else}}<span class="mut">no fix</span>{{end}}</td>
<td class="mut">{{if .Urgency}}{{.Urgency}}{{else}}&mdash;{{end}}</td>
</tr>{{else}}
<tr><td colspan="6" class="mut">No advisories match. Load data with <span class="mono">ingest --distro both</span>.</td></tr>
{{end}}</tbody></table>
{{template "pager" .}}
{{template "foot" .}}{{end}}

{{define "pager"}}{{if or .HasPrev .HasNext}}<div class="pager">
{{if .HasPrev}}<a href="{{pageurl .Query (dec .Page)}}">&larr; prev</a>{{else}}<span class="mut">&larr; prev</span>{{end}}
<span class="mut">page {{.Page}}</span>
{{if .HasNext}}<a href="{{pageurl .Query (inc .Page)}}">next &rarr;</a>{{else}}<span class="mut">next &rarr;</span>{{end}}
</div>{{end}}{{end}}

{{define "admin_users"}}{{template "head" .}}
<h1>Admin — Users</h1>
<p class="sub">Dashboard accounts. Every user has full access to the application; any user can manage accounts here. Passwords are stored as salted PBKDF2 hashes.</p>
{{if .Msg}}<p class="banner ok">{{.Msg}}</p>{{end}}
{{if .Err}}<p class="banner err">{{.Err}}</p>{{end}}
{{if .Bootstrap}}<p class="banner warn">No users yet — you're signed in with the bootstrap credential. Create your first user below; once a user exists, the bootstrap credential stops working.</p>{{end}}
<table><thead><tr><th>Username</th><th>Created</th><th>Updated</th><th>Actions</th></tr></thead><tbody>
{{range .Users}}<tr>
<td class="mono">{{.Username}}{{if eq .Username $.Me}} <span class="tag">you</span>{{end}}</td>
<td class="mut">{{since .CreatedAt}}</td>
<td class="mut">{{since .UpdatedAt}}</td>
<td class="triage">
<form method="post" action="/admin/users/{{.Username}}">
<input type="hidden" name="action" value="password"><input type="password" name="password" placeholder="new password" minlength="8">
<button>Reset password</button>
</form>
<form method="post" action="/admin/users/{{.Username}}" onsubmit="return confirm('Delete user {{.Username}}?')">
<input type="hidden" name="action" value="delete"><button class="clr">Delete</button>
</form>
</td>
</tr>{{else}}
<tr><td colspan="4" class="mut">No users defined.</td></tr>
{{end}}</tbody></table>
<h1 style="font-size:15px;margin-top:20px">Add user</h1>
<form method="post" action="/admin/users" class="search">
<input name="username" placeholder="username" required>
<input type="password" name="password" placeholder="password (min 8 chars)" minlength="8" required>
<button>Create user</button>
</form>
{{template "foot" .}}{{end}}

{{define "about"}}{{template "head" .}}
<h1>About</h1>
<div class="about">
<div class="hd"><img src="/favicon.svg" alt="Cobra"><div><div class="nm">Cobra</div><div class="ver">Release {{.Version}}</div></div></div>
<p>Cobra is a runtime vulnerability-management platform for Debian, Ubuntu and Red Hat family systems: a low-footprint agent (cobraagent) reports inventory, and the Cobra server matches it against distribution security data plus NVD/OSV/KEV/EPSS enrichment.</p>
<dl>
<dt>Release</dt><dd>{{.Version}}</dd>
<dt>Designed by</dt><dd>Stéphane Maubian</dd>
<dt>License</dt><dd>Apache License 2.0</dd>
<dt>Built by</dt><dd>Claude</dd>
</dl>
</div>
{{template "foot" .}}{{end}}

{{define "audit"}}{{template "head" .}}
<h1>Triage audit log</h1>
<p class="sub">most recent {{len .Events}} triage action(s)</p>
<table><thead><tr>
<th>When</th><th>Actor</th><th>Action</th><th>Host</th><th>CVE</th><th>Package</th><th>Until</th><th>Note</th>
</tr></thead><tbody>
{{range .Events}}<tr>
<td class="mut">{{since .When}}</td>
<td>{{.Actor}}</td>
<td>{{template "actionBadge" .}}</td>
<td class="mono"><a href="/agents/{{.AgentID}}">{{.Hostname}}</a></td>
<td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a></td>
<td class="mono">{{.SourcePackage}}{{if .Ecosystem}}<span class="eco">{{.Ecosystem}}</span>{{end}}</td>
<td class="mut">{{if not .Until.IsZero}}{{date .Until}}{{else}}&mdash;{{end}}</td>
<td class="mut">{{if .Note}}{{.Note}}{{else}}&mdash;{{end}}</td>
</tr>{{else}}
<tr><td colspan="8" class="mut">No triage actions yet.</td></tr>
{{end}}</tbody></table>
{{template "foot" .}}{{end}}

{{define "actionBadge"}}{{if eq .Action "muted"}}<span class="tri muted">muted</span>{{else if eq .Action "snoozed"}}<span class="tri snoozed">snoozed</span>{{else if eq .Action "risk_accepted"}}<span class="tri accepted">risk-accepted</span>{{else if eq .Action "acknowledged"}}<span class="tri ack">ack</span>{{else}}<span class="tri clr">cleared</span>{{end}}{{end}}

{{define "trends"}}{{template "head" .}}
<h1>Trends</h1>
<p class="sub">Open findings over the last 30 days, derived from finding history</p>
<div class="cards">
<div class="card"><div class="n">{{.Stats.OpenTotal}}</div><div class="l">open now</div></div>
<div class="card"><div class="n">{{with index .Stats.OpenBySeverity "CRITICAL"}}{{.}}{{else}}0{{end}}</div><div class="l">critical open</div></div>
<div class="card"><div class="n">{{.Stats.OpenRunning}}</div><div class="l">running &amp; open</div></div>
<div class="card"><div class="n">{{.Stats.Appeared7d}}</div><div class="l">appeared (7d)</div></div>
<div class="card"><div class="n">{{.Stats.Resolved7d}}</div><div class="l">resolved (7d)</div></div>
<div class="card"><div class="n">{{.Stats.Resolved30d}}</div><div class="l">resolved (30d)</div></div>
</div>
<div class="chart">
<svg viewBox="0 0 {{.Chart.W}} {{.Chart.H}}" width="100%" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Open findings per day by severity">
<line x1="0" y1="{{.Chart.Base}}" x2="{{.Chart.W}}" y2="{{.Chart.Base}}" stroke="#242833"/>
{{range .Chart.Bars}}{{$b := .}}
{{range .Segs}}<rect class="{{.Class}}" x="{{$b.X}}" y="{{.Y}}" width="{{$b.W}}" height="{{.H}}"/>{{end}}
{{if .Label}}<text x="{{.X}}" y="{{$.Chart.Base}}" dy="13">{{.Label}}</text>{{end}}
{{end}}
</svg>
<div class="legend">
<span><span class="dot" style="background:var(--crit)"></span>Critical</span>
<span><span class="dot" style="background:var(--hi)"></span>High</span>
<span><span class="dot" style="background:var(--md)"></span>Medium</span>
<span><span class="dot" style="background:var(--lo)"></span>Low</span>
<span class="mut">peak {{.Chart.MaxTotal}}/day</span>
</div>
</div>
<h1 style="font-size:15px">Recent activity</h1>
<table><thead><tr><th>When</th><th>Event</th><th>Host</th><th>CVE</th><th>Package</th><th>Severity</th></tr></thead><tbody>
{{range .Activity}}<tr>
<td class="mut">{{since .When}}</td>
<td>{{if eq .Kind "resolved"}}<span class="rs">✔ resolved</span>{{else}}<span class="ap">▲ appeared</span>{{end}}</td>
<td class="mono"><a href="/agents/{{.AgentID}}">{{.Hostname}}</a></td>
<td class="mono"><a href="/cves/{{.CVE}}">{{.CVE}}</a></td>
<td class="mono">{{.SourcePackage}}</td>
<td><span class="pill {{sevclass .CVSSSeverity}}">{{.CVSSSeverity}}</span></td>
</tr>{{else}}
<tr><td colspan="6" class="mut">No activity yet.</td></tr>
{{end}}</tbody></table>
{{template "foot" .}}{{end}}
`
