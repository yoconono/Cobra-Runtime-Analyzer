// Package api implements the agent-facing HTTP endpoints: enrollment (exchange
// a registration token for a durable credential) and report ingestion (which
// runs the matcher and stores findings).
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/match"
	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/notify"
	"github.com/yourorg/cve-fleet/server/internal/osvmatch"
	"github.com/yourorg/cve-fleet/server/internal/store"
	"github.com/yourorg/cve-fleet/server/internal/tracker"
)

type API struct {
	store store.Store
	log   *log.Logger
	opt   match.Options
	alert notify.Engine // optional
}

func New(s store.Store, logger *log.Logger, opt match.Options) *API {
	return &API{store: s, log: logger, opt: opt}
}

// WithAlerts attaches an alert engine (nil disables alerting).
func (a *API) WithAlerts(e notify.Engine) *API {
	a.alert = e
	return a
}

// Routes registers the API endpoints on mux.
func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/agents/enroll", a.handleEnroll)
	mux.HandleFunc("POST /api/v1/agents/{id}/report", a.handleReport)
}

func (a *API) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req model.EnrollRequest
	if !decode(w, r, &req) {
		return
	}
	if req.EnrollmentToken == "" || req.MachineID == "" {
		httpError(w, http.StatusBadRequest, "enrollment_token and machine_id are required")
		return
	}
	if err := a.store.ConsumeEnrollmentToken(req.EnrollmentToken); err != nil {
		httpError(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}

	apiToken := newToken()
	agent := model.Agent{
		ID:           "agent-" + newID(),
		MachineID:    req.MachineID,
		Hostname:     req.Hostname,
		OSID:         req.OSID,
		OSVersionID:  req.OSVersionID,
		AgentVersion: req.AgentVersion,
		APITokenHash: hashToken(apiToken),
	}
	saved, err := a.store.UpsertAgent(agent)
	if err != nil {
		a.log.Printf("enroll: upsert agent: %v", err)
		httpError(w, http.StatusInternalServerError, "could not register agent")
		return
	}
	a.log.Printf("enrolled agent %s (%s, %s/%s)", saved.ID, saved.Hostname, saved.OSID, saved.OSVersionID)
	// Tags supplied at provisioning are applied immediately, before the first report.
	if len(req.Tags) > 0 {
		if err := a.store.SetReportedTags(saved.ID, req.Tags); err != nil {
			a.log.Printf("enroll: set tags for %s: %v", saved.ID, err)
		} else {
			a.log.Printf("enroll: applied %d provisioning tag(s) to %s", len(req.Tags), saved.ID)
		}
	}
	writeJSON(w, http.StatusOK, model.EnrollResponse{AgentID: saved.ID, APIToken: apiToken})
}

func (a *API) handleReport(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")

	agent, err := a.authAgent(r)
	if err != nil {
		httpError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if subtle.ConstantTimeCompare([]byte(agent.ID), []byte(agentID)) != 1 {
		httpError(w, http.StatusForbidden, "token does not match agent id")
		return
	}

	var rep model.Report
	if !decode(w, r, &rep) {
		return
	}

	osID := firstNonEmpty(rep.Host.OSID, agent.OSID)
	verID := firstNonEmpty(rep.Host.OSVersionID, agent.OSVersionID)
	release := tracker.Codename(osID, verID)
	family := tracker.Family(osID)
	findings := match.Match(rep.Packages, release, family, a.store, a.opt)

	// Language/SBOM findings: match reported pip/npm/Go deps against the OSV index.
	if len(rep.LanguagePackages) > 0 {
		findings = append(findings, osvmatch.Match(rep.LanguagePackages, a.store)...)
	}

	// Reachability: refine each finding from "library loaded" to whether the
	// flaw's affected symbol is actually imported by a running process.
	a.classifyReachability(findings, rep)

	// Observation time: prefer the agent's collection time (clamped to now) so
	// backfilled/queued reports land on the right day; fall back to now.
	observedAt := time.Now().UTC()
	if !rep.CollectedAt.IsZero() && rep.CollectedAt.Before(observedAt) {
		observedAt = rep.CollectedAt.UTC()
	}
	appeared, resolved, err := a.store.ReconcileFindings(agent.ID, findings, observedAt)
	if err != nil {
		a.log.Printf("report: store findings: %v", err)
		httpError(w, http.StatusInternalServerError, "could not store findings")
		return
	}
	_ = a.store.TouchAgent(agent.ID)
	if len(rep.Tags) > 0 {
		_ = a.store.SetReportedTags(agent.ID, rep.Tags)
	}

	// Alert on newly-appeared and newly-resolved findings. Severity is joined
	// from enrichment here, since reconcile stores raw findings. Findings the
	// operator has triaged away (muted / snoozed / risk-accepted) don't alert.
	if a.alert != nil && (len(appeared) > 0 || len(resolved) > 0) {
		appeared = a.dropSuppressed(agent.ID, appeared)
		resolved = a.dropSuppressed(agent.ID, resolved)
		a.enrichSeverity(appeared)
		a.enrichSeverity(resolved)
		a.alert.Handle(agent.ID, agent.Hostname, appeared, resolved)
	}

	a.log.Printf("report from %s (%s): %d os packages, %d language deps, %d findings",
		agent.ID, agent.Hostname, len(rep.Packages), len(rep.LanguagePackages), len(findings))
	writeJSON(w, http.StatusOK, model.ReportResponse{Received: true, VulnerabilitiesFound: len(findings)})
}

// classifyReachability sets finding.Reachability using the report's symbol map
// (which functions running processes import, per library) and each CVE's affected
// symbols. Findings whose package doesn't back a running process stay "installed";
// with no symbol data they're "loaded".
func (a *API) classifyReachability(findings []model.Finding, rep model.Report) {
	// package -> set of used symbols (union across the sonames it owns)
	pkgSyms := map[string]map[string]struct{}{}
	for soname, pkg := range rep.LibraryOwners {
		set := pkgSyms[pkg]
		if set == nil {
			set = map[string]struct{}{}
			pkgSyms[pkg] = set
		}
		for _, s := range rep.RunningSymbols[soname] {
			set[s] = struct{}{}
		}
	}
	affectedCache := map[string][]string{}
	affectedFor := func(cve string) []string {
		if v, ok := affectedCache[cve]; ok {
			return v
		}
		var syms []string
		if e, ok, _ := a.store.EnrichmentFor(cve); ok {
			syms = e.AffectedSymbols
		}
		affectedCache[cve] = syms
		return syms
	}
	for i := range findings {
		f := &findings[i]
		var used []string
		if set, ok := pkgSyms[f.SourcePackage]; ok {
			used = make([]string, 0, len(set))
			for s := range set {
				used = append(used, s)
			}
		}
		f.Reachability = model.Reachability(f.Running, affectedFor(f.CVE), used)
		if bins := rep.RunningBinaries[f.SourcePackage]; len(bins) > 0 {
			f.RunningBinaries = bins
		}
		if pid := rep.RunningPIDs[f.SourcePackage]; pid > 0 {
			f.RunningPID = pid
		}
	}
}

// dropSuppressed removes findings the operator has triaged away (effective
// muted / snoozed / risk-accepted), so they don't generate alerts.
func (a *API) dropSuppressed(agentID string, fs []model.Finding) []model.Finding {
	if len(fs) == 0 {
		return fs
	}
	now := time.Now()
	out := make([]model.Finding, 0, len(fs))
	for _, f := range fs {
		if tr, ok, _ := a.store.TriageFor(agentID, f.CVE, f.SourcePackage, f.Ecosystem); ok {
			if model.IsSuppressed(model.EffectiveTriage(tr.State, tr.Until, now)) {
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// enrichSeverity fills CVSS severity/score and exploitation signals on findings
// from the enrichment store (needed for alert filtering/routing).
func (a *API) enrichSeverity(fs []model.Finding) {
	for i := range fs {
		if e, ok, _ := a.store.EnrichmentFor(fs[i].CVE); ok {
			fs[i].CVSSSeverity = e.CVSSSeverity
			fs[i].CVSSScore = e.CVSSScore
			fs[i].KEVListed = e.KEVListed
			fs[i].EPSSScore = e.EPSSScore
			fs[i].EPSSPercentile = e.EPSSPercentile
		}
		if fs[i].CVSSSeverity == "" {
			fs[i].CVSSSeverity = "UNKNOWN"
		}
	}
}

func (a *API) authAgent(r *http.Request) (model.Agent, error) {
	auth := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(auth, "Bearer ")
	if !ok || tok == "" {
		return model.Agent{}, errors.New("missing bearer token")
	}
	return a.store.AgentByTokenHash(hashToken(tok))
}

// --- helpers ---

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20) // 32 MiB cap
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		httpError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func newToken() string { return randHex(32) } // 256-bit
func newID() string    { return randHex(8) }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return hex.EncodeToString(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
