package store

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Memory is a thread-safe in-memory Store. Data is lost on restart; intended
// for tests, demos, and small ephemeral deployments.
type Memory struct {
	mu       sync.RWMutex
	tokens   map[string]*EnrollmentToken
	agents   map[string]*model.Agent // by ID
	byMachine map[string]string      // machine_id -> agent ID
	byToken  map[string]string       // api token hash -> agent ID
	findings map[string][]model.Finding
	tracker  map[string][]model.Advisory // key: source|release
	enrich   map[string]model.Enrichment // key: CVE/vuln id
	osvPkg   map[string][]model.LangAdvisory // key: ecosystem|name
	triage   map[string]model.Triage         // key: agent|cve|source|ecosystem
	audit    []model.TriageEvent
	users    map[string]model.User           // key: username
}

func NewMemory() *Memory {
	return &Memory{
		tokens:    map[string]*EnrollmentToken{},
		agents:    map[string]*model.Agent{},
		byMachine: map[string]string{},
		byToken:   map[string]string{},
		findings:  map[string][]model.Finding{},
		tracker:   map[string][]model.Advisory{},
		enrich:    map[string]model.Enrichment{},
		osvPkg:    map[string][]model.LangAdvisory{},
		triage:    map[string]model.Triage{},
		users:     map[string]model.User{},
	}
}

func triageKey(agentID, cve, source, eco string) string {
	return agentID + "|" + cve + "|" + source + "|" + eco
}

func (m *Memory) CreateEnrollmentToken(t EnrollmentToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := t
	m.tokens[t.Token] = &c
	return nil
}

func (m *Memory) ConsumeEnrollmentToken(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[token]
	if !ok || t.Revoked {
		return ErrTokenInvalid
	}
	if t.MaxUses > 0 && t.Uses >= t.MaxUses {
		return ErrTokenInvalid
	}
	t.Uses++
	return nil
}

func (m *Memory) UpsertAgent(a model.Agent) (model.Agent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := m.byMachine[a.MachineID]; ok {
		a.ID = id // reuse existing identity for this machine
		if old := m.agents[id]; old != nil {
			delete(m.byToken, old.APITokenHash) // rotate token
			a.EnrolledAt = old.EnrolledAt
		}
	}
	if a.EnrolledAt.IsZero() {
		a.EnrolledAt = time.Now().UTC()
	}
	a.LastSeenAt = time.Now().UTC()
	c := a
	m.agents[a.ID] = &c
	m.byMachine[a.MachineID] = a.ID
	m.byToken[a.APITokenHash] = a.ID
	return c, nil
}

func (m *Memory) AgentByTokenHash(hash string) (model.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.byToken[hash]
	if !ok {
		return model.Agent{}, ErrNotFound
	}
	return *m.agents[id], nil
}

func (m *Memory) GetAgent(id string) (model.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.agents[id]
	if !ok {
		return model.Agent{}, ErrNotFound
	}
	return *a, nil
}

func (m *Memory) TouchAgent(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.agents[id]
	if !ok {
		return ErrNotFound
	}
	a.LastSeenAt = time.Now().UTC()
	return nil
}

func (m *Memory) ListAgents() ([]model.AgentSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	out := make([]model.AgentSummary, 0, len(m.agents))
	for id, a := range m.agents {
		s := model.AgentSummary{Agent: *a, SeverityCounts: map[string]int{}}
		for _, f := range m.findings[id] {
			if !f.ResolvedAt.IsZero() {
				continue // skip resolved episodes
			}
			if m.isSuppressed(id, f, now) {
				continue // triaged away (muted / snoozed / risk-accepted)
			}
			s.FindingCount++
			if f.Running {
				s.RunningCount++
			}
			sev := "UNKNOWN"
			if e, ok := m.enrich[f.CVE]; ok && e.CVSSSeverity != "" {
				sev = e.CVSSSeverity
			}
			if e, ok := m.enrich[f.CVE]; ok && e.KEVListed {
				s.KEVCount++
			}
			s.SeverityCounts[sev]++
		}
		out = append(out, s)
	}
	return out, nil
}

func (m *Memory) ReconcileFindings(agentID string, current []model.Finding, observedAt time.Time) ([]model.Finding, []model.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	existing := m.findings[agentID]

	curByKey := map[string]model.Finding{}
	order := []string{}
	for _, f := range current {
		k := f.CVE + "|" + f.SourcePackage + "|" + f.Ecosystem
		if _, ok := curByKey[k]; !ok {
			order = append(order, k)
		}
		curByKey[k] = f
	}
	openIdx := map[string]int{}
	for i := range existing {
		if existing[i].ResolvedAt.IsZero() {
			openIdx[existing[i].CVE+"|"+existing[i].SourcePackage+"|"+existing[i].Ecosystem] = i
		}
	}
	// Resolve open episodes no longer present; collect them.
	var resolved []model.Finding
	for k, i := range openIdx {
		if _, ok := curByKey[k]; !ok {
			existing[i].ResolvedAt = observedAt
			resolved = append(resolved, existing[i])
		}
	}
	// Insert or update current findings; collect newly-opened ones.
	var appeared []model.Finding
	for _, k := range order {
		f := curByKey[k]
		if i, ok := openIdx[k]; ok {
			f.FirstSeen = existing[i].FirstSeen
			f.LastSeen = observedAt
			f.ResolvedAt = time.Time{}
			existing[i] = f
		} else {
			f.FirstSeen = observedAt
			f.LastSeen = observedAt
			f.ResolvedAt = time.Time{}
			existing = append(existing, f)
			appeared = append(appeared, f)
		}
	}
	m.findings[agentID] = existing
	return appeared, resolved, nil
}

func (m *Memory) ListFindings(agentID string) ([]model.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Finding
	for _, f := range m.findings[agentID] {
		if !f.ResolvedAt.IsZero() {
			continue // open findings only
		}
		if e, ok := m.enrich[f.CVE]; ok {
			f.CVSSScore, f.CVSSSeverity, f.CVSSVector = e.CVSSScore, e.CVSSSeverity, e.CVSSVector
			f.KEVListed, f.EPSSScore, f.EPSSPercentile = e.KEVListed, e.EPSSScore, e.EPSSPercentile
		}
		if tr, ok := m.triage[triageKey(agentID, f.CVE, f.SourcePackage, f.Ecosystem)]; ok {
			f.TriageState, f.TriageUntil, f.TriageNote = tr.State, tr.Until, tr.Note
		}
		out = append(out, f)
	}
	return out, nil
}

func (m *Memory) FindingLifecycles() ([]model.FindingLifecycle, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.FindingLifecycle
	for agentID, eps := range m.findings {
		hostname := agentID
		if ag := m.agents[agentID]; ag != nil {
			hostname = ag.Hostname
		}
		for _, f := range eps {
			sev := "UNKNOWN"
			if e, ok := m.enrich[f.CVE]; ok && e.CVSSSeverity != "" {
				sev = e.CVSSSeverity
			}
			out = append(out, model.FindingLifecycle{
				AgentID: agentID, Hostname: hostname, CVE: f.CVE, SourcePackage: f.SourcePackage,
				CVSSSeverity: sev, Running: f.Running,
				FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, ResolvedAt: f.ResolvedAt,
			})
		}
	}
	return out, nil
}

func (m *Memory) ListCVEs() ([]model.CVESummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	type agg struct{ hosts, running map[string]bool }
	byCVE := map[string]*agg{}
	for agentID, fs := range m.findings {
		for _, f := range fs {
			if !f.ResolvedAt.IsZero() {
				continue
			}
			if m.isSuppressed(agentID, f, now) {
				continue
			}
			a := byCVE[f.CVE]
			if a == nil {
				a = &agg{hosts: map[string]bool{}, running: map[string]bool{}}
				byCVE[f.CVE] = a
			}
			a.hosts[agentID] = true
			if f.Running {
				a.running[agentID] = true
			}
		}
	}
	out := make([]model.CVESummary, 0, len(byCVE))
	for cve, a := range byCVE {
		s := model.CVESummary{CVE: cve, CVSSSeverity: "UNKNOWN", AffectedHosts: len(a.hosts), RunningHosts: len(a.running)}
		if e, ok := m.enrich[cve]; ok {
			s.CVSSSeverity, s.CVSSScore, s.Summary = e.CVSSSeverity, e.CVSSScore, e.Summary
			s.KEVListed, s.EPSSScore = e.KEVListed, e.EPSSScore
		}
		out = append(out, s)
	}
	return out, nil
}

func (m *Memory) HostsForCVE(cve string) ([]model.CVEHost, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.CVEHost
	for agentID, fs := range m.findings {
		ag := m.agents[agentID]
		if ag == nil {
			continue
		}
		for _, f := range fs {
			if f.CVE != cve || !f.ResolvedAt.IsZero() {
				continue
			}
			out = append(out, model.CVEHost{
				AgentID: agentID, Hostname: ag.Hostname, OSID: ag.OSID, OSVersionID: ag.OSVersionID,
				SourcePackage: f.SourcePackage, Ecosystem: f.Ecosystem, InstalledVersion: f.InstalledVersion,
				FixedVersion: f.FixedVersion, Running: f.Running, Reachability: f.Reachability, Status: f.Status,
			})
		}
	}
	return out, nil
}

func (m *Memory) ReplaceTracker(advs []model.Advisory) error {
	idx := make(map[string][]model.Advisory, len(advs)/4+1)
	for _, a := range advs {
		k := a.SourcePackage + "|" + a.Release
		idx[k] = append(idx[k], a)
	}
	m.mu.Lock()
	m.tracker = idx
	m.mu.Unlock()
	return nil
}

// MergeTracker upserts advisories by (source_package, cve, release) without
// discarding rows already present — an additive load for restarts/refreshes.
func (m *Memory) MergeTracker(advs []model.Advisory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tracker == nil {
		m.tracker = map[string][]model.Advisory{}
	}
	for _, a := range advs {
		k := a.SourcePackage + "|" + a.Release
		bucket := m.tracker[k]
		found := false
		for i := range bucket {
			if bucket[i].CVE == a.CVE {
				bucket[i] = a // update in place
				found = true
				break
			}
		}
		if !found {
			bucket = append(bucket, a)
		}
		m.tracker[k] = bucket
	}
	return nil
}

func (m *Memory) ForPackage(src, release string) []model.Advisory {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.tracker[src+"|"+release]
}

func (m *Memory) TrackerCount() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, v := range m.tracker {
		n += len(v)
	}
	return n, nil
}

func (m *Memory) DistinctTrackerCVEs() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := map[string]struct{}{}
	for _, advs := range m.tracker {
		for _, a := range advs {
			set[a.CVE] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out, nil
}

func (m *Memory) UpsertEnrichment(e model.Enrichment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enrich[e.CVE] = e
	return nil
}

func (m *Memory) EnrichmentFor(cve string) (model.Enrichment, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.enrich[cve]
	return e, ok, nil
}

func (m *Memory) UpsertKEV(cve string, dateAdded, dueDate time.Time, ransomware bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.enrich[cve]
	e.CVE = cve
	if e.CVSSSeverity == "" {
		e.CVSSSeverity = "UNKNOWN"
	}
	e.KEVListed, e.KEVDateAdded, e.KEVDueDate, e.KEVRansomware = true, dateAdded, dueDate, ransomware
	m.enrich[cve] = e
	return nil
}

func (m *Memory) UpsertEPSS(cve string, score, percentile float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.enrich[cve]
	e.CVE = cve
	if e.CVSSSeverity == "" {
		e.CVSSSeverity = "UNKNOWN"
	}
	e.EPSSScore, e.EPSSPercentile = score, percentile
	m.enrich[cve] = e
	return nil
}

func (m *Memory) UpsertAffectedSymbols(cve string, symbols []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.enrich[cve]
	e.CVE = cve
	if e.CVSSSeverity == "" {
		e.CVSSSeverity = "UNKNOWN"
	}
	e.AffectedSymbols = symbols
	m.enrich[cve] = e
	return nil
}

func (m *Memory) EnrichedCVEs() (map[string]bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]bool, len(m.enrich))
	for c := range m.enrich {
		out[c] = true
	}
	return out, nil
}

func (m *Memory) EnrichmentCount() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.enrich), nil
}

// MergeOSVPackages upserts advisories by (ecosystem,name,vuln_id), keeping rows
// already present (incremental load).
func (m *Memory) MergeOSVPackages(advs []model.LangAdvisory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.osvPkg == nil {
		m.osvPkg = map[string][]model.LangAdvisory{}
	}
	for _, a := range advs {
		k := a.Ecosystem + "|" + a.Package
		bucket := m.osvPkg[k]
		found := false
		for i := range bucket {
			if bucket[i].VulnID == a.VulnID {
				bucket[i] = a
				found = true
				break
			}
		}
		if !found {
			bucket = append(bucket, a)
		}
		m.osvPkg[k] = bucket
	}
	return nil
}

func (m *Memory) ReplaceOSVPackages(advs []model.LangAdvisory) error {
	idx := make(map[string][]model.LangAdvisory)
	for _, a := range advs {
		k := a.Ecosystem + "|" + a.Package
		idx[k] = append(idx[k], a)
	}
	m.mu.Lock()
	m.osvPkg = idx
	m.mu.Unlock()
	return nil
}

func (m *Memory) ForLangPackage(ecosystem, name string) []model.LangAdvisory {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.osvPkg[ecosystem+"|"+name]
}

func (m *Memory) OSVPackageCount() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, v := range m.osvPkg {
		n += len(v)
	}
	return n, nil
}

func (m *Memory) Close() error { return nil }

func (m *Memory) SetAgentTags(agentID string, tags map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.agents[agentID]
	if a == nil {
		return ErrNotFound
	}
	a.Tags = tags
	return nil
}

func (m *Memory) SetReportedTags(agentID string, tags map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.agents[agentID]
	if a == nil {
		return ErrNotFound
	}
	a.ReportedTags = tags
	return nil
}

// isSuppressed reports whether a finding is hidden by an effective triage state.
// Caller holds at least a read lock.
func (m *Memory) isSuppressed(agentID string, f model.Finding, now time.Time) bool {
	tr, ok := m.triage[triageKey(agentID, f.CVE, f.SourcePackage, f.Ecosystem)]
	if !ok {
		return false
	}
	return model.IsSuppressed(model.EffectiveTriage(tr.State, tr.Until, now))
}

func (m *Memory) SetTriage(t model.Triage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t.UpdatedAt = time.Now().UTC()
	key := triageKey(t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem)
	if t.State == "" || t.State == model.TriageActive {
		delete(m.triage, key)
	} else {
		m.triage[key] = t
	}
	hostname := t.AgentID
	if a := m.agents[t.AgentID]; a != nil {
		hostname = a.Hostname
	}
	m.audit = append(m.audit, model.TriageEvent{
		When: t.UpdatedAt, Actor: t.Actor, Action: t.State, AgentID: t.AgentID, Hostname: hostname,
		CVE: t.CVE, SourcePackage: t.SourcePackage, Ecosystem: t.Ecosystem, Until: t.Until, Note: t.Note,
	})
	return nil
}

func (m *Memory) TriageFor(agentID, cve, source, eco string) (model.Triage, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.triage[triageKey(agentID, cve, source, eco)]
	return t, ok, nil
}

func (m *Memory) AuditLog(limit int) ([]model.TriageEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.audit)
	out := make([]model.TriageEvent, 0, n)
	for i := n - 1; i >= 0; i-- { // newest first
		out = append(out, m.audit[i])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) SearchAdvisories(q AdvisoryQuery) ([]model.Advisory, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	text := strings.ToLower(q.Text)
	var all []model.Advisory
	for _, advs := range m.tracker {
		for _, a := range advs {
			if q.Release != "" && a.Release != q.Release {
				continue
			}
			if q.SourcePackage != "" && !strings.Contains(strings.ToLower(a.SourcePackage), strings.ToLower(q.SourcePackage)) {
				continue
			}
			if q.Status != "" && a.Status != q.Status {
				continue
			}
			if text != "" && !strings.Contains(strings.ToLower(a.CVE), text) &&
				!strings.Contains(strings.ToLower(a.SourcePackage), text) &&
				!strings.Contains(strings.ToLower(a.Description), text) {
				continue
			}
			all = append(all, a)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CVE != all[j].CVE {
			return all[i].CVE > all[j].CVE // newest CVE ids first
		}
		if all[i].SourcePackage != all[j].SourcePackage {
			return all[i].SourcePackage < all[j].SourcePackage
		}
		return all[i].Release < all[j].Release
	})
	total := len(all)
	return page(all, q.Offset, clampLimit(q.Limit)), total, nil
}

func (m *Memory) AdvisoriesForCVE(cve string) ([]model.Advisory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Advisory
	for _, advs := range m.tracker {
		for _, a := range advs {
			if a.CVE == cve {
				out = append(out, a)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourcePackage != out[j].SourcePackage {
			return out[i].SourcePackage < out[j].SourcePackage
		}
		return out[i].Release < out[j].Release
	})
	return out, nil
}

func (m *Memory) TrackerReleases() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	set := map[string]bool{}
	for _, advs := range m.tracker {
		for _, a := range advs {
			set[a.Release] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out, nil
}

func (m *Memory) SearchCVEs(q CVEQuery) ([]model.Enrichment, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	text := strings.ToLower(q.Text)
	var all []model.Enrichment
	for _, e := range m.enrich {
		if q.Severity != "" && e.CVSSSeverity != q.Severity {
			continue
		}
		if q.KEVOnly && !e.KEVListed {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(e.CVE), text) &&
			!strings.Contains(strings.ToLower(e.Summary), text) {
			continue
		}
		all = append(all, e)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].KEVListed != all[j].KEVListed {
			return all[i].KEVListed // KEV first
		}
		if all[i].CVSSScore != all[j].CVSSScore {
			return all[i].CVSSScore > all[j].CVSSScore
		}
		return all[i].CVE > all[j].CVE
	})
	total := len(all)
	return pageE(all, q.Offset, clampLimit(q.Limit)), total, nil
}

func page(s []model.Advisory, off, lim int) []model.Advisory {
	if off >= len(s) {
		return nil
	}
	end := off + lim
	if end > len(s) {
		end = len(s)
	}
	return s[off:end]
}
func pageE(s []model.Enrichment, off, lim int) []model.Enrichment {
	if off >= len(s) {
		return nil
	}
	end := off + lim
	if end > len(s) {
		end = len(s)
	}
	return s[off:end]
}

// ---- Users ----

func (m *Memory) CreateUser(u model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.users == nil {
		m.users = map[string]model.User{}
	}
	if _, ok := m.users[u.Username]; ok {
		return ErrExists
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	m.users[u.Username] = u
	return nil
}

func (m *Memory) GetUser(username string) (model.User, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[username]
	return u, ok, nil
}

func (m *Memory) ListUsers() ([]model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]model.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (m *Memory) SetUserPassword(username, passHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return ErrNotFound
	}
	u.PassHash = passHash
	u.UpdatedAt = time.Now().UTC()
	m.users[username] = u
	return nil
}

func (m *Memory) SetUserAdmin(username string, isAdmin bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return ErrNotFound
	}
	u.IsAdmin = isAdmin
	u.UpdatedAt = time.Now().UTC()
	m.users[username] = u
	return nil
}

func (m *Memory) DeleteUser(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[username]; !ok {
		return ErrNotFound
	}
	delete(m.users, username)
	return nil
}

func (m *Memory) CountUsers() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *Memory) CountAdmins() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, u := range m.users {
		if u.IsAdmin {
			n++
		}
	}
	return n, nil
}
