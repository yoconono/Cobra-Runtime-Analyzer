// Package store defines persistence for agents, enrollment tokens, findings,
// and the ingested Debian tracker data. Two implementations are provided:
// Memory (dependency-free, for tests and small/ephemeral use) and Postgres
// (production).
package store

import (
	"errors"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrExists        = errors.New("already exists")
	ErrTokenInvalid  = errors.New("enrollment token invalid or exhausted")
)

// EnrollmentToken controls how many agents may enroll with a given token.
type EnrollmentToken struct {
	Token       string
	Description string
	MaxUses     int // 0 = unlimited
	Uses        int
	Revoked     bool
}

// Store is the persistence contract.
type Store interface {
	// Enrollment tokens
	CreateEnrollmentToken(t EnrollmentToken) error
	ConsumeEnrollmentToken(token string) error // atomically validates + increments use

	// Agents
	UpsertAgent(a model.Agent) (model.Agent, error) // reuses ID when machine_id already exists
	AgentByTokenHash(hash string) (model.Agent, error)
	GetAgent(id string) (model.Agent, error)
	TouchAgent(id string) error
	ListAgents() ([]model.AgentSummary, error)

	// Findings lifecycle (reconciled against the latest report). Returns the
	// findings that newly opened and those that just resolved (for alerting).
	ReconcileFindings(agentID string, current []model.Finding, observedAt time.Time) (appeared, resolved []model.Finding, err error)
	ListFindings(agentID string) ([]model.Finding, error) // open findings only
	FindingLifecycles() ([]model.FindingLifecycle, error) // all episodes, for history/trends

	// Fleet-wide CVE views
	ListCVEs() ([]model.CVESummary, error)
	HostsForCVE(cve string) ([]model.CVEHost, error)

	// Debian tracker data
	ReplaceTracker(advs []model.Advisory) error // full reload (truncate + insert)
	MergeTracker(advs []model.Advisory) error   // additive upsert (keep existing rows)
	ForPackage(sourcePackage, release string) []model.Advisory // satisfies match.AdvisorySource
	TrackerCount() (int, error)
	DistinctTrackerCVEs() ([]string, error)
	// Catalog browsing/search over the reference data.
	SearchAdvisories(q AdvisoryQuery) ([]model.Advisory, int, error)
	AdvisoriesForCVE(cve string) ([]model.Advisory, error)
	TrackerReleases() ([]string, error)

	// OSV language-package index
	ReplaceOSVPackages(advs []model.LangAdvisory) error // full reload (truncate + insert)
	MergeOSVPackages(advs []model.LangAdvisory) error   // additive upsert (incremental)
	ForLangPackage(ecosystem, name string) []model.LangAdvisory // satisfies osvmatch.Source
	OSVPackageCount() (int, error)

	// CVE enrichment (NVD/OSV)
	UpsertEnrichment(e model.Enrichment) error
	EnrichmentFor(cve string) (model.Enrichment, bool, error)
	EnrichedCVEs() (map[string]bool, error)
	SearchCVEs(q CVEQuery) ([]model.Enrichment, int, error)
	EnrichmentCount() (int, error)

	// Exploitation signals (merged onto the CVE record)
	UpsertKEV(cve string, dateAdded, dueDate time.Time, ransomware bool) error
	UpsertEPSS(cve string, score, percentile float64) error
	UpsertAffectedSymbols(cve string, symbols []string) error

	// Triage (operator decisions + audit trail)
	SetTriage(t model.Triage) error // upserts the decision and appends an audit event
	TriageFor(agentID, cve, sourcePackage, ecosystem string) (model.Triage, bool, error)
	AuditLog(limit int) ([]model.TriageEvent, error)

	// Dashboard users (auth + admin management)
	CreateUser(u model.User) error
	GetUser(username string) (model.User, bool, error)
	ListUsers() ([]model.User, error)
	SetUserPassword(username, passHash string) error
	SetUserAdmin(username string, isAdmin bool) error
	DeleteUser(username string) error
	CountUsers() (int, error)
	CountAdmins() (int, error)

	// Host tags
	SetAgentTags(agentID string, tags map[string]string) error      // operator-set (durable)
	SetReportedTags(agentID string, tags map[string]string) error   // from the agent's report

	Close() error
}

// AdvisoryQuery filters the tracker advisory catalog. Empty fields are ignored.
type AdvisoryQuery struct {
	Text          string // substring match on CVE or source package (case-insensitive)
	SourcePackage string // exact source package
	Release       string // exact release codename (e.g. "noble", "bookworm")
	Status        string // exact status (e.g. "resolved", "open")
	Limit         int    // page size (0 => 50)
	Offset        int
}

// CVEQuery filters the CVE enrichment catalog. Empty fields are ignored.
type CVEQuery struct {
	Text     string // substring match on CVE id or summary (case-insensitive)
	Severity string // exact CVSS severity (CRITICAL/HIGH/...)
	KEVOnly  bool   // only KEV-listed CVEs
	Limit    int    // page size (0 => 50)
	Offset   int
}

func clampLimit(n int) int {
	if n <= 0 {
		return 50
	}
	if n > 500 {
		return 500
	}
	return n
}
