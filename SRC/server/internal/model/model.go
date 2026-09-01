// Package model holds the JSON wire types shared with the agent (kept in sync
// with agent/internal/model) and server-side domain types.
package model

import "time"

// ---- Wire types (must match the agent) ----

type HostInfo struct {
	Hostname    string `json:"hostname"`
	MachineID   string `json:"machine_id"`
	OSID        string `json:"os_id"`
	OSVersionID string `json:"os_version_id"`
	Arch        string `json:"arch"`
	Kernel      string `json:"kernel"`
}

type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Arch          string `json:"arch"`
	Running       bool   `json:"running"`
}

// LangPackage is one language-ecosystem dependency (pip/PyPI, npm, Go) reported
// by the agent. Ecosystem uses OSV names.
type LangPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	Running   bool   `json:"running"`
}

type Report struct {
	AgentVersion          string            `json:"agent_version"`
	CollectedAt           time.Time         `json:"collected_at"`
	Host                  HostInfo          `json:"host"`
	Tags                  map[string]string `json:"tags"`
	Packages              []Package         `json:"packages"`
	LanguagePackages      []LangPackage     `json:"language_packages"`
	UnmanagedRunningFiles []string          `json:"unmanaged_running_files"`
	RunningProcessCount   int               `json:"running_process_count"`
	RunningSymbols        map[string][]string `json:"running_symbols"`
	LibraryOwners         map[string]string   `json:"library_owners"`
	RunningBinaries       map[string][]string `json:"running_binaries"`
	RunningPIDs           map[string]int      `json:"running_pids"`
}

type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	MachineID       string `json:"machine_id"`
	OSID            string `json:"os_id"`
	OSVersionID     string `json:"os_version_id"`
	AgentVersion    string `json:"agent_version"`
	Tags            map[string]string `json:"tags,omitempty"` // set at provisioning
}

type EnrollResponse struct {
	AgentID  string `json:"agent_id"`
	APIToken string `json:"api_token"`
}

type ReportResponse struct {
	Received             bool `json:"received"`
	VulnerabilitiesFound int  `json:"vulnerabilities_found"`
}

// ---- Server-side domain types ----

// Agent is a registered host.
type Agent struct {
	ID           string
	MachineID    string
	Hostname     string
	OSID         string
	OSVersionID  string
	Arch         string
	Kernel       string
	AgentVersion string
	APITokenHash string
	EnrolledAt   time.Time
	LastSeenAt   time.Time

	// Tags for grouping/filtering. ReportedTags come from the agent's config;
	// Tags are operator-set in the dashboard and win on conflict.
	ReportedTags map[string]string
	Tags         map[string]string
}

// EffectiveTags merges reported and operator tags (operator wins).
func (a Agent) EffectiveTags() map[string]string {
	out := map[string]string{}
	for k, v := range a.ReportedTags {
		out[k] = v
	}
	for k, v := range a.Tags {
		out[k] = v
	}
	return out
}

// Advisory is one CVE affecting one source package in one Debian release,
// distilled from the Debian Security Tracker.
type Advisory struct {
	CVE           string
	SourcePackage string
	Release       string // codename, e.g. "bookworm"
	Status        string // "resolved" | "open" | "undetermined"
	FixedVersion  string // Debian version that fixes it; "" or "0" => not vulnerable
	Urgency       string
	Description   string
}

// Finding is a confirmed vulnerability on a specific agent.
type Finding struct {
	CVE              string
	SourcePackage    string
	Ecosystem        string // "" = Debian/OS package; else OSV ecosystem (PyPI/npm/Go)
	InstalledVersion string
	FixedVersion     string // "" when no fix is available yet (status "open")
	Urgency          string // Debian urgency
	Status           string
	Running          bool
	Reachability     string // installed|loaded|symbol_used|loaded_unused (see reach.go)
	RunningBinaries  []string // executables that map this package's code (runtime attribution)
	RunningPID       int      // last PID seen using this package (0 when not running)
	Description      string

	// Enrichment fields, populated at read time by joining CVE data (NVD/OSV).
	CVSSScore    float64
	CVSSSeverity string // NONE|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN
	CVSSVector   string

	// Exploitation signals (KEV / EPSS).
	KEVListed      bool
	EPSSScore      float64 // probability 0..1
	EPSSPercentile float64 // 0..1

	// Lifecycle, assigned by the store on reconcile.
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt time.Time // zero => still open

	// Triage (operator decision), joined at read time.
	TriageState string    // "" or "active" | "acknowledged" | "snoozed" | "risk_accepted" | "muted"
	TriageUntil time.Time // expiry for snoozed / risk_accepted (zero = none)
	TriageNote  string
}

// FindingLifecycle is a flattened finding episode (open or resolved) joined
// with host and severity, used to compute history, trends, and activity.
type FindingLifecycle struct {
	AgentID       string
	Hostname      string
	CVE           string
	SourcePackage string
	CVSSSeverity  string
	Running       bool
	FirstSeen     time.Time
	LastSeen      time.Time
	ResolvedAt    time.Time // zero => still open
}

// Enrichment is severity/metadata for a CVE, sourced from NVD and/or OSV,
// augmented with exploitation signals from CISA KEV and FIRST EPSS.
type Enrichment struct {
	CVE          string
	CVSSScore    float64
	CVSSSeverity string
	CVSSVector   string
	Source       string // "nvd", "osv", or "nvd+osv"
	Summary      string
	Aliases      []string
	References    []string
	Published    time.Time
	Modified     time.Time

	// CISA Known Exploited Vulnerabilities
	KEVListed     bool
	KEVDateAdded  time.Time
	KEVDueDate    time.Time
	KEVRansomware bool

	// FIRST EPSS
	EPSSScore      float64 // probability 0..1
	EPSSPercentile float64 // 0..1

	// Function-level reachability data: symbols in which the flaw lives. Sparse —
	// populated from the Go vuln DB / GHSA / OSV / a curated file where available.
	AffectedSymbols []string
}

// AgentSummary is the dashboard list-row view.
type AgentSummary struct {
	Agent
	FindingCount  int
	RunningCount  int
	KEVCount      int
	SeverityCounts map[string]int // by CVSS severity: CRITICAL/HIGH/MEDIUM/LOW/...
}

// CVESummary is one row of the fleet-wide vulnerability view.
type CVESummary struct {
	CVE           string
	CVSSSeverity  string
	CVSSScore     float64
	Summary       string
	AffectedHosts int
	RunningHosts  int
	KEVListed     bool
	EPSSScore     float64
}

// CVEHost is one host affected by a given CVE.
type CVEHost struct {
	AgentID          string
	Hostname         string
	OSID             string
	OSVersionID      string
	SourcePackage    string
	Ecosystem        string
	InstalledVersion string
	FixedVersion     string
	Running          bool
	Reachability     string
	Status           string
}

// VersionRange is an OSV affected range: [Introduced, Fixed).
type VersionRange struct {
	Introduced string
	Fixed      string
}

// LangAdvisory is one OSV vulnerability affecting one ecosystem package,
// flattened from the OSV schema. It is to language packages what Advisory is to
// Debian source packages.
type LangAdvisory struct {
	VulnID         string // CVE or GHSA id
	Aliases        []string
	Ecosystem      string
	Package        string
	Ranges         []VersionRange
	Versions       []string // explicit affected versions
	SeverityVector string   // CVSS vector, for enrichment
	Summary        string
}

// ---- Triage ----

// Triage states. "active" (or empty) means no triage decision is in effect.
const (
	TriageActive       = "active"
	TriageAcknowledged = "acknowledged"
	TriageSnoozed      = "snoozed"
	TriageRiskAccepted = "risk_accepted"
	TriageMuted        = "muted"
)

// Triage is an operator decision about a specific finding identity
// (agent + cve + source package + ecosystem). It persists across reconciles.
type Triage struct {
	AgentID       string
	CVE           string
	SourcePackage string
	Ecosystem     string
	State         string
	Until         time.Time // expiry for snoozed / risk_accepted (zero = none)
	Note          string
	Actor         string
	UpdatedAt     time.Time
}

// TriageEvent is an append-only audit record of a triage action.
type TriageEvent struct {
	When          time.Time
	Actor         string
	Action        string // the state that was set (e.g. "muted", "active")
	AgentID       string
	Hostname      string
	CVE           string
	SourcePackage string
	Ecosystem     string
	Until         time.Time
	Note          string
}

// EffectiveTriage resolves the stored state against the clock: snoozed and
// risk_accepted lapse back to active once their expiry passes.
func EffectiveTriage(state string, until, now time.Time) string {
	switch state {
	case TriageSnoozed, TriageRiskAccepted:
		if until.IsZero() || now.Before(until) {
			return state
		}
		return TriageActive
	case TriageAcknowledged, TriageMuted:
		return state
	default:
		return TriageActive
	}
}

// IsSuppressed reports whether an effective triage state hides a finding from
// default views/counts and silences its alerts. Acknowledged is NOT suppressed.
func IsSuppressed(effectiveState string) bool {
	switch effectiveState {
	case TriageMuted, TriageSnoozed, TriageRiskAccepted:
		return true
	default:
		return false
	}
}

// User is a dashboard account. Passwords are stored only as PBKDF2 hashes.
type User struct {
	Username  string
	PassHash  string
	IsAdmin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
