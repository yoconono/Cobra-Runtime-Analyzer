// Package model defines the JSON wire types shared between the agent and the
// CVE Fleet server. Keep this in sync with the server implementation.
package model

import "time"

// HostInfo identifies the machine the agent runs on.
type HostInfo struct {
	Hostname    string `json:"hostname"`
	MachineID   string `json:"machine_id"`
	OSID        string `json:"os_id"`         // e.g. "debian"
	OSVersionID string `json:"os_version_id"` // e.g. "12" (bookworm) / "13" (trixie)
	Arch        string `json:"arch"`          // dpkg architecture, e.g. "amd64"
	Kernel      string `json:"kernel"`
}

// Package is one installed dpkg package. Source/SourceVersion are what the
// server matches against the Debian Security Tracker (binary packages share a
// source package, and Debian tracks vulnerabilities per source package).
type Package struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	Arch          string `json:"arch"`
	Running       bool   `json:"running"` // referenced by at least one live process
}

// LangPackage is one language-ecosystem dependency discovered outside dpkg
// (pip/PyPI, npm, or a Go module baked into a binary). Ecosystem uses OSV names
// ("PyPI", "npm", "Go"). Running indicates it backs a live process.
type LangPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	Running   bool   `json:"running"`
}

// Report is the payload sent to the server on each scan.
type Report struct {
	AgentVersion          string            `json:"agent_version"`
	CollectedAt           time.Time         `json:"collected_at"`
	Host                  HostInfo          `json:"host"`
	Tags                  map[string]string `json:"tags,omitempty"`
	Packages              []Package         `json:"packages"`
	LanguagePackages      []LangPackage     `json:"language_packages"` // SBOM: pip/npm/Go deps
	UnmanagedRunningFiles []string          `json:"unmanaged_running_files"`
	RunningProcessCount   int               `json:"running_process_count"`
	// Symbol reachability: soname -> symbols imported by running processes, and
	// soname -> owning package. Lets the server tell "flaw's function is used"
	// from "library merely loaded".
	RunningSymbols map[string][]string `json:"running_symbols,omitempty"`
	LibraryOwners  map[string]string   `json:"library_owners,omitempty"`
	RunningBinaries map[string][]string `json:"running_binaries,omitempty"`
	RunningPIDs     map[string]int      `json:"running_pids,omitempty"`
}

// EnrollRequest is sent once, with the registration token, to obtain a credential.
type EnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	MachineID       string `json:"machine_id"`
	OSID            string `json:"os_id"`
	OSVersionID     string `json:"os_version_id"`
	AgentVersion    string `json:"agent_version"`
	Tags            map[string]string `json:"tags,omitempty"` // set at provisioning
}

// EnrollResponse carries the durable per-agent credential.
type EnrollResponse struct {
	AgentID  string `json:"agent_id"`
	APIToken string `json:"api_token"`
}

// ReportResponse is the server's acknowledgement of a report.
type ReportResponse struct {
	Received             bool `json:"received"`
	VulnerabilitiesFound int  `json:"vulnerabilities_found"`
}
