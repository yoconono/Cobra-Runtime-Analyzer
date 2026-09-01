// Package inventory gathers the host's package and running-process state.
package inventory

import (
	"sort"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/agent/internal/inventory/langscan"
	"github.com/yourorg/cve-fleet/agent/internal/model"
)

// Collect builds a full report: host identity, the complete installed-package
// inventory, which of those packages are in use by a live process, and (when
// enabled) a language-ecosystem SBOM. Pass langCfg=nil to skip language scanning.
func Collect(agentVersion string, langCfg *langscan.Config) (model.Report, error) {
	host := hostInfo()
	fam := osFamily(host.OSID)

	pkgs, err := installedPackages(fam)
	if err != nil {
		return model.Report{}, err
	}

	runningFiles, procCount, err := RunningFiles()
	if err != nil {
		return model.Report{}, err
	}

	fileToPkg := packagesForPaths(fam, runningFiles)

	// Binary package -> source package, so shared libraries can be attributed to
	// the source package that findings are keyed on.
	binToSource := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		binToSource[p.Name] = p.Source
	}

	running := make(map[string]struct{}, len(fileToPkg))
	for _, name := range fileToPkg {
		running[name] = struct{}{}
	}
	for i := range pkgs {
		if _, ok := running[pkgs[i].Name]; ok {
			pkgs[i].Running = true
		}
	}

	// Live files owned by no package: locally built binaries, bundled runtime
	// libraries, container payloads.
	var unmanaged []string
	var runningExes []string
	for _, f := range runningFiles {
		if _, ok := fileToPkg[f]; !ok {
			unmanaged = append(unmanaged, f)
		}
		if !isSharedObject(f) {
			runningExes = append(runningExes, f)
		}
	}

	var langPkgs []model.LangPackage
	if langCfg != nil {
		langPkgs = langscan.Collect(*langCfg, runningExes)
	}

	runSyms, libOwners := SymbolReachability(runningFiles, fileToPkg, binToSource)

	// Attribute each source package to the running executable(s) that actually
	// map one of its files (the binary "responsible" for a runtime flaw). Keyed
	// on source package, which is what findings are keyed on.
	procs, _ := RunningProcs()
	runningBinaries, runningPIDs := buildRunningBinaries(procs, fileToPkg, binToSource, langPkgs)

	return model.Report{
		AgentVersion:          agentVersion,
		CollectedAt:           time.Now().UTC(),
		Host:                  host,
		Packages:              pkgs,
		LanguagePackages:      langPkgs,
		UnmanagedRunningFiles: unmanaged,
		RunningProcessCount:   procCount,
		RunningSymbols:        runSyms,
		LibraryOwners:         libOwners,
		RunningBinaries:       runningBinaries,
		RunningPIDs:           runningPIDs,
	}, nil
}

// buildRunningBinaries maps source package -> sorted list of running executables
// that map at least one file belonging to that package.
func buildRunningBinaries(procs []Proc, fileToPkg, binToSource map[string]string, langPkgs []model.LangPackage) (map[string][]string, map[string]int) {
	sets := map[string]map[string]struct{}{}
	pids := map[string]int{} // key (source pkg / module) -> highest PID seen using it
	exeToPID := map[string]int{}
	for _, p := range procs {
		if p.Exe != "" && p.PID > exeToPID[p.Exe] {
			exeToPID[p.Exe] = p.PID
		}
	}
	addAttr := func(key, exe string, pid int) {
		set := sets[key]
		if set == nil {
			set = map[string]struct{}{}
			sets[key] = set
		}
		set[exe] = struct{}{}
		if pid > pids[key] {
			pids[key] = pid
		}
	}
	// OS packages: resolve each mapped file to a source package via dpkg.
	for _, p := range procs {
		if p.Exe == "" {
			continue
		}
		seen := map[string]struct{}{}
		for _, f := range p.Files {
			binPkg, ok := fileToPkg[f]
			if !ok {
				continue
			}
			src := binToSource[binPkg]
			if src == "" {
				src = binPkg
			}
			if _, dup := seen[src]; dup {
				continue
			}
			seen[src] = struct{}{}
			addAttr(src, p.Exe, p.PID)
		}
	}
	// Language packages (Go modules read from running binaries): the module's
	// Path is the executable it was found in, keyed by module name (which is the
	// finding's source package for language ecosystems).
	for _, lp := range langPkgs {
		if !lp.Running || lp.Path == "" {
			continue
		}
		if pid, ok := exeToPID[lp.Path]; ok { // Path is a live executable (Go case)
			addAttr(lp.Name, lp.Path, pid)
		}
	}
	if len(sets) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(sets))
	for src, set := range sets {
		list := make([]string, 0, len(set))
		for exe := range set {
			list = append(list, exe)
		}
		sort.Strings(list)
		out[src] = list
	}
	return out, pids
}

// osFamily classifies a distribution ID into the package-management family that
// determines how inventory is collected and how versions are compared:
// "debian" (dpkg / debver) or "rhel" (rpm / rpmver). Unknown IDs fall back to
// probing for the package tools on PATH.
func osFamily(osID string) string {
	switch strings.ToLower(strings.TrimSpace(osID)) {
	case "debian", "ubuntu", "raspbian", "linuxmint", "pop", "devuan", "kali", "elementary", "zorin":
		return "debian"
	case "rhel", "redhat", "centos", "fedora", "rocky", "almalinux", "ol", "oracle", "oraclelinux",
		"amzn", "amazon", "scientific", "cloudlinux", "eurolinux", "circle":
		return "rhel"
	}
	// Unknown ID (or ID-less container): probe for the tools.
	_, haveDpkg := lookPath("dpkg-query")
	_, haveRPM := lookPath("rpm")
	switch {
	case haveDpkg:
		return "debian"
	case haveRPM:
		return "rhel"
	default:
		return "debian"
	}
}

func lookPath(bin string) (string, bool) {
	p, err := exec.LookPath(bin)
	return p, err == nil
}

// installedPackages returns the installed-package inventory for the host family.
func installedPackages(fam string) ([]model.Package, error) {
	if fam == "rhel" {
		return rpmInstalled()
	}
	return Installed()
}

// packagesForPaths resolves file paths to owning package names for the family.
func packagesForPaths(fam string, paths []string) map[string]string {
	if fam == "rhel" {
		return rpmPackagesForPaths(paths)
	}
	return PackagesForPaths(paths)
}

func hostInfo() model.HostInfo {
	h := model.HostInfo{}
	if hn, err := os.Hostname(); err == nil {
		h.Hostname = hn
	}
	h.MachineID = machineID()
	h.OSID, h.OSVersionID = osRelease()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
	h.Arch = archFor(osFamily(h.OSID))
	return h
}

// archFor reports the primary package architecture for the host family:
// dpkg's architecture name on Debian, or the machine hardware name (uname -m,
// e.g. x86_64/aarch64) on Red Hat.
func archFor(fam string) string {
	if fam == "rhel" {
		if out, err := exec.Command("uname", "-m").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
		return ""
	}
	return dpkgArch()
}

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return ""
}

func osRelease() (id, versionID string) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = v
		case "VERSION_ID":
			versionID = v
		}
	}
	return id, versionID
}

func dpkgArch() string {
	out, err := exec.Command("dpkg", "--print-architecture").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
