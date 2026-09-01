package inventory

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"

	"github.com/yourorg/cve-fleet/agent/internal/model"
)

// rpmInstalled returns every installed rpm package with a full EVR
// (epoch:version-release) version string and its source package, mirroring what
// dpkg Installed() provides for Debian. The server compares the EVR with the
// rpmver algorithm (the Red Hat counterpart to debver).
func rpmInstalled() ([]model.Package, error) {
	// %{EPOCHNUM} yields 0 (not "(none)") when a package has no epoch.
	const qf = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n`
	cmd := exec.Command("rpm", "-qa", "--qf", qf)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return nil, wrapExec("rpm -qa", err, errb.String())
	}
	return parseRpmInstalled(out.Bytes()), nil
}

// parseRpmInstalled turns `rpm -qa --qf` output into packages. Split out from
// exec so it can be unit-tested without rpm present.
func parseRpmInstalled(b []byte) []model.Package {
	var pkgs []model.Package
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 6 {
			continue
		}
		name := f[0]
		if name == "" || name == "gpg-pubkey" { // gpg-pubkey is a pseudo-package
			continue
		}
		epoch, ver, rel, srcRPM, arch := f[1], f[2], f[3], f[4], f[5]
		evr := composeEVR(epoch, ver, rel)
		srcName, srcEVR := parseSourceRPM(srcRPM)
		if srcName == "" {
			srcName = name
		}
		if srcEVR == "" {
			srcEVR = evr
		}
		pkgs = append(pkgs, model.Package{
			Name:          name,
			Version:       evr,
			Source:        srcName,
			SourceVersion: srcEVR,
			Arch:          arch,
		})
	}
	return pkgs
}

// composeEVR builds "epoch:version-release", omitting the epoch when it is 0 or
// unset so it matches how Red Hat advisories usually express versions.
func composeEVR(epoch, version, release string) string {
	vr := version
	if release != "" {
		vr = version + "-" + release
	}
	if epoch != "" && epoch != "0" && epoch != "(none)" {
		return epoch + ":" + vr
	}
	return vr
}

// parseSourceRPM extracts the source package name and its version-release from a
// SOURCERPM string like "openssl-3.0.7-27.el9.src.rpm" -> ("openssl","3.0.7-27.el9").
func parseSourceRPM(s string) (name, evr string) {
	if s == "" || s == "(none)" {
		return "", ""
	}
	s = strings.TrimSuffix(s, ".rpm")
	s = strings.TrimSuffix(s, ".src")
	s = strings.TrimSuffix(s, ".nosrc")
	// name-version-release: release is after the last '-', version after the one
	// before it, name is everything before that.
	lastDash := strings.LastIndexByte(s, '-')
	if lastDash < 0 {
		return s, ""
	}
	prevDash := strings.LastIndexByte(s[:lastDash], '-')
	if prevDash < 0 {
		return s[:lastDash], s[lastDash+1:]
	}
	name = s[:prevDash]
	evr = s[prevDash+1:]
	return name, evr
}

// rpmPackagesForPaths maps on-disk file paths to their owning rpm package name.
// rpm -qf cannot echo the queried path, so each path is resolved individually to
// keep the path->package mapping unambiguous; unowned paths are simply absent.
// Cost is bounded by the number of distinct files backing running processes.
func rpmPackagesForPaths(paths []string) map[string]string {
	result := make(map[string]string, len(paths))
	const cap = 4000 // safety bound for pathological hosts
	for i, p := range paths {
		if i >= cap {
			break
		}
		out, err := exec.Command("rpm", "-qf", "--qf", "%{NAME}", "--", p).Output()
		if err != nil {
			continue // not owned by any package
		}
		name := strings.TrimSpace(string(out))
		if name == "" || strings.Contains(name, "not owned") {
			continue
		}
		result[p] = name
	}
	return result
}

func wrapExec(what string, err error, stderr string) error {
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		return &execError{what: what, err: err}
	}
	return &execError{what: what, err: err, stderr: msg}
}

type execError struct {
	what   string
	err    error
	stderr string
}

func (e *execError) Error() string {
	if e.stderr != "" {
		return e.what + ": " + e.err.Error() + ": " + e.stderr
	}
	return e.what + ": " + e.err.Error()
}
