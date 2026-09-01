package inventory

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/yourorg/cve-fleet/agent/internal/model"
)

// Installed returns every fully-installed dpkg package with its source package
// and source version — the fields the server needs to match against Debian's
// security data.
func Installed() ([]model.Package, error) {
	const format = `${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n`
	cmd := exec.Command("dpkg-query", "-W", "-f="+format)

	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return nil, fmt.Errorf("dpkg-query -W: %v: %s", err, strings.TrimSpace(errb.String()))
	}

	var pkgs []model.Package
	sc := bufio.NewScanner(&out)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 6 {
			continue
		}
		if !strings.HasPrefix(f[0], "ii") { // only fully installed
			continue
		}
		name, ver := f[1], f[2]
		src := f[3]
		if src == "" {
			src = name
		}
		srcVer := f[4]
		if srcVer == "" {
			srcVer = ver
		}
		pkgs = append(pkgs, model.Package{
			Name:          name,
			Version:       ver,
			Source:        src,
			SourceVersion: srcVer,
			Arch:          f[5],
		})
	}
	return pkgs, sc.Err()
}

// PackagesForPaths maps on-disk file paths to their owning package name using
// dpkg-query -S, batched to stay well under ARG_MAX. Paths owned by no package
// are simply absent from the result.
func PackagesForPaths(paths []string) map[string]string {
	result := make(map[string]string, len(paths))
	const chunk = 200
	for i := 0; i < len(paths); i += chunk {
		end := i + chunk
		if end > len(paths) {
			end = len(paths)
		}
		args := append([]string{"-S"}, paths[i:end]...)
		cmd := exec.Command("dpkg-query", args...)

		var out bytes.Buffer
		cmd.Stdout = &out
		// dpkg-query exits non-zero when a path isn't found; ignore and parse stdout.
		_ = cmd.Run()

		sc := bufio.NewScanner(&out)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			idx := strings.LastIndex(line, ": ")
			if idx < 0 {
				continue
			}
			pkgPart := strings.TrimSpace(line[:idx])
			path := strings.TrimSpace(line[idx+2:])
			if strings.HasPrefix(pkgPart, "diversion by") || strings.HasPrefix(pkgPart, "local diversion") {
				continue
			}
			if c := strings.IndexByte(pkgPart, ','); c >= 0 { // "pkgA, pkgB" -> first
				pkgPart = pkgPart[:c]
			}
			pkgPart = strings.TrimSpace(pkgPart)
			if c := strings.IndexByte(pkgPart, ':'); c >= 0 { // "libssl3:amd64" -> "libssl3"
				pkgPart = pkgPart[:c]
			}
			result[path] = pkgPart
		}
	}
	return result
}
