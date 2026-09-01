// Package langscan discovers language-ecosystem dependencies that dpkg/rpm do
// not track: Go modules baked into binaries, pip/PyPI packages, npm packages,
// and Rust crates (from Cargo.lock). It is stdlib-only and bounded (depth/count
// caps) to keep the agent's footprint small. Ecosystem names match OSV ("Go",
// "PyPI", "npm", "crates.io").
package langscan

import (
	"bufio"
	"debug/buildinfo"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yourorg/cve-fleet/agent/internal/model"
)

// Config controls what gets scanned.
type Config struct {
	ScanGo    bool     // inspect running executables for Go build info
	Roots     []string // filesystem roots to scan for Python/npm packages
	MaxDepth  int      // directory depth limit under each root
	MaxItems  int      // overall cap on discovered packages (safety)
}

// DefaultConfig is conservative: Go binaries on, common app roots for py/npm.
func DefaultConfig() Config {
	return Config{
		ScanGo:   true,
		Roots:    []string{"/srv", "/opt", "/app"},
		MaxDepth: 8,
		MaxItems: 5000,
	}
}

// Collect runs all enabled scanners. runningExes are executable paths backing
// live processes (from the process scan); Go modules found in them are marked
// Running. Errors on individual files are ignored so one bad file can't fail a scan.
func Collect(cfg Config, runningExes []string) []model.LangPackage {
	var out []model.LangPackage
	seen := map[string]bool{}
	add := func(p model.LangPackage) {
		if len(out) >= cfg.MaxItems {
			return
		}
		k := p.Ecosystem + "|" + p.Name + "|" + p.Version + "|" + p.Path
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, p)
	}

	if cfg.ScanGo {
		for _, exe := range runningExes {
			for _, p := range goModules(exe) {
				add(p)
			}
		}
	}
	for _, root := range cfg.Roots {
		scanRoot(root, cfg.MaxDepth, add)
	}
	return out
}

// goModules extracts the main module and dependencies from a Go binary.
func goModules(path string) []model.LangPackage {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil // not a Go binary, or unreadable
	}
	var out []model.LangPackage
	if info.Main.Path != "" && info.Main.Path != "command-line-arguments" {
		out = append(out, model.LangPackage{
			Ecosystem: "Go", Name: info.Main.Path, Version: cleanGoVer(info.Main.Version),
			Path: path, Running: true,
		})
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path == "" {
			continue
		}
		// Follow module replacements to the actual code in use.
		m := dep
		if m.Replace != nil {
			m = m.Replace
		}
		out = append(out, model.LangPackage{
			Ecosystem: "Go", Name: m.Path, Version: cleanGoVer(m.Version),
			Path: path, Running: true,
		})
	}
	return out
}

func cleanGoVer(v string) string {
	// buildinfo versions look like "v1.10.9" or "(devel)"; drop leading v so it
	// matches OSV Go versions, and blank out non-versions.
	if v == "" || strings.HasPrefix(v, "(") {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

// scanRoot walks a root (bounded depth) collecting Python dist-info and npm
// package.json manifests.
func scanRoot(root string, maxDepth int, add func(model.LangPackage)) {
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, keep walking
		}
		if d.IsDir() {
			if strings.Count(path, string(os.PathSeparator))-rootDepth > maxDepth {
				return fs.SkipDir
			}
			// Skip obviously irrelevant/expensive trees.
			switch d.Name() {
			case ".git", ".cache", "proc", "sys", "dev":
				return fs.SkipDir
			}
			return nil
		}
		base := d.Name()
		switch {
		case base == "METADATA" && strings.HasSuffix(filepath.Dir(path), ".dist-info"):
			if p, ok := parsePyMetadata(path); ok {
				add(p)
			}
		case base == "PKG-INFO" && strings.HasSuffix(filepath.Dir(path), ".egg-info"):
			if p, ok := parsePyMetadata(path); ok {
				add(p)
			}
		case base == "package.json" && filepath.Base(filepath.Dir(filepath.Dir(path))) == "node_modules":
			if p, ok := parseNpm(path); ok {
				add(p)
			}
		case base == "package.json": // scoped packages: node_modules/@scope/name/package.json
			gp := filepath.Base(filepath.Dir(filepath.Dir(filepath.Dir(path))))
			if gp == "node_modules" && strings.HasPrefix(filepath.Base(filepath.Dir(filepath.Dir(path))), "@") {
				if p, ok := parseNpm(path); ok {
					add(p)
				}
			}
		case base == "Cargo.lock": // Rust: exact crate versions from the lockfile
			for _, p := range parseCargoLock(path) {
				add(p)
			}
		}
		return nil
	})
}

// parseCargoLock reads crate name/version pairs from a Cargo.lock file. Only
// crates sourced from the crates.io registry are emitted (path/workspace crates
// have no source; git and alternative-registry crates aren't in OSV's crates.io
// data). Cargo.lock is TOML, but the relevant subset — repeated [[package]]
// tables with name/version/source string keys — parses reliably line by line
// without a TOML dependency.
func parseCargoLock(path string) []model.LangPackage {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	dir := filepath.Dir(path)
	var out []model.LangPackage
	var name, version, source string
	inPkg := false
	flush := func() {
		if inPkg && name != "" && version != "" && isCratesIO(source) {
			out = append(out, model.LangPackage{Ecosystem: "crates.io", Name: name, Version: version, Path: dir})
		}
		name, version, source, inPkg = "", "", "", false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush()
			inPkg = true
		case strings.HasPrefix(line, "["): // any other table header ends the block
			flush()
		case inPkg && strings.HasPrefix(line, "name = "):
			name = tomlString(line[len("name = "):])
		case inPkg && strings.HasPrefix(line, "version = "):
			version = tomlString(line[len("version = "):])
		case inPkg && strings.HasPrefix(line, "source = "):
			source = tomlString(line[len("source = "):])
		}
	}
	flush()
	return out
}

// isCratesIO reports whether a Cargo.lock source string refers to the public
// crates.io registry (git and sparse protocols both reference the same index).
func isCratesIO(source string) bool {
	return strings.Contains(source, "crates.io-index") || strings.Contains(source, "index.crates.io")
}

func tomlString(s string) string { return strings.Trim(strings.TrimSpace(s), `"`) }

// parsePyMetadata reads Name/Version from a dist-info METADATA / egg-info PKG-INFO
// (RFC822-style headers).
func parsePyMetadata(path string) (model.LangPackage, bool) {
	f, err := os.Open(path)
	if err != nil {
		return model.LangPackage{}, false
	}
	defer f.Close()
	var name, version string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // headers end at the first blank line
		}
		if v, ok := cutHeader(line, "Name:"); ok {
			name = v
		} else if v, ok := cutHeader(line, "Version:"); ok {
			version = v
		}
		if name != "" && version != "" {
			break
		}
	}
	if name == "" || version == "" {
		return model.LangPackage{}, false
	}
	return model.LangPackage{Ecosystem: "PyPI", Name: name, Version: version, Path: filepath.Dir(path)}, true
}

func cutHeader(line, key string) (string, bool) {
	if strings.HasPrefix(line, key) {
		return strings.TrimSpace(line[len(key):]), true
	}
	return "", false
}

// parseNpm reads name/version from a package.json.
func parseNpm(path string) (model.LangPackage, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return model.LangPackage{}, false
	}
	var pj struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &pj) != nil || pj.Name == "" || pj.Version == "" {
		return model.LangPackage{}, false
	}
	return model.LangPackage{Ecosystem: "npm", Name: pj.Name, Version: pj.Version, Path: filepath.Dir(path)}, true
}
