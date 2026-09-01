package inventory

import (
	"debug/elf"
	"path/filepath"
	"sort"
)

// maxSymbolsPerLib bounds the reported symbol set per shared object, keeping the
// report payload sane on hosts that map very large libraries.
const maxSymbolsPerLib = 4096

// SymbolReachability inspects the ELF objects currently mapped by running
// processes and returns, per shared-library soname, the set of symbols those
// objects actually import from it — i.e. the functions that are genuinely
// referenced at runtime. It also returns soname -> owning Debian package
// (resolved from the concrete file paths) so the server can tie a symbol set to
// a finding.
//
// This answers "is the flawed function used?" one rung more precisely than "is
// the library loaded?": a CVE whose affected symbol never appears here is very
// unlikely to be exercised, even though the library is mapped.
func SymbolReachability(mappedFiles []string, fileToPkg map[string]string, binToSource map[string]string) (used map[string][]string, owners map[string]string) {
	usedSet := map[string]map[string]struct{}{} // soname -> symbol set
	seen := map[string]bool{}                    // avoid re-parsing a file mapped by many procs

	for _, path := range mappedFiles {
		if seen[path] {
			continue
		}
		seen[path] = true
		f, err := elf.Open(path)
		if err != nil {
			continue // not ELF, unreadable, or already gone
		}
		imps, err := f.ImportedSymbols()
		f.Close()
		if err != nil {
			continue
		}
		for _, s := range imps {
			// s.Library is the DT_NEEDED soname that provides the symbol
			// (from the ELF version records). Skip symbols with no binding.
			if s.Library == "" || s.Name == "" {
				continue
			}
			m := usedSet[s.Library]
			if m == nil {
				m = map[string]struct{}{}
				usedSet[s.Library] = m
			}
			if len(m) < maxSymbolsPerLib {
				m[s.Name] = struct{}{}
			}
		}
	}
	if len(usedSet) == 0 {
		return nil, nil
	}

	used = make(map[string][]string, len(usedSet))
	for lib, set := range usedSet {
		syms := make([]string, 0, len(set))
		for s := range set {
			syms = append(syms, s)
		}
		sort.Strings(syms)
		used[lib] = syms
	}

	// Map each soname we reported to the SOURCE package that owns the concrete
	// file (findings are keyed on the source package).
	owners = map[string]string{}
	for path, binPkg := range fileToPkg {
		base := filepath.Base(path)
		if _, ok := used[base]; !ok {
			continue
		}
		src := binToSource[binPkg]
		if src == "" {
			src = binPkg
		}
		owners[base] = src
	}
	return used, owners
}
