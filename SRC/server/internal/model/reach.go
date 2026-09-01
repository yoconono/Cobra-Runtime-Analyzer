package model

// Reachability levels, from least to most evidence that a flaw is actually used.
// Higher rungs (call-reachable, executed) are reserved for later analysis modes.
const (
	ReachInstalled    = "installed"     // vulnerable package present, nothing running uses it
	ReachLoaded       = "loaded"        // a running process maps the library, no symbol data
	ReachSymbolUsed   = "symbol_used"   // a running process imports the flaw's affected symbol
	ReachSymbolUnused = "loaded_unused" // library loaded, but the affected symbol is never imported
)

// ReachRank orders levels for sorting/prioritization (higher = more concerning).
func ReachRank(level string) int {
	switch level {
	case ReachSymbolUsed:
		return 4
	case ReachLoaded:
		return 3
	case ReachSymbolUnused:
		return 2
	case ReachInstalled:
		return 1
	default:
		return 0
	}
}

// Reachability classifies a finding given whether the package backs a running
// process and, when known, the flaw's affected symbols versus the symbols the
// running processes actually import from the affected library.
//
//   - not running                -> installed
//   - running, no symbol data    -> loaded
//   - running, affected symbol imported     -> symbol_used
//   - running, affected symbol NOT imported -> loaded_unused (likely not exercised)
func Reachability(running bool, affectedSymbols, usedSymbols []string) string {
	if !running {
		return ReachInstalled
	}
	if len(affectedSymbols) == 0 {
		return ReachLoaded
	}
	used := make(map[string]struct{}, len(usedSymbols))
	for _, s := range usedSymbols {
		used[s] = struct{}{}
	}
	for _, s := range affectedSymbols {
		if _, ok := used[s]; ok {
			return ReachSymbolUsed
		}
	}
	return ReachSymbolUnused
}
