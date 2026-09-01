// Package config loads the agent configuration from a simple, human-readable
// "key = value" file. It intentionally uses only the standard library so the
// agent has zero external dependencies.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerURL          string        // must be https://
	EnrollmentToken    string        // used only until a credential is obtained
	CACertFile         string        // optional PEM bundle for a private CA
	StateDir           string        // where the credential is stored
	Interval           time.Duration // time between scans
	JitterFraction     float64       // +/- fraction applied to Interval to spread fleet load
	MaxProcs           int           // GOMAXPROCS
	MemoryLimitMiB     int64         // soft Go heap limit (keep below systemd MemoryMax)
	GCPercent          int           // GOGC
	HTTPTimeout        time.Duration
	InsecureSkipVerify bool // testing only

	// Language/SBOM scanning
	ScanLanguages bool     // master toggle for pip/npm/Go dependency scanning
	ScanGo        bool     // inspect running executables for Go build info
	ScanRoots     []string // filesystem roots scanned for Python/npm packages
	ScanMaxDepth  int      // directory depth limit under each root

	// Host tags reported to the server for grouping/filtering (key=value).
	Tags map[string]string
}

func Default() Config {
	return Config{
		StateDir:       "/var/lib/cveagent",
		Interval:       6 * time.Hour,
		JitterFraction: 0.15,
		MaxProcs:       1,
		MemoryLimitMiB: 90,
		GCPercent:      40,
		HTTPTimeout:    60 * time.Second,
		ScanLanguages:  true,
		ScanGo:         true,
		ScanRoots:      []string{"/srv", "/opt", "/app"},
		ScanMaxDepth:   8,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	var tokenFile string
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("config line %d: expected 'key = value'", lineNo)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		// Strip an inline comment (whitespace + '#') for unquoted values, so
		// lines like `max_procs = 1   # GOMAXPROCS` parse correctly. Quoted
		// values keep any '#' they contain.
		if !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, `'`) {
			if i := strings.IndexAny(val, " \t"); i >= 0 {
				if h := strings.IndexByte(val[i:], '#'); h >= 0 &&
					strings.TrimSpace(val[:i+h]) != "" {
					val = strings.TrimSpace(val[:i+h])
				}
			}
		}
		val = strings.Trim(val, `"'`)

		switch key {
		case "server_url":
			cfg.ServerURL = val
		case "enrollment_token":
			cfg.EnrollmentToken = val
		case "enrollment_token_file":
			tokenFile = val
		case "ca_cert_file":
			cfg.CACertFile = val
		case "state_dir":
			cfg.StateDir = val
		case "interval":
			if cfg.Interval, err = time.ParseDuration(val); err != nil {
				return cfg, fmt.Errorf("config line %d: bad interval: %w", lineNo, err)
			}
		case "jitter_fraction":
			if cfg.JitterFraction, err = strconv.ParseFloat(val, 64); err != nil {
				return cfg, fmt.Errorf("config line %d: bad jitter_fraction: %w", lineNo, err)
			}
		case "max_procs":
			if cfg.MaxProcs, err = strconv.Atoi(val); err != nil {
				return cfg, fmt.Errorf("config line %d: bad max_procs: %w", lineNo, err)
			}
		case "memory_limit_mib":
			if cfg.MemoryLimitMiB, err = strconv.ParseInt(val, 10, 64); err != nil {
				return cfg, fmt.Errorf("config line %d: bad memory_limit_mib: %w", lineNo, err)
			}
		case "gc_percent":
			if cfg.GCPercent, err = strconv.Atoi(val); err != nil {
				return cfg, fmt.Errorf("config line %d: bad gc_percent: %w", lineNo, err)
			}
		case "http_timeout":
			if cfg.HTTPTimeout, err = time.ParseDuration(val); err != nil {
				return cfg, fmt.Errorf("config line %d: bad http_timeout: %w", lineNo, err)
			}
		case "insecure_skip_verify":
			cfg.InsecureSkipVerify = val == "true" || val == "1"
		case "scan_languages":
			cfg.ScanLanguages = val == "true" || val == "1"
		case "scan_go":
			cfg.ScanGo = val == "true" || val == "1"
		case "scan_roots":
			cfg.ScanRoots = splitList(val)
		case "scan_max_depth":
			if cfg.ScanMaxDepth, err = strconv.Atoi(val); err != nil {
				return cfg, fmt.Errorf("config line %d: bad scan_max_depth: %w", lineNo, err)
			}
		case "tags":
			cfg.Tags = parseTags(val)
		default:
			return cfg, fmt.Errorf("config line %d: unknown key %q", lineNo, key)
		}
	}
	if err := sc.Err(); err != nil {
		return cfg, err
	}

	if tokenFile != "" && cfg.EnrollmentToken == "" {
		if b, err := os.ReadFile(tokenFile); err == nil {
			cfg.EnrollmentToken = strings.TrimSpace(string(b))
		}
	}
	return cfg, cfg.Validate()
}

// parseTags parses "env=prod team=payments,service=api" into a map.
func parseTags(s string) map[string]string {
	out := map[string]string{}
	for _, item := range splitList(s) {
		if i := strings.IndexByte(item, '='); i > 0 {
			out[strings.TrimSpace(item[:i])] = strings.TrimSpace(item[i+1:])
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// splitList parses a comma- or space-separated list, dropping empties.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (c Config) Validate() error {
	if c.ServerURL == "" {
		return fmt.Errorf("server_url is required")
	}
	if !strings.HasPrefix(strings.ToLower(c.ServerURL), "https://") {
		return fmt.Errorf("server_url must use https:// (got %q)", c.ServerURL)
	}
	if c.Interval < time.Minute {
		return fmt.Errorf("interval must be at least 1m")
	}
	if c.JitterFraction < 0 || c.JitterFraction >= 1 {
		return fmt.Errorf("jitter_fraction must be in [0, 1)")
	}
	return nil
}
