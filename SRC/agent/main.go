// Command cobraagent is a low-footprint runtime CVE analysis agent. It reports
// the host's installed and running package inventory to a CVE Fleet server over
// HTTPS; the server performs the actual vulnerability matching.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/yourorg/cve-fleet/agent/internal/client"
	"github.com/yourorg/cve-fleet/agent/internal/config"
	"github.com/yourorg/cve-fleet/agent/internal/inventory"
	"github.com/yourorg/cve-fleet/agent/internal/inventory/langscan"
	"github.com/yourorg/cve-fleet/agent/internal/model"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	configPath := flag.String("config", "/etc/cobraagent/cobraagent.conf", "path to config file")
	once := flag.Bool("once", false, "run a single scan and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("cobraagent", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatal("config: %v", err)
	}
	applyResourceLimits(cfg)

	cl, err := client.New(cfg, "cobraagent/"+version)
	if err != nil {
		fatal("client: %v", err)
	}

	if !cl.LoadCredential() {
		if cl.CredentialFileExists() {
			logf("WARNING: credential file %s exists but could not be read — check it is owned by the service user and mode 0600 (was the agent ever run as root?)", cl.CredPath())
		}
		if cfg.EnrollmentToken == "" {
			fatal("not enrolled and no enrollment_token configured")
		}
		if err := doEnroll(cl, cfg); err != nil {
			fatal("enrollment failed: %v", err)
		}
		if err := cl.PersistCredential(); err != nil {
			// The server already issued a credential; a persistence failure must
			// not crash-loop the agent (which would re-enroll every restart and
			// spam the server). Keep running this session with the in-memory
			// credential and make the cause obvious.
			logf("WARNING: enrolled, but could NOT save the credential: %v", err)
			logf("the agent will run now but will RE-ENROLL on every restart until this is fixed.")
			logf("fix: make sure %s is writable by the service user, e.g. 'chown -R cobraagent:cobraagent %s'", cfg.StateDir, cfg.StateDir)
		} else {
			logf("enrolled successfully; credential saved to %s", cl.CredPath())
		}
	}

	if *once {
		if err := runScan(cl, cfg); err != nil {
			fatal("scan: %v", err)
		}
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	logf("started; interval=%s jitter=%.0f%%", cfg.Interval, cfg.JitterFraction*100)
	for {
		if err := runScan(cl, cfg); err != nil {
			logf("scan error: %v", err)
		}
		debug.FreeOSMemory() // return the heap to the OS so idle RSS stays low

		select {
		case <-stop:
			logf("shutting down")
			return
		case <-time.After(nextInterval(cfg)):
		}
	}
}

func doEnroll(cl *client.Client, cfg config.Config) error {
	r, err := inventory.Collect(version, nil) // host info only; skip language scan
	if err != nil {
		return err
	}
	return cl.Enroll(model.EnrollRequest{
		EnrollmentToken: cfg.EnrollmentToken,
		Hostname:        r.Host.Hostname,
		MachineID:       r.Host.MachineID,
		OSID:            r.Host.OSID,
		OSVersionID:     r.Host.OSVersionID,
		AgentVersion:    version,
		Tags:            cfg.Tags,
	})
}

func runScan(cl *client.Client, cfg config.Config) error {
	start := time.Now()
	var lang *langscan.Config
	if cfg.ScanLanguages {
		lang = &langscan.Config{
			ScanGo:   cfg.ScanGo,
			Roots:    cfg.ScanRoots,
			MaxDepth: cfg.ScanMaxDepth,
			MaxItems: 5000,
		}
	}
	report, err := inventory.Collect(version, lang)
	if err != nil {
		return err
	}
	report.Tags = cfg.Tags
	resp, err := cl.Report(report)
	if err != nil {
		return err
	}
	logf("reported %d packages, %d language deps (%d running processes) in %s; server flagged %d vulnerabilities",
		len(report.Packages), len(report.LanguagePackages), report.RunningProcessCount,
		time.Since(start).Round(time.Millisecond), resp.VulnerabilitiesFound)
	return nil
}

func applyResourceLimits(cfg config.Config) {
	if cfg.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.MaxProcs)
	}
	if cfg.MemoryLimitMiB > 0 {
		debug.SetMemoryLimit(cfg.MemoryLimitMiB * 1024 * 1024)
	}
	if cfg.GCPercent > 0 {
		debug.SetGCPercent(cfg.GCPercent)
	}
}

func nextInterval(cfg config.Config) time.Duration {
	if cfg.JitterFraction <= 0 {
		return cfg.Interval
	}
	span := float64(cfg.Interval) * cfg.JitterFraction
	delta := (rand.Float64()*2 - 1) * span // uniform in +/- span
	return time.Duration(float64(cfg.Interval) + delta)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[cobraagent] "+format+"\n", args...)
}

func fatal(format string, args ...any) {
	logf(format, args...)
	os.Exit(1)
}
