// Command cobra is the CVE Fleet backend: it ingests the Debian Security
// Tracker, serves the agent enroll/report API, matches reported inventories
// against advisories, and renders an operator dashboard.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/auth"
	"github.com/yourorg/cve-fleet/server/internal/api"
	"github.com/yourorg/cve-fleet/server/internal/enrich"
	"github.com/yourorg/cve-fleet/server/internal/match"
	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/notify"
	"github.com/yourorg/cve-fleet/server/internal/osvmatch"
	"github.com/yourorg/cve-fleet/server/internal/redhat"
	"github.com/yourorg/cve-fleet/server/internal/store"
	"github.com/yourorg/cve-fleet/server/internal/tracker"
	"github.com/yourorg/cve-fleet/server/internal/web"
)

var version = "0.1.8"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[cobrart] ")

	if len(os.Args) < 2 {
		shortUsage(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "ingest":
		cmdIngest(os.Args[2:])
	case "enrich":
		cmdEnrich(os.Args[2:])
	case "refresh":
		cmdRefresh(os.Args[2:])
	case "ingest-osv":
		cmdIngestOSV(os.Args[2:])
	case "ingest-redhat":
		cmdIngestRedHat(os.Args[2:])
	case "osv-query":
		cmdOSVQuery(os.Args[2:])
	case "create-token":
		cmdCreateToken(os.Args[2:])
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println("cobrart", version)
	case "help", "-h", "--help":
		fullHelp()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		shortUsage(2)
	}
}

const commandList = `cobrart <command> [flags]

  serve         run the API + dashboard
  ingest        fetch/parse the Debian Security Tracker into the store
  enrich        fill CVE severity/metadata (NVD/OSV) and exploitation signals (KEV/EPSS)
  refresh       one-shot: update all feeds (tracker + NVD/OSV + KEV + EPSS) for a timer
  ingest-osv    load the OSV language-package vulnerability index (file)
  ingest-redhat load Red Hat CSAF/VEX advisories (file, dir, or .tar.gz) into the tracker
  osv-query     ad-hoc: list OSV vulns for an ecosystem package version
  create-token  create an enrollment token
  migrate       create/upgrade the database schema
  version       print version
  help          show this help, including every command's flags

Common flags for store-backed commands (everything except serve's demo mode):
  --store   memory|postgres|mariadb      (env CVE_STORE)
  --dsn     database DSN                  (env CVE_DSN)`

// shortUsage prints the command list and exits.
func shortUsage(code int) {
	fmt.Fprintln(os.Stderr, commandList)
	fmt.Fprintln(os.Stderr, "\nRun 'cobrart help' or 'cobrart <command> --help' for all flags.")
	os.Exit(code)
}

// fullHelp prints the command list followed by every subcommand's own flag help,
// so `cobra --help` is a complete reference. Each block is produced by the
// subcommand itself, so it can never drift from the real flags.
func fullHelp() {
	fmt.Println(commandList)
	self, err := os.Executable()
	if err != nil || self == "" {
		self = os.Args[0]
	}
	for _, c := range []string{"serve", "ingest", "enrich", "refresh", "ingest-osv", "ingest-redhat", "osv-query", "create-token", "migrate"} {
		out, _ := exec.Command(self, c, "--help").CombinedOutput()
		fmt.Printf("\n=== %s ===\n%s", c, string(out))
	}
	os.Exit(0)
}

// openStore builds the store selected by flags.
// applyConfigFile reads a key=value file and sets any flag not already given on
// the command line (so CLI flags override the file, which overrides env/defaults).
// Keys may use '-' or '_'; '#' starts a comment. When strict, unknown keys are an
// error; otherwise they're skipped (so one shared file can serve several commands).
func applyConfigFile(fs *flag.FlagSet, path string, strict bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	setOnCLI := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { setOnCLI[f.Name] = true })

	for i, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("%s:%d: expected key = value", path, i+1)
		}
		name := strings.ReplaceAll(strings.TrimSpace(key), "_", "-")
		val = strings.TrimSpace(val)
		// Strip an inline comment (whitespace + '#') for unquoted values, so
		// lines like `refresh_hours = 6   # hours` parse correctly. Quoted values
		// keep any '#'.
		if !strings.HasPrefix(val, `"`) && !strings.HasPrefix(val, `'`) {
			if wsp := strings.IndexAny(val, " \t"); wsp >= 0 {
				if h := strings.IndexByte(val[wsp:], '#'); h >= 0 {
					val = strings.TrimSpace(val[:wsp+h])
				}
			}
		}
		val = strings.Trim(val, `"'`)
		if setOnCLI[name] {
			continue // command line wins
		}
		if fs.Lookup(name) == nil {
			if strict {
				return fmt.Errorf("%s:%d: unknown setting %q", path, i+1, name)
			}
			continue // key belongs to a different command
		}
		if err := fs.Set(name, val); err != nil {
			return fmt.Errorf("%s:%d: %s: %w", path, i+1, name, err)
		}
	}
	return nil
}

func openStore(kind, dsn string) store.Store {
	switch kind {
	case "memory":
		return store.NewMemory()
	case "postgres":
		requireDSN(kind, dsn)
		pg, err := store.OpenPostgres(dsn)
		if err != nil {
			dbConnectFatal(kind, dsn, err)
		}
		if err := pg.Migrate(); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		return pg
	case "mariadb", "mysql":
		requireDSN(kind, dsn)
		md, err := store.OpenMariaDB(dsn)
		if err != nil {
			dbConnectFatal(kind, dsn, err)
		}
		if err := md.Migrate(); err != nil {
			log.Fatalf("migrate: %v", err)
		}
		return md
	default:
		log.Fatalf("unknown --store %q (want memory|postgres|mariadb)", kind)
		return nil
	}
}

// requireDSN aborts with actionable guidance when a SQL backend has no DSN.
func requireDSN(kind, dsn string) {
	if dsn != "" {
		return
	}
	example := `--store mariadb --dsn "user:pass@tcp(127.0.0.1:3306)/cobra?parseTime=true&loc=UTC"`
	if kind == "postgres" {
		example = `--store postgres --dsn "postgres://user:pass@127.0.0.1:5432/cobra?sslmode=disable"`
	}
	log.Fatalf("store=%s but no database DSN was given.\n"+
		"  Pass --dsn or set the CVE_DSN environment variable, e.g.\n    %s\n"+
		"  For a throwaway trial with no database, use --store memory (data is lost on exit).",
		kind, example)
}

// dbConnectFatal turns a raw driver error into a friendlier message.
func dbConnectFatal(kind, dsn string, err error) {
	hint := ""
	if strings.Contains(err.Error(), "connection refused") {
		hint = "\n  The database doesn't appear to be running or reachable at the DSN host/port.\n" +
			"  Start it (e.g. `sudo systemctl start mariadb`) or check the host:port in your DSN.\n" +
			"  If you meant to use the other engine, switch --store (memory|postgres|mariadb) or set CVE_STORE."
	}
	log.Fatalf("could not connect to %s: %v%s", kind, err, hint)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configFile := fs.String("config", env("CVE_CONFIG", ""), "path to a key=value config file (command-line flags override it)")
	addr := fs.String("addr", ":8080", "listen address")
	kind := fs.String("store", env("CVE_STORE", "memory"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "postgres DSN (when --store=postgres)")
	trackerFile := fs.String("tracker-file", "", "load Debian tracker JSON from a file at startup")
	trackerURL := fs.String("tracker-url", "", "load Debian tracker JSON from URL at startup ("+tracker.DefaultURL+")")
	distro := fs.String("distro", "all", "which distro trackers to load/refresh: debian|ubuntu|all")
	usnFile := fs.String("ubuntu-usn-file", "", "load Ubuntu USN database from a file at startup (.json[.bz2])")
	usnURL := fs.String("ubuntu-usn-url", "", "load Ubuntu USN database from URL at startup ("+tracker.DefaultUSNURL+")")
	refresh := fs.Duration("refresh", 0, "background refresh interval as a duration (advanced; prefer --refresh-hours)")
	refreshHours := fs.Int("refresh-hours", 0, "hours between background refresh of the tracker + cve tables (0 = disabled)")
	enrichSource := fs.String("enrich-source", "both", "background CVE enrichment source: nvd|osv|both|none")
	nvdAPIKey := fs.String("nvd-api-key", env("NVD_API_KEY", ""), "NVD API key (raises the enrichment rate limit)")
	enrichRate := fs.Duration("enrich-rate", 0, "delay between upstream enrichment requests (default: 6s, or 0.6s with an API key)")
	skipKEV := fs.Bool("skip-kev", false, "don't refresh the CISA KEV catalog in the background")
	skipEPSS := fs.Bool("skip-epss", false, "don't refresh FIRST EPSS scores in the background")
	trackerReplace := fs.Bool("tracker-replace", false, "full-reload the tracker table on load instead of an additive merge")
	nvdFile := fs.String("nvd-file", "", "load CVE enrichment from a saved NVD 2.0 response at startup")
	osvFile := fs.String("osv-file", "", "load CVE enrichment from a saved OSV list at startup")
	osvIndexFile := fs.String("osv-index-file", "", "load the OSV language-package index at startup")
	osvDownload := fs.Bool("osv-download", false, "download the OSV index at startup/refresh when no --osv-index-file is set")
	osvReplace := fs.Bool("osv-replace", false, "full-reload the OSV table instead of an incremental merge")
	redhatCSAF := fs.String("redhat-csaf", env("CVE_REDHAT_CSAF", "/var/lib/cobrart/redhat-csaf"), "Red Hat CSAF/VEX path (file, directory, or .tar/.tar.gz) loaded at startup/refresh; skipped if absent")
	redhatURL := fs.String("redhat-url", env("CVE_REDHAT_URL", ""), "download a .tar/.tar.gz Red Hat CSAF archive from this URL at startup/refresh")
	osvURL := fs.String("osv-url", osvmatch.DefaultOSVBaseURL, "OSV bulk mirror base URL")
	osvEcosystems := fs.String("osv-ecosystems", strings.Join(osvmatch.DefaultOSVEcosystems, ","), "comma-separated OSV ecosystems to download (e.g. Go,PyPI,npm)")
	kevFile := fs.String("kev-file", "", "load the CISA KEV catalog (JSON) at startup")
	epssFile := fs.String("epss-file", "", "load the FIRST EPSS scores (CSV/CSV.gz) at startup")
	symbolsFile := fs.String("symbols-file", "", "load CVE->affected-symbols JSON at startup (enables symbol reachability)")
	seedToken := fs.String("enroll-token", env("CVE_ENROLL_TOKEN", ""), "seed this enrollment token at startup (handy for memory store)")
	dashUser := fs.String("dash-user", env("CVE_DASH_USER", ""), "dashboard basic-auth user (empty = no auth)")
	dashPass := fs.String("dash-pass", env("CVE_DASH_PASS", ""), "dashboard basic-auth password")
	sessionKey := fs.String("session-key", env("CVE_SESSION_KEY", ""), "secret key for signing session cookies; set a stable value so logins survive restarts and work across instances (empty = random per start)")
	tlsCert := fs.String("tls-cert", env("CVE_TLS_CERT", ""), "TLS certificate file (enables HTTPS)")
	tlsKey := fs.String("tls-key", env("CVE_TLS_KEY", ""), "TLS private key file")
	includeUndet := fs.Bool("include-undetermined", false, "include advisories Debian has not triaged for the release")
	alertWebhook := fs.String("alert-webhook", env("CVE_ALERT_WEBHOOK", ""), "POST new-finding alerts to this URL")
	alertMinSev := fs.String("alert-min-severity", env("CVE_ALERT_MIN_SEVERITY", "HIGH"), "minimum CVSS severity to alert on: LOW|MEDIUM|HIGH|CRITICAL")
	alertRunningOnly := fs.Bool("alert-running-only", false, "only alert on findings backing a live process")
	alertOnResolved := fs.Bool("alert-on-resolved", true, "emit 'all clear' notices when findings resolve")
	alertRoutes := fs.String("alert-routes", env("CVE_ALERT_ROUTES", ""), "JSON routing config; enables rule-based routing (overrides the --alert-* channel flags)")
	dashURL := fs.String("dashboard-url", env("CVE_DASHBOARD_URL", ""), "public dashboard base URL (used to build alert links)")
	smtpHost := fs.String("alert-smtp-host", env("CVE_SMTP_HOST", ""), "SMTP host for email alerts")
	smtpPort := fs.String("alert-smtp-port", env("CVE_SMTP_PORT", "587"), "SMTP port")
	smtpFrom := fs.String("alert-smtp-from", env("CVE_SMTP_FROM", ""), "SMTP From address")
	smtpTo := fs.String("alert-smtp-to", env("CVE_SMTP_TO", ""), "comma-separated alert recipients")
	smtpUser := fs.String("alert-smtp-user", env("CVE_SMTP_USER", ""), "SMTP username (optional)")
	smtpPass := fs.String("alert-smtp-pass", env("CVE_SMTP_PASS", ""), "SMTP password (optional)")
	_ = fs.Parse(args)
	if *configFile != "" {
		if err := applyConfigFile(fs, *configFile, true); err != nil {
			log.Fatalf("config: %v", err)
		}
	}

	st := openStore(*kind, *dsn)
	defer st.Close()

	// Load trackers at startup (Debian and/or Ubuntu) from files and/or URLs.
	// Additive by default (keeps rows already in the table); --tracker-replace
	// forces a full reload.
	if *trackerFile != "" || *usnFile != "" {
		loadTracker(st, func() ([]model.Advisory, error) {
			return gatherTracker(*distro, "", *trackerFile, "", *usnFile)
		}, *trackerReplace)
	}
	if *trackerURL != "" || *usnURL != "" {
		loadTracker(st, func() ([]model.Advisory, error) {
			return gatherTracker(*distro, *trackerURL, "", *usnURL, "")
		}, *trackerReplace)
	}

	// OSV language-package index — loaded at startup like the tracker (from a
	// local file, or downloaded live from the OSV mirror when enabled). Merged
	// incrementally by default; --osv-replace forces a full reload.
	osvEcos := splitCSV(*osvEcosystems)
	startupOSV(st, *osvIndexFile, *osvURL, osvEcos, *osvDownload, *osvReplace)

	// Red Hat CSAF/VEX advisories (optional): merged into the tracker so RHEL
	// hosts match with rpm EVR comparison.
	if *redhatCSAF != "" || *redhatURL != "" {
		if err := loadRedHat(st, *redhatCSAF, *redhatURL, false); err != nil {
			log.Printf("redhat load: %v", err)
		}
	}

	// Background refresh: keep the debian_tracker and cve tables current from
	// inside the running server. Interval comes from --refresh-hours (preferred);
	// --refresh (a duration) is an advanced/testing override.
	interval := time.Duration(*refreshHours) * time.Hour
	if interval <= 0 {
		interval = *refresh
	}
	if interval > 0 {
		go backgroundRefresh(st, refreshOpts{
			distro: *distro, trackerURL: *trackerURL, usnURL: *usnURL, trackerReplace: *trackerReplace,
			enrichSource: *enrichSource, apiKey: *nvdAPIKey, rate: *enrichRate,
			skipKEV: *skipKEV, skipEPSS: *skipEPSS,
			osv: osvSpec{file: *osvIndexFile, url: *osvURL, ecosystems: osvEcos, download: *osvDownload, replace: *osvReplace},
			redhatCSAF: *redhatCSAF, redhatURL: *redhatURL,
		}, interval)
	}
	if *seedToken != "" {
		if err := st.CreateEnrollmentToken(store.EnrollmentToken{Token: *seedToken, Description: "seeded"}); err != nil {
			if errors.Is(err, store.ErrExists) {
				log.Printf("enrollment token already present (seed skipped)")
			} else {
				log.Printf("seed token: %v", err)
			}
		} else {
			log.Printf("seeded enrollment token")
		}
	}
	if *nvdFile != "" || *osvFile != "" {
		en := &enrich.Enricher{Store: st, Log: log.Default()}
		if err := en.RunFromFiles(*nvdFile, *osvFile); err != nil {
			log.Printf("enrichment load: %v", err)
		}
	}
	if *kevFile != "" {
		if err := loadKEV(st, func() (map[string]enrich.KEVInfo, error) { return enrich.FetchKEVFile(*kevFile) }); err != nil {
			log.Printf("kev load: %v", err)
		}
	}
	if *epssFile != "" {
		if err := loadEPSS(st, func() (map[string]enrich.EPSSInfo, error) { return enrich.FetchEPSSFile(*epssFile) }); err != nil {
			log.Printf("epss load: %v", err)
		}
	}
	if *symbolsFile != "" {
		if err := loadSymbols(st, *symbolsFile); err != nil {
			log.Printf("symbols load: %v", err)
		}
	}
	// Seed an initial dashboard user from the configured credentials if none exist,
	// so the first login can then manage users from the Admin page.
	if *dashUser != "" && *dashPass != "" {
		if n, _ := st.CountUsers(); n == 0 {
			if h, err := auth.Hash(*dashPass); err == nil {
				if err := st.CreateUser(model.User{Username: *dashUser, PassHash: h, IsAdmin: true}); err == nil {
					log.Printf("seeded initial dashboard user %q (admin)", *dashUser)
				}
			}
		}
	}

	mux := http.NewServeMux()
	var engine notify.Engine
	if *alertRoutes != "" {
		if _, statErr := os.Stat(*alertRoutes); errors.Is(statErr, os.ErrNotExist) {
			log.Printf("alert routes file %s not found; falling back to channel flags", *alertRoutes)
			*alertRoutes = ""
		}
	}
	if *alertRoutes != "" {
		rt, err := notify.LoadRouter(*alertRoutes, *dashURL, log.Default())
		if err != nil {
			log.Fatalf("alert routing config: %v", err)
		}
		log.Printf("alerts: rule-based routing (%d rules, %d channels, on-resolved=%v)", len(rt.Rules), len(rt.Channels), rt.OnResolved)
		engine = rt
	} else {
		engine = buildDispatcher(*alertWebhook, *alertMinSev, *alertRunningOnly, *alertOnResolved, *dashURL,
			*smtpHost, *smtpPort, *smtpFrom, *smtpTo, *smtpUser, *smtpPass)
	}
	api.New(st, log.Default(), match.Options{IncludeUndetermined: *includeUndet}).
		WithAlerts(engine).Routes(mux)
	sessKey := []byte(*sessionKey)
	if len(sessKey) == 0 {
		sessKey = make([]byte, 32)
		_, _ = rand.Read(sessKey)
		log.Printf("session-key not set: using a random key (logins will not survive restart or work across instances). Set --session-key or CVE_SESSION_KEY for durable sessions.")
	}
	web.New(st, *dashUser, *dashPass, sessKey, version).Routes(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if *dashUser == "" {
		log.Printf("WARNING: dashboard has no auth (set --dash-user/--dash-pass or put it behind a reverse proxy)")
	}
	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("listening on https://%s (store=%s)", *addr, *kind)
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Printf("listening on http://%s (store=%s) — agents require HTTPS; use --tls-cert/--tls-key or a TLS proxy", *addr, *kind)
	log.Fatal(srv.ListenAndServe())
}

// buildDispatcher assembles the alert channels from flags. A log fallback is
// always included so alerts are visible even with no webhook/SMTP configured.
func buildDispatcher(webhook, minSev string, runningOnly, onResolved bool, dashURL,
	smtpHost, smtpPort, smtpFrom, smtpTo, smtpUser, smtpPass string) *notify.Dispatcher {
	channels := notify.Multi{notify.LogNotifier{Log: log.Default()}}
	if webhook != "" {
		channels = append(channels, notify.Webhook{URL: webhook})
		log.Printf("alerts: webhook enabled")
	}
	if smtpHost != "" && smtpFrom != "" && smtpTo != "" {
		to := splitComma(smtpTo)
		channels = append(channels, notify.SMTP{
			Host: smtpHost, Port: smtpPort, From: smtpFrom, To: to, User: smtpUser, Pass: smtpPass,
		})
		log.Printf("alerts: email enabled (%d recipient(s))", len(to))
	}
	log.Printf("alerts: min-severity=%s running-only=%v on-resolved=%v", strings.ToUpper(minSev), runningOnly, onResolved)
	return &notify.Dispatcher{
		Policy:       notify.Policy{MinSeverity: strings.ToUpper(minSev), RunningOnly: runningOnly},
		Notifier:     channels,
		DashboardURL: dashURL,
		OnResolved:   onResolved,
		Log:          log.Default(),
	}
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "database DSN")
	distro := fs.String("distro", "all", "which distro trackers to ingest: debian|ubuntu|all")
	url := fs.String("tracker-url", tracker.DefaultURL, "Debian tracker JSON URL")
	file := fs.String("tracker-file", "", "Debian tracker JSON file (overrides --tracker-url)")
	usnURL := fs.String("ubuntu-usn-url", tracker.DefaultUSNURL, "Ubuntu USN database URL (.json[.bz2])")
	usnFile := fs.String("ubuntu-usn-file", "", "Ubuntu USN database file (overrides --ubuntu-usn-url)")
	_ = fs.Parse(args)

	st := openStore(*kind, *dsn)
	defer st.Close()

	advs, err := gatherTracker(*distro, *url, *file, *usnURL, *usnFile)
	if err != nil {
		log.Fatalf("fetch tracker: %v", err)
	}
	if err := st.ReplaceTracker(advs); err != nil {
		log.Fatalf("store tracker: %v", err)
	}
	n, _ := st.TrackerCount()
	log.Printf("ingested %d advisories (%s)", n, *distro)
}

// gatherTracker fetches and merges the selected distro trackers into one advisory
// set. Debian and Ubuntu use distinct release codenames, so their rows coexist in
// the single tracker table and each host matches only its own distro. A per-source
// failure is tolerated as long as at least one selected source succeeds.
func gatherTracker(distro, debURL, debFile, usnURL, usnFile string) ([]model.Advisory, error) {
	var all []model.Advisory
	var errs []string
	want := func(d string) bool { return distro == "both" || distro == "all" || distro == d }

	if want("debian") {
		var a []model.Advisory
		var e error
		if debFile != "" {
			a, e = tracker.FetchFile(debFile)
		} else {
			a, e = tracker.FetchURL(debURL)
		}
		if e != nil {
			errs = append(errs, "debian: "+e.Error())
		} else {
			all = append(all, a...)
		}
	}
	if want("ubuntu") {
		var a []model.Advisory
		var e error
		if usnFile != "" {
			a, e = tracker.FetchUSNFile(usnFile)
		} else {
			a, e = tracker.FetchUSNURL(usnURL)
		}
		if e != nil {
			errs = append(errs, "ubuntu: "+e.Error())
		} else {
			all = append(all, a...)
		}
	}
	if len(all) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		log.Printf("tracker: partial load (%s)", strings.Join(errs, "; "))
	}
	return all, nil
}

func cmdEnrich(args []string) {
	fs := flag.NewFlagSet("enrich", flag.ExitOnError)
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "postgres DSN")
	source := fs.String("source", "both", "nvd|osv|both")
	nvdFile := fs.String("nvd-file", "", "offline: NVD 2.0 response file")
	osvFile := fs.String("osv-file", "", "offline: OSV list file")
	kevFile := fs.String("kev-file", "", "offline: CISA KEV catalog JSON")
	epssFile := fs.String("epss-file", "", "offline: FIRST EPSS CSV (.csv or .csv.gz)")
	fetchKEV := fs.Bool("fetch-kev", false, "live: download the CISA KEV catalog")
	fetchEPSS := fs.Bool("fetch-epss", false, "live: download the FIRST EPSS scores")
	apiKey := fs.String("nvd-api-key", env("NVD_API_KEY", ""), "NVD API key (raises rate limit)")
	rate := fs.Duration("rate", 0, "delay between upstream requests (default: 6s, or 0.6s with an API key)")
	refreshAll := fs.Bool("refresh-all", false, "re-fetch CVEs already enriched")
	limit := fs.Int("limit", 0, "max CVEs to process (0 = all)")
	_ = fs.Parse(args)
	sourceSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "source" {
			sourceSet = true
		}
	})

	st := openStore(*kind, *dsn)
	defer st.Close()

	en := &enrich.Enricher{Store: st, Log: log.Default()}

	// Exploitation signals (independent of NVD/OSV; can run alone or together).
	kevReq := *kevFile != "" || *fetchKEV
	epssReq := *epssFile != "" || *fetchEPSS
	if *kevFile != "" {
		if err := loadKEV(st, func() (map[string]enrich.KEVInfo, error) { return enrich.FetchKEVFile(*kevFile) }); err != nil {
			log.Fatalf("kev: %v", err)
		}
	} else if *fetchKEV {
		if err := loadKEV(st, func() (map[string]enrich.KEVInfo, error) { return enrich.FetchKEVURL(enrich.DefaultKEVURL) }); err != nil {
			log.Fatalf("kev: %v", err)
		}
	}
	if *epssFile != "" {
		if err := loadEPSS(st, func() (map[string]enrich.EPSSInfo, error) { return enrich.FetchEPSSFile(*epssFile) }); err != nil {
			log.Fatalf("epss: %v", err)
		}
	} else if *fetchEPSS {
		if err := loadEPSS(st, func() (map[string]enrich.EPSSInfo, error) { return enrich.FetchEPSSURL(enrich.DefaultEPSSURL) }); err != nil {
			log.Fatalf("epss: %v", err)
		}
	}

	// Offline path: load from saved files.
	if *nvdFile != "" || *osvFile != "" {
		if err := en.RunFromFiles(*nvdFile, *osvFile); err != nil {
			log.Fatalf("enrich from files: %v", err)
		}
		return
	}

	// Skip the live NVD/OSV run only when the caller asked purely for KEV/EPSS
	// (i.e. requested exploitation signals and did not explicitly set --source).
	// `enrich --source both --fetch-kev --fetch-epss` now does all four.
	if (kevReq || epssReq) && !sourceSet {
		return
	}

	if err := runEnrichLive(en, *source, *apiKey, *rate, *refreshAll, *limit); err != nil {
		log.Fatalf("enrich: %v", err)
	}
}

// runEnrichLive performs a live NVD/OSV enrichment pass over the CVEs referenced
// by the ingested tracker. Shared by `enrich` and `refresh`.
func runEnrichLive(en *enrich.Enricher, source, apiKey string, rate time.Duration, refreshAll bool, limit int) error {
	if source == "nvd" || source == "both" {
		en.NVD = enrich.NewNVDClient(apiKey)
	}
	if source == "osv" || source == "both" {
		en.OSV = enrich.NewOSVClient()
	}
	perReq := rate
	if perReq == 0 {
		if apiKey != "" {
			perReq = 600 * time.Millisecond
		} else {
			perReq = 6 * time.Second
		}
	}
	return en.RunFromStore(context.Background(),
		enrich.Options{RefreshAll: refreshAll, PerRequest: perReq, Limit: limit})
}

// cmdIngestRedHat loads Red Hat CSAF/VEX advisories from a file, directory, or
// tar(.gz) archive into the tracker (additive), so RHEL-family hosts can be
// matched with rpm (EVR) version comparison.
func cmdIngestRedHat(args []string) {
	fs := flag.NewFlagSet("ingest-redhat", flag.ExitOnError)
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "postgres DSN")
	path := fs.String("redhat-csaf", "", "CSAF VEX path: a .json file, a directory of them, or a .tar/.tar.gz archive")
	url := fs.String("redhat-url", "", "download a .tar/.tar.gz CSAF archive from this URL instead of --redhat-csaf")
	replace := fs.Bool("replace", false, "full-reload Red Hat advisories instead of an incremental merge")
	_ = fs.Parse(args)
	if *path == "" && *url == "" {
		log.Fatalf("one of --redhat-csaf or --redhat-url is required")
	}
	st := openStore(*kind, *dsn)
	defer st.Close()
	if err := loadRedHat(st, *path, *url, *replace); err != nil {
		log.Fatalf("ingest-redhat: %v", err)
	}
}

// loadRedHat ingests Red Hat advisories from a path or URL into the tracker.
// Shared by the ingest-redhat command and serve/refresh startup.
func loadRedHat(st store.Store, path, url string, replace bool) error {
	var advs []model.Advisory
	var err error
	switch {
	case path != "":
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			log.Printf("Red Hat CSAF: %s not present; skipping (drop CSAF data there to enable RHEL matching)", path)
			return nil
		}
		log.Printf("loading Red Hat CSAF advisories from %s ...", path)
		advs, err = redhat.LoadPath(path)
	case url != "":
		log.Printf("downloading Red Hat CSAF archive from %s ...", url)
		advs, err = redhat.FetchArchive(url)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if len(advs) == 0 {
		log.Printf("Red Hat CSAF: no advisories parsed")
		return nil
	}
	before, _ := st.TrackerCount()
	if replace {
		// Red Hat rows live in the shared tracker; a targeted replace isn't
		// available, so merge is used and a full reload just re-upserts.
		if err := st.MergeTracker(advs); err != nil {
			return err
		}
	} else if err := st.MergeTracker(advs); err != nil {
		return err
	}
	after, _ := st.TrackerCount()
	log.Printf("Red Hat CSAF merged: %d advisory rows from feed; tracker now %d rows (+%d new)",
		len(advs), after, after-before)
	return nil
}

func cmdIngestOSV(args []string) {
	fs := flag.NewFlagSet("ingest-osv", flag.ExitOnError)
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "postgres DSN")
	file := fs.String("osv-index-file", "", "OSV index file (JSON array of OSV records)")
	_ = fs.Parse(args)
	if *file == "" {
		log.Fatalf("--osv-index-file is required")
	}
	st := openStore(*kind, *dsn)
	defer st.Close()
	if err := loadOSVIndex(st, *file, true); err != nil {
		log.Fatalf("ingest-osv: %v", err)
	}
}

// loadOSVIndex parses an OSV index file, stores it for language matching, and
// seeds CVE enrichment (severity/summary) from each record.
// loadSymbols loads a CVE -> affected-symbols JSON map, enabling symbol-level
// reachability. Format: {"CVE-2025-1234": ["SSL_read","SSL_write"], ...}
func loadSymbols(st store.Store, file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var m map[string][]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	n := 0
	for cve, syms := range m {
		if err := st.UpsertAffectedSymbols(cve, syms); err != nil {
			return err
		}
		n++
	}
	log.Printf("affected symbols loaded: %d CVEs", n)
	return nil
}

func loadOSVIndex(st store.Store, file string, replace bool) error {
	advs, err := osvmatch.ParseIndexFile(file)
	if err != nil {
		return err
	}
	return ingestOSVAdvs(st, advs, replace)
}

// ingestOSVAdvs stores OSV package advisories and seeds per-CVE enrichment. By
// default it merges (incremental upsert, no TRUNCATE); pass replace=true for a
// full reload.
func ingestOSVAdvs(st store.Store, advs []model.LangAdvisory, replace bool) error {
	// Guard against pathologically long package names that can't be indexed by
	// the SQL stores (MariaDB's osv_pkg.name is VARCHAR(512)); skip rather than
	// abort the whole batch.
	const maxOSVName = 512
	if n := len(advs); n > 0 {
		kept := make([]model.LangAdvisory, 0, n)
		skipped := 0
		for _, a := range advs {
			if len(a.Package) > maxOSVName {
				skipped++
				continue
			}
			kept = append(kept, a)
		}
		if skipped > 0 {
			log.Printf("osv: skipped %d advisory row(s) with package names longer than %d chars", skipped, maxOSVName)
		}
		advs = kept
	}
	before, _ := st.OSVPackageCount()
	if replace {
		if err := st.ReplaceOSVPackages(advs); err != nil {
			return err
		}
	} else {
		if err := st.MergeOSVPackages(advs); err != nil {
			return err
		}
	}
	seeded := map[string]bool{}
	for _, a := range advs {
		e := osvmatch.Enrichment(a)
		if seeded[e.CVE] {
			continue
		}
		seeded[e.CVE] = true
		if err := st.UpsertEnrichment(e); err != nil {
			log.Printf("osv enrich %s: %v", e.CVE, err)
		}
	}
	after, _ := st.OSVPackageCount()
	if replace {
		log.Printf("OSV index loaded: %d package advisories, %d CVEs enriched", after, len(seeded))
	} else {
		log.Printf("OSV index merged: %d advisories from feed; osv_pkg now %d rows (+%d new), %d CVEs enriched",
			len(advs), after, after-before, len(seeded))
	}
	return nil
}

// loadKEV applies a KEV catalog to the enrichment store.
func loadKEV(st store.Store, fetch func() (map[string]enrich.KEVInfo, error)) error {
	kev, err := fetch()
	if err != nil {
		return err
	}
	n := 0
	for cve, info := range kev {
		if err := st.UpsertKEV(cve, info.DateAdded, info.DueDate, info.Ransomware); err != nil {
			log.Printf("kev %s: %v", cve, err)
			continue
		}
		n++
	}
	log.Printf("KEV loaded: %d known-exploited CVEs", n)
	return nil
}

// loadEPSS applies EPSS scores to the enrichment store.
func loadEPSS(st store.Store, fetch func() (map[string]enrich.EPSSInfo, error)) error {
	epss, err := fetch()
	if err != nil {
		return err
	}
	n := 0
	for cve, info := range epss {
		if err := st.UpsertEPSS(cve, info.Score, info.Percentile); err != nil {
			continue
		}
		n++
	}
	log.Printf("EPSS loaded: %d CVE scores", n)
	return nil
}

func cmdRefresh(args []string) {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	configFile := fs.String("config", env("CVE_CONFIG", ""), "key=value config file (shares store/dsn with serve; flags override)")
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "database DSN")
	trackerURL := fs.String("tracker-url", tracker.DefaultURL, "Debian tracker JSON URL")
	trackerFile := fs.String("tracker-file", "", "Debian tracker JSON file (overrides --tracker-url)")
	distro := fs.String("distro", "debian", "which trackers to refresh: debian|ubuntu|both")
	usnURL := fs.String("ubuntu-usn-url", tracker.DefaultUSNURL, "Ubuntu USN database URL (.json[.bz2])")
	usnFile := fs.String("ubuntu-usn-file", "", "Ubuntu USN database file (overrides --ubuntu-usn-url)")
	trackerReplace := fs.Bool("tracker-replace", false, "full-reload the tracker table instead of an additive merge")
	source := fs.String("source", "both", "NVD/OSV enrichment: nvd|osv|both|none")
	apiKey := fs.String("nvd-api-key", env("NVD_API_KEY", ""), "NVD API key (raises rate limit)")
	rate := fs.Duration("rate", 0, "delay between upstream requests (default: 6s, or 0.6s with an API key)")
	refreshAll := fs.Bool("refresh-all", false, "re-fetch CVEs already enriched")
	limit := fs.Int("limit", 0, "max CVEs to enrich (0 = all)")
	osvIndexFile := fs.String("osv-index-file", "", "OSV language-package index file (optional)")
	skipKEV := fs.Bool("skip-kev", false, "don't refresh the CISA KEV catalog")
	skipEPSS := fs.Bool("skip-epss", false, "don't refresh FIRST EPSS scores")
	_ = fs.Parse(args)
	if *configFile != "" {
		if err := applyConfigFile(fs, *configFile, false); err != nil {
			log.Fatalf("config: %v", err)
		}
	}

	st := openStore(*kind, *dsn)
	defer st.Close()

	runRefreshPipeline(st, refreshOpts{
		distro: *distro, trackerURL: *trackerURL, trackerFile: *trackerFile,
		usnURL: *usnURL, usnFile: *usnFile, trackerReplace: *trackerReplace,
		enrichSource: *source, apiKey: *apiKey, rate: *rate, refreshAll: *refreshAll, limit: *limit,
		skipKEV: *skipKEV, skipEPSS: *skipEPSS,
		osv: osvSpec{file: *osvIndexFile},
	})
}

func cmdOSVQuery(args []string) {
	fs := flag.NewFlagSet("osv-query", flag.ExitOnError)
	eco := fs.String("ecosystem", "", "OSV ecosystem, e.g. PyPI, npm, Go")
	name := fs.String("name", "", "package name")
	ver := fs.String("version", "", "package version")
	_ = fs.Parse(args)
	if *eco == "" || *name == "" || *ver == "" {
		log.Fatalf("--ecosystem, --name and --version are required")
	}
	vulns, err := enrich.NewOSVClient().QueryPackage(context.Background(), *eco, *name, *ver)
	if err != nil {
		log.Fatalf("osv query: %v", err)
	}
	if len(vulns) == 0 {
		fmt.Printf("no known vulnerabilities for %s/%s@%s\n", *eco, *name, *ver)
		return
	}
	for _, v := range vulns {
		fmt.Printf("%s\t%s\n", v.ID, v.Summary)
	}
}

func cmdCreateToken(args []string) {
	fs := flag.NewFlagSet("create-token", flag.ExitOnError)
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: memory|postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "postgres DSN")
	desc := fs.String("desc", "", "description")
	maxUses := fs.Int("max-uses", 0, "maximum uses (0 = unlimited)")
	_ = fs.Parse(args)

	st := openStore(*kind, *dsn)
	defer st.Close()

	tok := randHex(24)
	if err := st.CreateEnrollmentToken(store.EnrollmentToken{Token: tok, Description: *desc, MaxUses: *maxUses}); err != nil {
		log.Fatalf("create token: %v", err)
	}
	fmt.Println(tok)
}

func cmdMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	kind := fs.String("store", env("CVE_STORE", "postgres"), "store backend: postgres|mariadb")
	dsn := fs.String("dsn", env("CVE_DSN", ""), "database DSN")
	_ = fs.Parse(args)
	st := openStore(*kind, *dsn) // openStore runs Migrate for SQL backends
	defer st.Close()
	log.Printf("schema up to date")
}

type osvSpec struct {
	file       string
	url        string
	ecosystems []string
	download   bool
	replace    bool
}

// refreshOpts bundles everything a full refresh needs, shared by the `refresh`
// command and the in-serve background refresher.
type refreshOpts struct {
	distro, trackerURL, trackerFile, usnURL, usnFile string
	trackerReplace                                   bool
	enrichSource, apiKey                             string
	rate                                             time.Duration
	refreshAll                                       bool
	limit                                            int
	skipKEV, skipEPSS                                bool
	osv                                              osvSpec
	redhatCSAF, redhatURL                            string
}

// runEnrichment refreshes the cve table: NVD/OSV severity enrichment for tracker
// CVEs, plus the CISA KEV catalog and FIRST EPSS scores.
func runEnrichment(st store.Store, o refreshOpts) {
	if o.enrichSource != "none" && o.enrichSource != "" {
		en := &enrich.Enricher{Store: st, Log: log.Default()}
		if err := runEnrichLive(en, o.enrichSource, o.apiKey, o.rate, o.refreshAll, o.limit); err != nil {
			log.Printf("enrich: %v", err)
		}
	}
	if !o.skipKEV {
		if err := loadKEV(st, func() (map[string]enrich.KEVInfo, error) { return enrich.FetchKEVURL(enrich.DefaultKEVURL) }); err != nil {
			log.Printf("kev: %v", err)
		}
	}
	if !o.skipEPSS {
		if err := loadEPSS(st, func() (map[string]enrich.EPSSInfo, error) { return enrich.FetchEPSSURL(enrich.DefaultEPSSURL) }); err != nil {
			log.Printf("epss: %v", err)
		}
	}
}

// runRefreshPipeline does a complete refresh: tracker, OSV index, and the cve
// table (enrichment + KEV + EPSS).
func runRefreshPipeline(st store.Store, o refreshOpts) {
	loadTracker(st, func() ([]model.Advisory, error) {
		return gatherTracker(o.distro, o.trackerURL, o.trackerFile, o.usnURL, o.usnFile)
	}, o.trackerReplace)
	startupOSV(st, o.osv.file, o.osv.url, o.osv.ecosystems, o.osv.download, o.osv.replace)
	if o.redhatCSAF != "" || o.redhatURL != "" {
		if err := loadRedHat(st, o.redhatCSAF, o.redhatURL, false); err != nil {
			log.Printf("redhat refresh: %v", err)
		}
	}
	runEnrichment(st, o)
	log.Printf("refresh complete")
}

// backgroundRefresh keeps the debian_tracker and cve tables current from inside
// the running server. The tracker + OSV index are already loaded synchronously at
// startup, so the first pass here just fills the cve table; every interval after
// that it re-runs the full pipeline.
func backgroundRefresh(st store.Store, o refreshOpts, every time.Duration) {
	log.Printf("background refresh enabled: every %s (initial CVE enrichment starting now)", every)
	runEnrichment(st, o)
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		log.Printf("background refresh: starting scheduled update")
		runRefreshPipeline(st, o)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// startupOSV loads the OSV language-package index at startup / on refresh, the
// same way the Debian/Ubuntu tracker is loaded. Precedence: a local index file
// (osvFile) if set, otherwise a live download of the configured ecosystems from
// the OSV mirror when download is enabled. A no-op when neither is configured.
func startupOSV(st store.Store, osvFile, osvURL string, ecosystems []string, download, replace bool) {
	if osvFile != "" {
		log.Printf("loading OSV language-package index from %s ...", osvFile)
		if err := loadOSVIndex(st, osvFile, replace); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Printf("osv-index file %s not present; skipping", osvFile)
			} else {
				log.Printf("osv index load: %v", err)
			}
		}
		return
	}
	if !download {
		return
	}
	if len(ecosystems) == 0 {
		ecosystems = osvmatch.DefaultOSVEcosystems
	}
	base := osvURL
	if base == "" {
		base = osvmatch.DefaultOSVBaseURL
	}
	log.Printf("downloading OSV index for %s from %s (first fetch can take a few minutes)...",
		strings.Join(ecosystems, ", "), base)
	advs, err := osvmatch.FetchIndex(base, ecosystems)
	if err != nil && len(advs) == 0 {
		log.Printf("osv download failed: %v", err)
		return
	}
	if err != nil {
		log.Printf("osv download: %v", err) // partial
	}
	if err := ingestOSVAdvs(st, advs, replace); err != nil {
		log.Printf("osv ingest: %v", err)
	}
}

// loadTracker fetches advisories and writes them to the store. By default it
// merges (additive upsert, keeping rows already present); pass replace=true for a
// full reload. It logs before fetching, because the first Debian fetch is large
// and can take a few minutes.
func loadTracker(st store.Store, fetch func() ([]model.Advisory, error), replace bool) {
	mode := "merging into"
	if replace {
		mode = "reloading"
	}
	log.Printf("loading security tracker (%s the debian_tracker table; the first fetch can take a few minutes)...", mode)
	advs, err := fetch()
	if err != nil {
		log.Printf("tracker load failed: %v", err)
		return
	}
	before, _ := st.TrackerCount()
	if replace {
		err = st.ReplaceTracker(advs)
	} else {
		err = st.MergeTracker(advs)
	}
	if err != nil {
		log.Printf("tracker store failed: %v", err)
		return
	}
	after, _ := st.TrackerCount()
	if replace {
		log.Printf("tracker reloaded: %d advisories in debian_tracker", after)
	} else {
		log.Printf("tracker merged: %d advisories from feed; debian_tracker now %d rows (+%d new)", len(advs), after, after-before)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
