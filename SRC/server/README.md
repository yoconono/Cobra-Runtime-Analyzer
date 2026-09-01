# cobra — CVE Fleet backend

The server half of the platform. It ingests the **Debian Security Tracker**,
serves the agent enroll/report API, matches each reported inventory against
advisories using dpkg-accurate version comparison, and renders an operator
dashboard.

## Install (Debian/Ubuntu .deb)

The server ships as `cobra_<ver>_amd64.deb` and installs a systemd service.

```sh
sudo apt install ./cobrart_0.1.2_amd64.deb
# On first install, /etc/cobrart/cobra.conf is created from /etc/cobrart/cobra.conf.template.
# On upgrades your cobra.conf is preserved untouched (it is not a dpkg conffile,
# so there is never an "overwrite config?" prompt); the template is refreshed so
# you can diff it for new options.
sudoedit /etc/cobrart/cobra.conf        # store/DSN, enroll_token, dash_pass, session_key, TLS paths
# provide TLS material (agents require HTTPS):
sudo install -m0640 -o root -g cobra cert.pem /etc/cobrart/tls/cert.pem
sudo install -m0640 -o root -g cobra key.pem  /etc/cobrart/tls/key.pem
# if using a database backend, create the schema:
sudo -u cobra cobra migrate --store mariadb --dsn "$CVE_DSN"
sudo systemctl start cobra                     # API + dashboard
sudo systemctl start cobrart-refresh.timer       # daily feed refresh
```

The package installs `/usr/bin/cobrart`, a dedicated `cobra` system user,
`cobrart.service` (long-running server) and `cobrart-refresh.service` +
`cobrart-refresh.timer` (daily tracker/NVD/OSV/KEV/EPSS refresh). The service is
sandboxed (NoNewPrivileges, ProtectSystem=strict, private tmp, syscall filter,
read-only `/etc/cobra`, writable `/var/lib/cobrart`). Agents install separately from
`cobraagent_<ver>_amd64.deb`.

## Why matching is done here (and done this way)

Agents only *collect*; the server *decides*. Vulnerability status is determined
against the **Debian Security Tracker**, comparing the installed Debian version
to the version Debian fixed the issue in — using an implementation of dpkg's own
version algorithm (`internal/debver`, cross-checked against real `dpkg` in tests).

This is deliberate. Debian backports security fixes without changing the upstream
version number, so comparing installed versions to NVD's upstream CPE ranges
produces large numbers of false positives. Example that the test suite and demo
both cover: `coreutils 9.4-3ubuntu6.2` is **not** flagged for an issue "fixed in
9.4-3ubuntu6.1", because the installed version is already newer than the fix.

NVD and OSV are layered on top as **enrichment** (implemented — see below): CVSS
scores/severity and CVE metadata, not the primary matcher. The Debian verdict
still decides *whether* a package is vulnerable; enrichment decides *how bad*.

## Enrichment (NVD + OSV)

Findings carry a CVSS severity and base score, joined from a CVE enrichment table
at read time (so scores that arrive after a report still show up). Two sources:

- **NVD** (`services.nvd.nist.gov`, 2.0 API) — authoritative CVSS base score and
  severity. An API key raises the rate limit; pass `--nvd-api-key` or `NVD_API_KEY`.
- **OSV** (`api.osv.dev`) — CVE aliases, a CVSS *vector* (scored locally by
  `internal/cvss`, cross-checked against canonical values in tests), and a
  package-query API that is the entry point for the planned language/SBOM phase.

NVD is authoritative for CVSS; OSV fills gaps and adds aliases (`Merge` in
`internal/enrich`). Run it against the CVEs referenced by the ingested tracker:

```sh
# live (schedule alongside ingest)
cobra enrich --store postgres --dsn "$CVE_DSN" --source both --nvd-api-key "$NVD_API_KEY"

# offline / air-gapped: ingest saved feed files
cobra enrich --store postgres --dsn "$CVE_DSN" \
  --nvd-file nvd.json --osv-file osv.json

# ad-hoc language-package lookup (foundation for the SBOM phase)
cobra osv-query --ecosystem PyPI --name requests --version 2.19.1
```

`serve` can also load enrichment files at startup with `--nvd-file/--osv-file`
(used by the demo).

### Exploitation signals: KEV + EPSS

CVSS says how bad a flaw *could* be; **KEV** and **EPSS** say how likely it is to
be exploited — usually the better patch-priority signal. Both merge onto the same
CVE record and surface everywhere findings do.

- **CISA KEV** (Known Exploited Vulnerabilities): flags a CVE as actively
  exploited, with date-added, remediation due-date, and a ransomware indicator.
- **FIRST EPSS**: a 0–1 probability (and percentile) that a CVE will be exploited
  in the next 30 days.

```sh
# live
cobra enrich --store postgres --dsn "$CVE_DSN" --fetch-kev --fetch-epss
# offline (KEV JSON, EPSS CSV or .csv.gz)
cobra enrich --store postgres --dsn "$CVE_DSN" --kev-file kev.json --epss-file epss.csv.gz
# or at startup:  cobra serve ... --kev-file kev.json --epss-file epss.csv.gz
```

Default feeds: KEV `https://www.cisa.gov/.../known_exploited_vulnerabilities.json`,
EPSS `https://epss.cyentia.com/epss_scores-current.csv.gz`. The dashboard shows a
**KEV** badge and **EPSS %** on findings, the CVE list, and CVE detail; the
fleet vulnerability view sorts **KEV-first, then severity, then EPSS**. Alerting
escalates KEV findings (they alert even below the severity floor) and routing
rules can match on `kev` and `min_epss` (see Alerting).

## Build

```sh
cd server
go build -o ../build/cobra ./     # needs network for lib/pq, or:
go build -mod=vendor -o ../build/cobra ./   # offline (vendored)
```

Dependencies: `github.com/lib/pq` (Postgres) and `github.com/go-sql-driver/mysql`
(MariaDB/MySQL) — both dependency-free drivers, vendored under `vendor/`.

## Run

Storage sits behind one `Store` interface (`internal/store`); pick a backend:

- `--store=memory` — dependency-free, in-process, lost on restart. Great for
  trials and the demo below.
- `--store=postgres --dsn=...` — production on PostgreSQL. Schema is created
  automatically (`migrate` runs on startup, or run `cobra migrate` explicitly).
- `--store=mariadb --dsn=...` — production on MariaDB/MySQL. Same behaviour;
  DSN is a go-sql-driver string, e.g.
  `user:pass@tcp(host:3306)/cobra?parseTime=true&loc=UTC&charset=utf8mb4`
  (`parseTime=true&loc=UTC` is added automatically if omitted). Run
  `cobra migrate --store mariadb --dsn ...` to create the schema.

All three implement the identical interface, so every feature (matching,
enrichment, KEV/EPSS, lifecycle/trends, triage, tags, alerting) works the same
regardless of backend. The MariaDB dialect differs from Postgres in a few places:
the "one open episode per finding" guarantee (a partial unique index in Postgres)
is reproduced with a generated `open_key` column that is NULL once an episode
resolves; `RETURNING`/`xmax` insert-detection becomes select-then-write inside a
transaction; `ON CONFLICT` becomes `INSERT … ON DUPLICATE KEY`; array/JSONB
columns become `JSON`; and expiry comparisons use `UTC_TIMESTAMP()`.

> Note: the Postgres and MariaDB backends are compile- and dialect-verified but
> have not been exercised against a live server in this build environment; the
> `memory` backend is what the end-to-end demos run against.

Agents require HTTPS. Provide `--tls-cert/--tls-key`, or terminate TLS at a
reverse proxy (nginx/Caddy) in front of the server.

### Quick demo (memory store, self-signed TLS)

```sh
# self-signed cert with SANs
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes \
  -subj /CN=localhost -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

./build/cobra serve \
  --store memory --addr 127.0.0.1:8443 \
  --tls-cert cert.pem --tls-key key.pem \
  --tracker-file server/testdata/sample-tracker.json \
  --enroll-token demo-enroll-token \
  --dash-user admin --dash-pass secret
```

Point the agent at it (`cobraagent.conf`): `server_url = https://localhost:8443`,
`enrollment_token = demo-enroll-token`, `ca_cert_file = cert.pem`. Run
`cobraagent --once`, then open `https://localhost:8443/` (user `admin`).


### Tracker loading (additive)

At startup and on each refresh the server **merges** the security tracker into the
`debian_tracker` table (upsert by source-package + CVE + release): existing rows
are kept, changed rows are updated in place, and new advisories are added — no
truncate-and-refill, so there's no window where the table is empty. It logs a
`loading security tracker ...` line before the (potentially slow first) fetch and a
`tracker merged: N advisories from feed; debian_tracker now M rows (+K new)` line
after. Use `--tracker-replace` (serve/refresh) for an occasional full reload that
also prunes advisories dropped from the feed; `cobra ingest` always does a clean
replace. The **OSV language-package data** (for pip/npm/Go deps) is ingested the same way —
at startup and on every refresh cycle, mirroring the tracker. Enable
`osv_download = true` to fetch it live from the OSV.dev mirror
(`osv_ecosystems = Go,PyPI,npm`, base `osv_url`), or point `osv_index_file` at a
local index you generate (the file takes precedence). This replaces having to run
`cobra ingest-osv` by hand. Optional feed
files that don't exist yet (`osv_index_file`, `alert_routes`) are skipped with a
notice rather than treated as errors.


### Background refresh (tracker + CVE tables)

The running server keeps its data current on its own — no external cron needed.
Set `refresh_hours` (a plain number of hours) in `cobra.conf` and the server, in a
background goroutine, periodically refreshes:

- **debian_tracker** — Debian + Ubuntu security data (additive merge),
- the **OSV index** — language-package advisories (download or file),
- the **cve table** — NVD/OSV severity enrichment plus the CISA KEV catalog and
  FIRST EPSS scores.

```ini
refresh_hours = 6          # 0 disables background refresh
enrich_source = both       # nvd | osv | both | none
# nvd_api_key = ...        # strongly recommended: NVD is heavily rate-limited without a key
```

The tracker + OSV are also loaded synchronously at startup so matching works
immediately; the first background pass then fills the cve table. NVD enrichment is
incremental (only not-yet-enriched CVEs) and, without an API key, deliberately
slow — set `nvd_api_key`, or use `enrich_source = osv` if you don't want to depend
on NVD. The bundled `cobrart-refresh.timer` becomes optional once `refresh_hours` is
set, but is kept for anyone who prefers an external schedule.

## Users & authentication

The dashboard supports multiple accounts, managed from the **Admin -> Users**
page. Every user has full access to the application and can manage accounts.
Passwords are never stored in the clear — only salted PBKDF2-HMAC-SHA256 hashes
(pure standard library, no extra dependency).

Bootstrap: set `--dash-user`/`--dash-pass` (or `CVE_DASH_USER`/`CVE_DASH_PASS`,
or the config file). On first start with an empty user table, that credential is
hashed and seeded as the initial account, and also works as a break-glass login
while no users exist. As soon as a real user exists, the static credential is no
longer accepted — the stored hashes are authoritative. From the Admin page you
can add users, reset passwords (min 8 chars), and delete accounts; the last
remaining account cannot be deleted, to prevent lock-out.

Login & sessions: browsers get a login form at `/login`; a successful sign-in sets
a **stateless, HMAC-signed** session cookie (`HttpOnly; Secure; SameSite=Lax`, 12 h
TTL) that carries the username and expiry — no server-side session state. Because
verification only needs the signing key, logins **survive restarts and work across
multiple server instances** that share the key. Unauthenticated page requests are
redirected to the login form (no browser Basic-Auth popup). HTTP Basic Auth still
works for scripts and `curl -u`, validated against the same user store.

Set the signing key with `--session-key` (or `CVE_SESSION_KEY`, or the config
file) to a long, stable, secret value; generate one with e.g.
`head -c 32 /dev/urandom | base64`. If unset, a random key is generated per start
(sessions then don't survive restart) and a warning is logged. `/logout` clears
the cookie in the browser; the token stays cryptographically valid until it
expires, so to force **all** sessions to end immediately, rotate the session key.

If neither users nor a static credential are configured, the dashboard runs open
(local/demo mode) — set a credential for anything exposed.

## Catalog browser (list / search / view)

The dashboard's **Catalog** tab browses the reference data itself — independent of
whether any host is affected:

- `/catalog` — all enriched **CVE** records: search by id or summary, filter by
  severity or KEV-only, paginated.
- `/catalog/advisories` — all **tracker advisories** (Debian + Ubuntu): search by
  CVE or source package, filter by distro, release codename, or status.
- Any CVE links to `/cves/{id}`, which now works even for CVEs with no current
  findings — it shows enrichment metadata, every Debian/Ubuntu tracker advisory
  for that CVE, and any affected hosts.

Backed by `SearchAdvisories` / `SearchCVEs` / `AdvisoriesForCVE` on the store
(all three backends), so it scales to the full feed with server-side filtering
and paging.

## Ubuntu support

The server understands both the **Debian Security Tracker** and the **Ubuntu
Security Notices (USN)** feed, selected with `--distro debian|ubuntu|both`. Both
distros' advisories live in one table keyed by release codename (bookworm/trixie
vs noble/jammy/focal), so they never collide and each host matches only its own
distro — the agent reports `os_id`, and the server maps `VERSION_ID` to the right
codename (e.g. Ubuntu 24.04 -> noble, Debian 12 -> bookworm).

```sh
# Ubuntu only, from the live USN database (bzip2 JSON, decompressed automatically):
cobra ingest --store mariadb --dsn "$CVE_DSN" --distro ubuntu
# Both distros in one shot (for a mixed fleet):
cobra ingest --store mariadb --dsn "$CVE_DSN" --distro both
# Offline: cobra serve --distro both --tracker-file deb.json --ubuntu-usn-file usn.json[.bz2]
```

USN entries describe *fixed* releases, so a finding fires when the installed
source version is older than the Ubuntu fix — the same dpkg-accurate comparison
used for Debian. `--distro`, `--ubuntu-usn-url`, and `--ubuntu-usn-file` are
available on `serve`, `ingest`, and `refresh` (and in the config file).

## Runtime reachability analysis

Beyond "is a vulnerable package installed" and "is it loaded by a running
process", the agent reports, per shared-library soname, the exact symbols that
running processes actually import (via ELF `debug/elf` inspection of every mapped
object — the executable and its whole `.so` chain). When an advisory names the
flaw's affected symbol(s), the server classifies each finding on a reachability
ladder:

- `installed` — vulnerable package present, nothing running uses it
- `loaded` — a running process maps the library, but no symbol data for the CVE
- `symbol_used` — a running process imports the flaw's affected symbol ("flaw used")
- `loaded_unused` — the library is loaded but the affected symbol is never
  imported ("sym unused") — strong evidence the flaw isn't exercised

This also covers the native parts of Python/npm packages (C/Rust extensions are
ELF objects mapped into the interpreter). Affected-symbol data is sparse in
Debian/NVD; load it with `serve --symbols-file cve-symbols.json` (a
`{"CVE-…":["SSL_read",…]}` map) — from the Go vuln DB, GHSA/OSV, or a curated
file. Without symbol data a finding simply stays at `loaded`.

Honest limits: symbol-import means "referenced, plausibly reachable", not
"executed" — `dlopen`/`dlsym` and function-pointer dispatch can hide calls, and
stripped/static binaries reduce signal. Treat `loaded_unused` as de-prioritization
evidence, not proof of safety.

## Configuration file

`cobra serve` can read all its settings from a `key = value` file via
`--config` (or the `CVE_CONFIG` env var), so you don't need a long flag line:

```sh
cobra serve --config /etc/cobrart/cobra.conf
```

Precedence is command-line flag > config file > `CVE_*` env var > built-in
default, so you can override any single setting on the CLI for a one-off. Keys use
the flag names (`-` or `_` both work); `#` starts a comment; unknown keys are
rejected. A complete template is `packaging/cobra.conf.example` (keep it mode
`0640` — it holds the DSN password, dashboard password, and enroll token). The
`refresh` command reads the same file (non-strict) for `store`/`dsn`, so one file
drives both the service and the refresh timer.

## Production setup

The app auto-creates its **tables** on startup (or via `cobra migrate`), but
not the database itself — create an empty database + user first, then point
`--dsn` at it.

Minimal bring-up (schema auto-migrates; the tracker self-refreshes):

```sh
# 1. create the empty DB + user out-of-band (createdb / CREATE DATABASE), then:
cobra create-token --store mariadb --dsn "$CVE_DSN" --desc fleet --max-uses 500
cobra serve --store mariadb --dsn "$CVE_DSN" \
  --tls-cert /etc/ssl/cve.crt --tls-key /etc/ssl/cve.key \
  --tracker-url https://security-tracker.debian.org/tracker/data/json --refresh 6h \
  --enroll-token "$CVE_ENROLL_TOKEN" --dash-user "$USER" --dash-pass "$PASS"
```

Reference data comes from five independent upstreams (Debian tracker, NVD, OSV,
CISA KEV, FIRST EPSS) on different cadences. The one-shot **`refresh`** command
pulls them all in a single invocation — ideal for a timer:

```sh
cobra refresh --store mariadb --dsn "$CVE_DSN" --source both \
  --nvd-api-key "$NVD_API_KEY" --osv-index-file osv-index.json
```

Run `refresh` from a scheduled job so one feed failing doesn't block the others.
Ready-to-use systemd units (`cobrart.service`, `cve-refresh.service` +
`cve-refresh.timer`), an env template, and a `Makefile` are in `packaging/`:

```sh
cd packaging && sudo make install-units   # service + daily refresh timer
```

To schedule feeds individually (e.g. EPSS/KEV daily, NVD weekly) the granular
commands still exist: `ingest` (tracker), `enrich` (NVD/OSV, plus
`--fetch-kev/--fetch-epss`), and `ingest-osv`. `enrich --source both --fetch-kev
--fetch-epss` now performs all four live sources in one call.

`CVE_STORE`, `CVE_DSN`, `CVE_ENROLL_TOKEN`, `CVE_DASH_USER/PASS`, `CVE_TLS_CERT/KEY`
are also read from the environment, so you can `export CVE_STORE=mariadb CVE_DSN=…`
once and drop those flags. Selecting a SQL backend without a DSN, or pointing at
an unreachable database, prints actionable guidance rather than a raw driver error.

## HTTP surface

Agent API (`internal/api`):
- `POST /api/v1/agents/enroll` — validates the registration token, issues a
  per-agent API token (only its SHA-256 is stored), returns `{agent_id, api_token}`.
- `POST /api/v1/agents/{id}/report` — `Authorization: Bearer <api_token>`; runs
  the matcher and stores findings; returns `{received, vulnerabilities_found}`.

Dashboard (`internal/web`): `GET /` (agent list, running-first),
`GET /agents/{id}` (per-host findings with first-seen), `GET /cves` (fleet-wide
vulnerability list, worst severity first), `GET /cves/{id}` (a CVE's CVSS details
plus every affected host), and `GET /trends` (30-day open-findings chart, summary
stats, and a recent-activity feed). Optional basic auth via `--dash-user/--dash-pass`.

## Findings history

Findings are stored as lifecycle episodes, not overwritten snapshots. Each report
is *reconciled* against the host's currently-open findings: new ones get a
`first_seen`, still-present ones get a refreshed `last_seen`, and ones that have
disappeared (e.g. after a package upgrade) are stamped `resolved_at`. A finding
that reappears later opens a fresh episode, so the full history is retained. The
`/trends` view derives its chart, stats (open / appeared / resolved), and activity
feed from these episodes.

Reconciliation uses the report's `collected_at` as the observation time (clamped
to not exceed now), so queued or backfilled reports land on the correct day.

## Language / SBOM findings

Alongside dpkg packages, the agent reports a language-ecosystem inventory
(`language_packages`): Go modules read from running binaries' embedded build info,
pip/PyPI packages from `dist-info`/`egg-info`, and npm packages from
`node_modules`. The server matches these against an **OSV package-vulnerability
index** (`internal/osvmatch`), using explicit affected-version lists and
`[introduced, fixed)` ranges evaluated with `internal/semver`. Matches become
ordinary findings tagged with an `ecosystem` (PyPI/npm/Go; empty = Debian/OS), so
they flow through the same lifecycle, CVE views, and trends as OS findings, and
are shown with an ecosystem badge on the dashboard.

Load the index (and seed CVE severity/summary from each record) with:

```sh
cobra ingest-osv --store postgres --dsn "$CVE_DSN" --osv-index-file osv.json
# or at startup:  cobra serve ... --osv-index-file osv.json
```

The index is a JSON array of OSV records. Populate it from OSV's per-ecosystem
exports (https://osv.dev/data) for the ecosystems you run, or for a small/curated
set use the live OSV query API (the `osv-query` client is already wired).

Note on version semantics: Go and npm use semver ranges directly; PyPI records are
matched by explicit `versions` lists and by semver-shaped ranges. Full PEP 440
range semantics are not implemented — prefer OSV exports that carry explicit
affected versions for PyPI, or the live query API for exact PyPI range matching.

## Triage workflow

Operators triage findings from the dashboard. A decision attaches to a finding's
*identity* (agent + CVE + package + ecosystem), so it persists across reconciles —
if a finding resolves and later reappears, the decision still applies. States:

- **acknowledged** — seen / being worked; stays visible and counted.
- **snoozed** — hidden until an expiry (days); lapses back to active automatically.
- **risk_accepted** — accepted, with an optional re-review expiry.
- **muted** — hidden indefinitely (false positive / won't-fix).
- **active** (the "Clear" button) — removes any decision.

A finding is *suppressed* when its effective state is muted, or snoozed/risk_accepted
before expiry. Suppressed findings drop out of the agent severity counts and the
fleet `/cves` view, and they don't raise alerts — including no "all clear" when they
resolve and no re-alert when they reappear. They remain visible on the agent page
behind a "show suppressed" toggle, tagged with their state. Acknowledged findings
are *not* suppressed. Expiry is evaluated at read time (`EffectiveTriage`).

Every action is written to an append-only audit log (who, when, action, finding,
expiry, note), viewable at `/audit`. The actor is the dashboard's basic-auth user
(else "operator"). Triage is applied via `POST /triage` (the dashboard's per-row
form); it's behind the same auth as the rest of the dashboard.



When a report opens a **new** finding at or above a severity threshold, the
server raises an alert. Because it triggers on the lifecycle *appearance* event,
alerts are deduplicated automatically: a finding that stays open across reports
won't re-alert (only a genuine reappearance after remediation does).

Channels (a log line is always emitted as a fallback):

```sh
cobra serve ... \
  --alert-min-severity HIGH \        # LOW|MEDIUM|HIGH|CRITICAL (default HIGH)
  --alert-running-only \             # optional: only findings backing a live process
  --dashboard-url https://cve.example.com \  # builds links in alerts
  --alert-webhook https://hooks.example.com/cve \
  --alert-smtp-host smtp.example.com --alert-smtp-port 587 \
  --alert-smtp-from cve@example.com --alert-smtp-to secops@example.com \
  --alert-smtp-user "$U" --alert-smtp-pass "$P"
```

All flags have `CVE_ALERT_*` / `CVE_SMTP_*` / `CVE_DASHBOARD_URL` env equivalents.
The webhook receives one JSON POST per report:

```json
{"source":"cve-fleet","host":"web-01","count":2,"alerts":[
  {"cve":"CVE-...","ecosystem":"Go","package":"github.com/lib/pq",
   "installed_version":"1.10.9","fixed_version":"1.11.0",
   "severity":"HIGH","cvss_score":7.5,"running":true,
   "url":"https://cve.example.com/cves/CVE-..."}]}
```

Delivery happens off the report path (async, time-bounded), so a slow or broken
channel never blocks or fails an agent's report. SMTP uses STARTTLS via
`net/smtp` (port 587 style); email is optional.

### Resolved "all clear" notices

When a finding disappears from a host (e.g. after a package upgrade) it is stamped
resolved, and — unless `--alert-on-resolved=false` — a `kind:"resolved"` notice is
emitted through the same channels. Resolved notices use the severity threshold but
ignore `running-only` (the process is gone). Webhook payloads carry `new_count`
and `resolved_count`; each alert has a `kind` of `new` or `resolved`.

### Rule-based routing

For more than one channel, point `--alert-routes` at a JSON file and different
alerts route to different channels. Rules are evaluated in order; the first match
wins unless it sets `"continue": true`. A rule matches on any of `min_severity`,
`ecosystems` (`Go`/`PyPI`/`npm`/`deb`), `running`, `kinds` (`new`/`resolved`),
`kev` (known-exploited), and `min_epss` (EPSS probability floor).
When `--alert-routes` is set it replaces the single-channel `--alert-*` flags.
Known-exploited (KEV) findings always alert regardless of the severity floor.

```json
{
  "dashboard_url": "https://cve.example.com",
  "on_resolved": true,
  "channels": {
    "pager": {"type": "webhook", "url": "https://events.pagerduty.com/..."},
    "slack": {"type": "webhook", "url": "https://hooks.slack.com/..."},
    "secops": {"type": "smtp", "host": "smtp.example.com", "port": "587",
               "from": "cve@example.com", "to": ["secops@example.com"],
               "user": "cve@example.com", "pass": "..."}
  },
  "rules": [
    {"min_severity": "CRITICAL", "channels": ["pager", "secops"]},
    {"min_severity": "HIGH", "running": true, "channels": ["slack"]},
    {"min_severity": "HIGH", "channels": ["slack"]}
  ]
}
```

## Security notes

- Enrollment tokens support `--max-uses`; API tokens are stored only as SHA-256
  hashes; token comparison is constant-time.
- Put the dashboard behind auth (basic auth built in) and TLS.
- Report bodies are size-capped (32 MiB).

## Tests

```sh
go test ./...
```

`internal/debver` is cross-validated against the real `dpkg --compare-versions`;
`internal/match` covers every Debian tracker status branch (resolved-older,
resolved-newer, `fixed_version: 0`, open, undetermined).

## Layout

```
server/
  main.go                     serve | ingest | enrich | refresh | ingest-osv | osv-query | create-token | migrate
  packaging/                  cobra.conf.example, systemd units (server + refresh timer), Makefile
  internal/model/             wire + domain types
  internal/debver/            dpkg-accurate version comparison (+ dpkg cross-check test)
  internal/tracker/           Debian Security Tracker parser/fetcher + codename map
  internal/match/             Debian matching engine (+ semantics tests)
  internal/cvss/              CVSS v3.x base-score calculator (+ tests)
  internal/enrich/            NVD + OSV + KEV + EPSS clients/parsers, merge (+ tests)
  internal/semver/            semver comparison for OSV ranges (+ tests)
  internal/osvmatch/          OSV language-package parsing + matching (+ tests)
  internal/trends/            history -> series/stats/activity (pure, + tests)
  internal/notify/            alerts: policy, channels, resolved notices, routing (+ tests)
  internal/store/             Store interface; Memory, Postgres, MariaDB impls
  internal/api/               enroll + report handlers
  internal/web/               server-rendered dashboard (+ triage controls, /audit)
  testdata/                   sample tracker + NVD/OSV/KEV/EPSS feeds and index for the demo
```

## Next

- Host tagging/grouping (env, team, service) with per-group rollups and digests.
- Full PEP 440 range matching for PyPI (or wire the live OSV query path for it).
- SSO/OIDC for the dashboard; agent mTLS as an alternative to bearer tokens.
- Durable alert delivery (persistent retry queue) and alert throttling/grouping.
