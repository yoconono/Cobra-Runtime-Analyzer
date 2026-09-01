# Cobra

**Runtime vulnerability management for Debian, Ubuntu, and Red Hat family systems.**

Cobra tells you not just *which* CVEs affect your fleet, but *which of them are actually loaded into running processes* — so you can fix what matters first. It has two parts:

| Component | Package | Binary | Role |
|-----------|---------|--------|------|
| **Server** | `cobrart` | `/usr/bin/cobrart` | Ingests distribution security data, matches it against reported inventory, serves the API + web dashboard. |
| **Agent** | `cobraagent` | `/usr/bin/cobraagent` | Low‑footprint, stdlib‑only. Reports package inventory and what's running; talks to the server over HTTPS only. |

Designed by Stéphane Maubian · Apache License 2.0

---

## How it works

```
  ┌──────────────┐   HTTPS + token    ┌─────────────────────────────┐
  │  cobraagent   │ ─────────────────► │            cobrart           │
  │  (each host)  │   inventory +      │  match ─► findings ─► web/API │
  └──────────────┘   runtime facts    └──────────────┬──────────────┘
                                                       │ pulls & merges
                     Debian tracker · Ubuntu USN · Red Hat CSAF/VEX ·
                     OSV (Go/PyPI/npm/crates.io) · NVD · CISA KEV · FIRST EPSS
```

The agent collects inventory; the **server** does all the matching. OS packages are compared with distribution‑exact version logic — **dpkg** semantics for Debian/Ubuntu, **rpm EVR** semantics for Red Hat family — against the security trackers. Language dependencies are matched against OSV. Everything is then enriched with CVSS (NVD/OSV), CISA KEV (known‑exploited), and FIRST EPSS (exploit probability).

### What the agent reports
- **OS packages** — `dpkg` on Debian/Ubuntu, `rpm` (full `epoch:version-release`) on Red Hat family. The agent auto‑detects the family from `/etc/os-release`.
- **Language dependencies** — Go (from build info baked into binaries), Python/PyPI (`dist-info`), npm (`node_modules`), and Rust/`crates.io` (from `Cargo.lock`).
- **Runtime facts** — a `/proc` scan maps shared libraries and binaries to the processes using them, so each finding is flagged **running** or not, attributed to the **consuming binary/binaries**, and tagged with the **last PID** seen.
- **Symbol reachability** — ELF import analysis grades a finding `installed` → `loaded` → `symbol_used`.
- **Provisioning tags** — arbitrary `key=value` labels set at enrollment.

### Security data sources
- **Debian Security Tracker** (JSON) — additive merge into the tracker table.
- **Ubuntu USN** database (bzip2 JSON).
- **Red Hat CSAF/VEX** — parsed to source‑package + release (`el9`, `el8`, …) with fixed EVRs; loaded from a local path (see `redhat_csaf`).
- **OSV** language ecosystems — `Go`, `PyPI`, `npm`, `crates.io` (bulk download from the OSV mirror).
- **Enrichment** — NVD (CVSS), OSV, CISA KEV, FIRST EPSS.

---

## Install

Both components ship as `.deb` packages for Debian/Ubuntu hosts. Red Hat hosts run the agent from the standalone binary (see below).

### Server

```bash
sudo apt install ./cobrart_<version>_amd64.deb
```

Installs `/usr/bin/cobrart`, a `cobrart` system user, the `cobrart.service` unit and a daily `cobrart-refresh.timer`, and a config **template** at `/etc/cobrart/cobrart.conf.template`. On first install the live config `/etc/cobrart/cobrart.conf` is created from the template; **upgrades never overwrite it**, so your secrets survive (which also means new defaults must be added by hand — see *Upgrading*).

Then:

```bash
sudoedit /etc/cobrart/cobrart.conf      # set store/DSN, dash_pass, session_key, TLS paths
# provide a TLS cert/key (agents require HTTPS):
sudo install -m0640 cert.pem /etc/cobrart/tls/cert.pem
sudo install -m0640 key.pem  /etc/cobrart/tls/key.pem
# create the database schema (Postgres or MariaDB):
sudo -u cobrart cobrart migrate --store mariadb --dsn "cobrart:pass@tcp(127.0.0.1:3306)/cobra?parseTime=true"
sudo systemctl enable --now cobrart.service cobrart-refresh.timer
```

> The **database** name in the DSN is `cobra` (that's the schema, not the binary). Storage backends: `memory` (demo only), `postgres`, `mariadb`.

### Agent — Debian/Ubuntu

```bash
sudo apt install ./cobraagent_<version>_amd64.deb
sudoedit /etc/cobraagent/cobraagent.conf   # set server_url + enrollment_token
sudo systemctl enable --now cobraagent.service
```

The agent runs as **root** by default so it can read every process and file for accurate runtime detection (the unit documents how to revert to an unprivileged `cobraagent` user with `CAP_SYS_PTRACE`).

### Agent — Red Hat / Rocky / Alma / Oracle / Amazon

There is no `.rpm` yet; use the standalone static binary:

```bash
sudo install -m0755 cobraagent-linux-amd64 /usr/local/bin/cobraagent
sudo mkdir -p /etc/cobraagent /var/lib/cobraagent
# write /etc/cobraagent/cobraagent.conf (see below), then run it (optionally as a systemd unit)
sudo cobraagent --config /etc/cobraagent/cobraagent.conf
```

The agent detects the RHEL family automatically and collects `rpm` inventory. RHEL findings appear once the server has Red Hat CSAF data loaded (see `redhat_csaf`).

---

## Configuration

### Server — `/etc/cobrart/cobrart.conf`

Key = value, one per line; `#` comments allowed. Every setting has a matching `--flag` (command line overrides the file). Common keys:

```ini
store           = mariadb
dsn             = cobrart:pass@tcp(127.0.0.1:3306)/cobra?parseTime=true
addr            = 127.0.0.1:8443
tls_cert        = /etc/cobrart/tls/cert.pem
tls_key         = /etc/cobrart/tls/key.pem

dash_user       = admin
dash_pass       = <set me>
session_key     = <stable random string>   # so logins survive restarts
enroll_token    = <token agents use to enroll>

# --- feeds ---
distro          = all                       # debian | ubuntu | all
tracker_url     = https://security-tracker.debian.org/tracker/data/json
# ubuntu_usn_url = https://usn.ubuntu.com/usn-db/database.json.bz2
osv_download    = true
osv_ecosystems  = Go,PyPI,npm,crates.io
redhat_csaf     = /var/lib/cobrart/redhat-csaf   # file, dir, or .tar/.tar.gz; skipped if absent

# --- background refresh + enrichment ---
refresh_hours   = 6
enrich_source   = both                      # nvd | osv | both | none
# nvd_api_key   = ...
# skip_kev / skip_epss = false
```

Notes:
- **`distro = all`** loads Debian **and** Ubuntu; Red Hat is loaded separately via `redhat_csaf`, so `all` + a Red Hat source covers all three families.
- **`redhat_csaf`** defaults to `/var/lib/cobrart/redhat-csaf` and is *skipped without error* if the path doesn't exist — drop CSAF/VEX data there to enable RHEL matching. Red Hat ships the corpus as `.tar.zst`; decompress it to a `.tar`/`.tar.gz` or a directory (zstd archives aren't read directly).
- Alerts (webhook / SMTP / routing rules) are available via `alert_*` keys — see `cobrart help`.

### Agent — `/etc/cobraagent/cobraagent.conf`

```ini
server_url         = https://cobra.example.internal:8443
enrollment_token   = <token from the server>
tags               = env=prod,team=platform

interval           = 1h        # how often to scan and report
scan_languages     = true      # pip / npm / Rust (Cargo.lock)
scan_go            = true       # read Go modules from binaries
scan_max_depth     = 8
scan_roots         = /srv,/opt,/app,/usr

# footprint / TLS knobs (optional):
# max_procs, memory_limit_mib, gc_percent, http_timeout, jitter_fraction,
# state_dir, ca_cert_file, insecure_skip_verify
```

The agent speaks **HTTPS only**. Enrollment exchanges the token for a persistent credential stored under `state_dir` (`/var/lib/cobraagent`); if it can't persist, it keeps running and logs a hint rather than crash‑looping.

---

## The web dashboard

Served over HTTPS with PBKDF2 auth and signed session cookies:

- **Overview** — fleet summary tiles (hosts + Critical/High/Medium/Low), a per‑OS breakdown, an impacted‑vs‑total‑hosts donut, and a **Top flaws** list ranked critical‑first then by host spread, with an **all / running** filter and pagination.
- **Agents** — inventory and per‑host findings, each with the **PID** and **consuming binary** for runtime hits, filters for *running / not‑running* and *severity*, sortable columns, and triage (ack / snooze / accept / mute).
- **Vulnerabilities** — every distinct CVE across the fleet; **50 per page**, **all columns sortable**, sort order preserved across pages.
- **Catalog** — browse enriched CVE records and tracker advisories.
- **Groups · Trends · Audit · Admin · About**.

---

## CLI (`cobrart <command>`)

| Command | Purpose |
|---------|---------|
| `serve` | Run the API + dashboard (loads feeds at startup; background‑refreshes on a timer). |
| `migrate` | Create/upgrade the database schema. |
| `ingest` | Load the Debian/Ubuntu trackers once (file or URL). |
| `ingest-osv` | Load the OSV language‑package index. |
| `ingest-redhat` | Load Red Hat CSAF/VEX (`--redhat-csaf <file|dir|.tar.gz>` or `--redhat-url`). |
| `enrich` / `refresh` | Refresh CVE enrichment (NVD/OSV/KEV/EPSS) / run the full pipeline. |
| `osv-query` | Ad‑hoc: list OSV vulns for an ecosystem package version. |
| `create-token` | Mint an enrollment token. |
| `version` · `help` | — |

Run `cobrart help` or `cobrart <command> --help` for all flags.

---

## Upgrading

Because the live config is never overwritten, after upgrading review new keys in `…/cobrart.conf.template` and copy any you want into your live config, then `systemctl restart cobrart`. In particular:
- To scan **Rust**, ensure `osv_ecosystems` includes `crates.io` (an existing explicit line overrides the new default).
- To enable **Red Hat**, place CSAF data at `redhat_csaf` (the default path is already active).

---

## Building from source

Go toolchain required. Module paths are under `github.com/yourorg/cve-fleet/{agent,server}`.

```bash
# server (vendored deps: lib/pq, go-sql-driver/mysql)
cd server && make            # or: go build ./...
# agent (stdlib only, ~5 MB static)
cd agent  && make            # produces ../build/cobraagent
```

The `packaging/` directory in each component holds the systemd units, config template, and `.deb` metadata.

---

## Versions

- Server: **cobrart 0.1.8**
- Agent: **cobraagent 0.1.9**

The two components are versioned independently. Server and agent are wire‑compatible across patch releases.
