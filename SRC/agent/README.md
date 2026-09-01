# cobraagent — runtime CVE analysis agent

A low-footprint daemon for Debian 12 (bookworm) / 13 (trixie). It reports the
host's installed and *running* package inventory to a CVE Fleet server over
HTTPS. The server performs the actual vulnerability matching (thin-agent design),
so the agent stays tiny and needs no direct internet access — only a link to your
server.

- **Zero external Go dependencies** — standard library only. ~5 MB static binary.
- **HTTPS only** — refuses `http://`, verifies the server certificate (private-CA
  bundle supported via `ca_cert_file`).
- **Registration-token enrollment** — a one-time token is exchanged for a durable
  per-agent credential stored `0600` under `state_dir`.
- **Runtime focus** — resolves each process's executable and mapped shared
  libraries from `/proc`, maps them back to dpkg packages, and flags which
  installed packages are actually in use.
- **Bounded footprint** — hard cgroup caps via systemd (`CPUQuota`, `MemoryMax`,
  …) plus in-process `GOMAXPROCS` / `GOMEMLIMIT` / `GOGC` and idle-between-scans.

## Build

```sh
cd agent
make build          # -> ../build/cobraagent  (CGO disabled, static)
make deb            # -> ../build/cobraagent_<version>_<arch>.deb  (needs nfpm)
```

Cross-compile for arm64: `make build GOARCH=arm64`.

## Configure

Edit `/etc/cobraagent/cobraagent.conf` (see `packaging/config.example.conf`). Minimum:

```
server_url = https://cve.example.com
enrollment_token = <token from the server UI>
```

### Language / SBOM scanning

The agent also inventories language dependencies that dpkg doesn't track, so the
server can match them against OSV:

- **Go** — modules read from running executables' embedded build info (precise,
  and tied to what's actually running).
- **PyPI** — packages found via `dist-info`/`egg-info` under the scan roots.
- **npm** — packages found via `node_modules` under the scan roots.

```
scan_languages = true          # master toggle (default: true)
scan_go        = true          # inspect running binaries for Go modules (default: true)
scan_roots     = /srv /opt /app  # dirs scanned for pip/npm (space- or comma-separated)
scan_max_depth = 8             # directory depth limit under each root
```

`scan_roots` defaults to `/srv /opt /app`. `/home` is intentionally **not** a
default — scanning home directories on a busy host can be expensive; add it only
if your applications live there. The Go scan needs no roots (it uses the running
process list). Set `scan_languages = false` to disable language scanning entirely.

## Deploy across a fleet

Install the `.deb` and set the token — e.g. with Ansible:

```yaml
- apt: { deb: "/tmp/cobraagent_0.1.0_amd64.deb" }
- copy:
    dest: /etc/cobraagent/enrollment.token
    content: "{{ cve_enrollment_token }}"
    mode: "0600"
- lineinfile:
    path: /etc/cobraagent/cobraagent.conf
    regexp: '^server_url'
    line: 'server_url = https://cve.example.com'
- systemd: { name: cobraagent, enabled: true, state: started }
```

For many hosts, publish the `.deb` in an internal apt repo and let config
management install `cobraagent` + drop the token file.

## Tuning footprint

The systemd unit sets the enforced ceilings (`CPUQuota=15%`, `MemoryMax=256M`,
`Nice=15`, …). The config knobs (`max_procs`, `memory_limit_mib`, `gc_percent`,
`interval`, `jitter_fraction`) let the agent stay comfortably under them and
spread reporting across the fleet. A scan on a typical host completes in well
under a second and the process is idle in between.

## Test locally

```sh
./build/cobraagent --version
./build/cobraagent --config ./my.conf --once   # single scan, then exit
```

## Server contract (what part 2 must implement)

Two HTTPS endpoints; payloads are defined in `internal/model/model.go`.

- `POST /api/v1/agents/enroll`
  Body: `EnrollRequest` (includes `enrollment_token`).
  Validate the token, create/lookup an agent by `machine_id`, return
  `EnrollResponse { agent_id, api_token }`.

- `POST /api/v1/agents/{agent_id}/report`  — `Authorization: Bearer <api_token>`
  Body: `Report` (host info + full package list with `running` flags +
  `unmanaged_running_files`). Match `source`/`source_version` against the
  **Debian Security Tracker** for the host's release (not raw NVD CPE ranges —
  Debian backports fixes without bumping upstream versions). Return
  `ReportResponse { received, vulnerabilities_found }`.

## Layout

```
agent/
  main.go                     entrypoint: limits, enroll, scan loop
  internal/model/             shared wire types (keep in sync with server)
  internal/config/            key=value config loader, HTTPS enforcement
  internal/inventory/         dpkg inventory, /proc scan, report assembly
  internal/client/            HTTPS client, enrollment, credential storage
  packaging/                  systemd unit, example config, nfpm.yaml, scripts
```
