package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Postgres is the production Store backed by PostgreSQL.
type Postgres struct{ db *sql.DB }

// OpenPostgres connects using a lib/pq DSN, e.g.
// "postgres://user:pass@host:5432/cobra?sslmode=require".
func OpenPostgres(dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Postgres{db: db}, nil
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	username   TEXT PRIMARY KEY,
	pass_hash  TEXT NOT NULL,
	is_admin   BOOL NOT NULL DEFAULT FALSE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS enrollment_tokens (
	token       TEXT PRIMARY KEY,
	description TEXT NOT NULL DEFAULT '',
	max_uses    INT  NOT NULL DEFAULT 0,
	uses        INT  NOT NULL DEFAULT 0,
	revoked     BOOL NOT NULL DEFAULT FALSE,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agents (
	id            TEXT PRIMARY KEY,
	machine_id    TEXT UNIQUE NOT NULL,
	hostname      TEXT NOT NULL DEFAULT '',
	os_id         TEXT NOT NULL DEFAULT '',
	os_version_id TEXT NOT NULL DEFAULT '',
	arch          TEXT NOT NULL DEFAULT '',
	kernel        TEXT NOT NULL DEFAULT '',
	agent_version TEXT NOT NULL DEFAULT '',
	api_token_hash TEXT NOT NULL,
	enrolled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	tags          JSONB NOT NULL DEFAULT '{}',
	reported_tags JSONB NOT NULL DEFAULT '{}'
);
ALTER TABLE agents ADD COLUMN IF NOT EXISTS tags JSONB NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS reported_tags JSONB NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS agents_token_idx ON agents(api_token_hash);
CREATE TABLE IF NOT EXISTS findings (
	id                BIGSERIAL PRIMARY KEY,
	agent_id          TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	cve               TEXT NOT NULL,
	source_package    TEXT NOT NULL,
	ecosystem         TEXT NOT NULL DEFAULT '',
	installed_version TEXT NOT NULL,
	fixed_version     TEXT NOT NULL DEFAULT '',
	urgency           TEXT NOT NULL DEFAULT '',
	status            TEXT NOT NULL DEFAULT '',
	running           BOOL NOT NULL DEFAULT FALSE,
	description       TEXT NOT NULL DEFAULT '',
	first_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
	resolved_at       TIMESTAMPTZ
);
-- At most one OPEN episode per (agent, cve, source_package, ecosystem); resolved episodes accumulate.
CREATE UNIQUE INDEX IF NOT EXISTS findings_open_idx ON findings(agent_id, cve, source_package, ecosystem) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS findings_agent_open_idx ON findings(agent_id) WHERE resolved_at IS NULL;
CREATE TABLE IF NOT EXISTS osv_pkg (
	ecosystem  TEXT NOT NULL,
	name       TEXT NOT NULL,
	vuln_id    TEXT NOT NULL,
	advisory   JSONB NOT NULL,
	PRIMARY KEY (ecosystem, name, vuln_id)
);
CREATE INDEX IF NOT EXISTS osv_pkg_lookup_idx ON osv_pkg(ecosystem, name);
CREATE TABLE IF NOT EXISTS triage (
	agent_id       TEXT NOT NULL,
	cve            TEXT NOT NULL,
	source_package TEXT NOT NULL,
	ecosystem      TEXT NOT NULL DEFAULT '',
	state          TEXT NOT NULL,
	until_ts       TIMESTAMPTZ,
	note           TEXT NOT NULL DEFAULT '',
	actor          TEXT NOT NULL DEFAULT '',
	updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (agent_id, cve, source_package, ecosystem)
);
CREATE TABLE IF NOT EXISTS triage_events (
	id             BIGSERIAL PRIMARY KEY,
	ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
	actor          TEXT NOT NULL DEFAULT '',
	action         TEXT NOT NULL,
	agent_id       TEXT NOT NULL,
	cve            TEXT NOT NULL,
	source_package TEXT NOT NULL,
	ecosystem      TEXT NOT NULL DEFAULT '',
	until_ts       TIMESTAMPTZ,
	note           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS triage_events_ts_idx ON triage_events(ts DESC);
ALTER TABLE cve ADD COLUMN IF NOT EXISTS affected_symbols TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS reachability TEXT NOT NULL DEFAULT 'installed';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS running_binaries TEXT NOT NULL DEFAULT '[]';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS running_pid INT NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS debian_tracker (
	source_package TEXT NOT NULL,
	cve            TEXT NOT NULL,
	release        TEXT NOT NULL,
	status         TEXT NOT NULL DEFAULT '',
	fixed_version  TEXT NOT NULL DEFAULT '',
	urgency        TEXT NOT NULL DEFAULT '',
	description    TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (source_package, cve, release)
);
CREATE INDEX IF NOT EXISTS tracker_pkg_rel_idx ON debian_tracker(source_package, release);
CREATE TABLE IF NOT EXISTS cve (
	cve           TEXT PRIMARY KEY,
	cvss_score    DOUBLE PRECISION NOT NULL DEFAULT 0,
	cvss_severity TEXT NOT NULL DEFAULT 'UNKNOWN',
	cvss_vector   TEXT NOT NULL DEFAULT '',
	source        TEXT NOT NULL DEFAULT '',
	summary       TEXT NOT NULL DEFAULT '',
	aliases       TEXT[] NOT NULL DEFAULT '{}',
	refs          TEXT[] NOT NULL DEFAULT '{}',
	published     TIMESTAMPTZ,
	modified      TIMESTAMPTZ,
	kev_listed      BOOL NOT NULL DEFAULT FALSE,
	kev_date_added  TIMESTAMPTZ,
	kev_due_date    TIMESTAMPTZ,
	kev_ransomware  BOOL NOT NULL DEFAULT FALSE,
	epss_score      DOUBLE PRECISION NOT NULL DEFAULT 0,
	epss_percentile DOUBLE PRECISION NOT NULL DEFAULT 0,
	affected_symbols TEXT[] NOT NULL DEFAULT '{}'
);
-- Additive columns for databases created before KEV/EPSS support:
ALTER TABLE cve ADD COLUMN IF NOT EXISTS kev_listed BOOL NOT NULL DEFAULT FALSE;
ALTER TABLE cve ADD COLUMN IF NOT EXISTS kev_date_added TIMESTAMPTZ;
ALTER TABLE cve ADD COLUMN IF NOT EXISTS kev_due_date TIMESTAMPTZ;
ALTER TABLE cve ADD COLUMN IF NOT EXISTS kev_ransomware BOOL NOT NULL DEFAULT FALSE;
ALTER TABLE cve ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cve ADD COLUMN IF NOT EXISTS epss_percentile DOUBLE PRECISION NOT NULL DEFAULT 0;
`

// Migrate creates tables and indexes if they do not exist.
func (p *Postgres) Migrate() error {
	_, err := p.db.Exec(schema)
	return err
}

func (p *Postgres) CreateEnrollmentToken(t EnrollmentToken) error {
	_, err := p.db.Exec(
		`INSERT INTO enrollment_tokens(token,description,max_uses,uses,revoked)
		 VALUES($1,$2,$3,$4,$5)`,
		t.Token, t.Description, t.MaxUses, t.Uses, t.Revoked)
	return err
}

func (p *Postgres) ConsumeEnrollmentToken(token string) error {
	// Atomic: only increments when the token is valid and not exhausted.
	res, err := p.db.Exec(
		`UPDATE enrollment_tokens SET uses = uses + 1
		 WHERE token = $1 AND revoked = FALSE AND (max_uses = 0 OR uses < max_uses)`,
		token)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTokenInvalid
	}
	return nil
}

func (p *Postgres) UpsertAgent(a model.Agent) (model.Agent, error) {
	// Reuse the existing id for a known machine; rotate token + host fields.
	err := p.db.QueryRow(
		`INSERT INTO agents(id,machine_id,hostname,os_id,os_version_id,arch,kernel,agent_version,api_token_hash)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (machine_id) DO UPDATE SET
		   hostname=EXCLUDED.hostname, os_id=EXCLUDED.os_id, os_version_id=EXCLUDED.os_version_id,
		   arch=EXCLUDED.arch, kernel=EXCLUDED.kernel, agent_version=EXCLUDED.agent_version,
		   api_token_hash=EXCLUDED.api_token_hash, last_seen_at=now()
		 RETURNING id, enrolled_at, last_seen_at`,
		a.ID, a.MachineID, a.Hostname, a.OSID, a.OSVersionID, a.Arch, a.Kernel, a.AgentVersion, a.APITokenHash,
	).Scan(&a.ID, &a.EnrolledAt, &a.LastSeenAt)
	return a, err
}

func (p *Postgres) AgentByTokenHash(hash string) (model.Agent, error) {
	return p.scanAgent(p.db.QueryRow(agentCols+` WHERE api_token_hash=$1`, hash))
}

func (p *Postgres) GetAgent(id string) (model.Agent, error) {
	return p.scanAgent(p.db.QueryRow(agentCols+` WHERE id=$1`, id))
}

const agentCols = `SELECT id,machine_id,hostname,os_id,os_version_id,arch,kernel,agent_version,api_token_hash,enrolled_at,last_seen_at,tags,reported_tags FROM agents`

func (p *Postgres) scanAgent(row *sql.Row) (model.Agent, error) {
	var a model.Agent
	var tags, reported []byte
	err := row.Scan(&a.ID, &a.MachineID, &a.Hostname, &a.OSID, &a.OSVersionID, &a.Arch,
		&a.Kernel, &a.AgentVersion, &a.APITokenHash, &a.EnrolledAt, &a.LastSeenAt, &tags, &reported)
	if err == sql.ErrNoRows {
		return a, ErrNotFound
	}
	a.Tags = unmarshalTags(tags)
	a.ReportedTags = unmarshalTags(reported)
	return a, err
}

func unmarshalTags(b []byte) map[string]string {
	if len(b) == 0 {
		return nil
	}
	m := map[string]string{}
	_ = json.Unmarshal(b, &m)
	return m
}

func (p *Postgres) TouchAgent(id string) error {
	_, err := p.db.Exec(`UPDATE agents SET last_seen_at=now() WHERE id=$1`, id)
	return err
}

func (p *Postgres) ListAgents() ([]model.AgentSummary, error) {
	rows, err := p.db.Query(agentCols + ` ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.AgentSummary
	for rows.Next() {
		var a model.Agent
		var tags, reported []byte
		if err := rows.Scan(&a.ID, &a.MachineID, &a.Hostname, &a.OSID, &a.OSVersionID, &a.Arch,
			&a.Kernel, &a.AgentVersion, &a.APITokenHash, &a.EnrolledAt, &a.LastSeenAt, &tags, &reported); err != nil {
			return nil, err
		}
		a.Tags = unmarshalTags(tags)
		a.ReportedTags = unmarshalTags(reported)
		out = append(out, model.AgentSummary{Agent: a, SeverityCounts: map[string]int{}})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Aggregate finding counts per agent, by CVSS severity (joined from cve).
	cnt, err := p.db.Query(
		`SELECT f.agent_id, COALESCE(c.cvss_severity,'UNKNOWN'), f.running, count(*)
		 FROM findings f
		 LEFT JOIN cve c ON c.cve = f.cve
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.resolved_at IS NULL
		   AND NOT COALESCE(t.state='muted' OR (t.state IN ('snoozed','risk_accepted') AND (t.until_ts IS NULL OR t.until_ts > now())), false)
		 GROUP BY f.agent_id, COALESCE(c.cvss_severity,'UNKNOWN'), f.running`)
	if err != nil {
		return nil, err
	}
	defer cnt.Close()
	byID := map[string]*model.AgentSummary{}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	for cnt.Next() {
		var id, sev string
		var running bool
		var n int
		if err := cnt.Scan(&id, &sev, &running, &n); err != nil {
			return nil, err
		}
		if s := byID[id]; s != nil {
			s.FindingCount += n
			if running {
				s.RunningCount += n
			}
			s.SeverityCounts[sev] += n
		}
	}
	if err := cnt.Err(); err != nil {
		return nil, err
	}
	// KEV finding count per agent (excluding suppressed).
	krows, err := p.db.Query(
		`SELECT f.agent_id, count(*)
		 FROM findings f
		 JOIN cve c ON c.cve = f.cve AND c.kev_listed
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.resolved_at IS NULL
		   AND NOT COALESCE(t.state='muted' OR (t.state IN ('snoozed','risk_accepted') AND (t.until_ts IS NULL OR t.until_ts > now())), false)
		 GROUP BY f.agent_id`)
	if err != nil {
		return nil, err
	}
	defer krows.Close()
	for krows.Next() {
		var id string
		var n int
		if err := krows.Scan(&id, &n); err != nil {
			return nil, err
		}
		if s := byID[id]; s != nil {
			s.KEVCount = n
		}
	}
	return out, krows.Err()
}

func (p *Postgres) ReconcileFindings(agentID string, current []model.Finding, observedAt time.Time) ([]model.Finding, []model.Finding, error) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	tx, err := p.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	// Stage the current finding keys in a temp table for set operations.
	if _, err := tx.Exec(`CREATE TEMP TABLE cur (cve TEXT, source_package TEXT, ecosystem TEXT) ON COMMIT DROP`); err != nil {
		return nil, nil, err
	}
	if len(current) > 0 {
		st, err := tx.Prepare(`INSERT INTO cur(cve, source_package, ecosystem) VALUES($1,$2,$3)`)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range current {
			if _, err := st.Exec(f.CVE, f.SourcePackage, f.Ecosystem); err != nil {
				st.Close()
				return nil, nil, err
			}
		}
		st.Close()
	}

	// Resolve open episodes that are no longer present; return them.
	rrows, err := tx.Query(
		`UPDATE findings f SET resolved_at=$2
		 WHERE f.agent_id=$1 AND f.resolved_at IS NULL
		   AND NOT EXISTS (SELECT 1 FROM cur c WHERE c.cve=f.cve AND c.source_package=f.source_package AND c.ecosystem=f.ecosystem)
		 RETURNING cve, source_package, ecosystem, installed_version, fixed_version, urgency, status, running, description`,
		agentID, observedAt)
	if err != nil {
		return nil, nil, err
	}
	var resolved []model.Finding
	for rrows.Next() {
		var f model.Finding
		if err := rrows.Scan(&f.CVE, &f.SourcePackage, &f.Ecosystem, &f.InstalledVersion, &f.FixedVersion,
			&f.Urgency, &f.Status, &f.Running, &f.Description); err != nil {
			rrows.Close()
			return nil, nil, err
		}
		resolved = append(resolved, f)
	}
	rrows.Close()
	if err := rrows.Err(); err != nil {
		return nil, nil, err
	}

	// Insert or refresh each current finding's open episode. RETURNING (xmax=0)
	// tells us which rows were freshly inserted (i.e. newly appeared).
	up, err := tx.Prepare(
		`INSERT INTO findings(agent_id,cve,source_package,ecosystem,installed_version,fixed_version,urgency,status,running,reachability,running_binaries,running_pid,description,first_seen,last_seen)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
		 ON CONFLICT (agent_id,cve,source_package,ecosystem) WHERE resolved_at IS NULL
		 DO UPDATE SET installed_version=EXCLUDED.installed_version, fixed_version=EXCLUDED.fixed_version,
		   urgency=EXCLUDED.urgency, status=EXCLUDED.status, running=EXCLUDED.running,
		   reachability=EXCLUDED.reachability, running_binaries=EXCLUDED.running_binaries, running_pid=EXCLUDED.running_pid, description=EXCLUDED.description, last_seen=EXCLUDED.last_seen
		 RETURNING (xmax = 0) AS inserted`)
	if err != nil {
		return nil, nil, err
	}
	defer up.Close()
	var appeared []model.Finding
	for _, f := range current {
		var inserted bool
		if err := up.QueryRow(agentID, f.CVE, f.SourcePackage, f.Ecosystem, f.InstalledVersion, f.FixedVersion,
			f.Urgency, f.Status, f.Running, f.Reachability, string(marshalStrs(f.RunningBinaries)), f.RunningPID, f.Description, observedAt).Scan(&inserted); err != nil {
			return nil, nil, err
		}
		if inserted {
			appeared = append(appeared, f)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return appeared, resolved, nil
}

func (p *Postgres) FindingLifecycles() ([]model.FindingLifecycle, error) {
	rows, err := p.db.Query(
		`SELECT f.agent_id, a.hostname, f.cve, f.source_package,
		        COALESCE(c.cvss_severity,'UNKNOWN'), f.running, f.first_seen, f.last_seen, f.resolved_at
		 FROM findings f
		 JOIN agents a ON a.id=f.agent_id
		 LEFT JOIN cve c ON c.cve=f.cve`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.FindingLifecycle
	for rows.Next() {
		var l model.FindingLifecycle
		var resolved sql.NullTime
		if err := rows.Scan(&l.AgentID, &l.Hostname, &l.CVE, &l.SourcePackage,
			&l.CVSSSeverity, &l.Running, &l.FirstSeen, &l.LastSeen, &resolved); err != nil {
			return nil, err
		}
		l.ResolvedAt = resolved.Time
		out = append(out, l)
	}
	return out, rows.Err()
}

func (p *Postgres) ListFindings(agentID string) ([]model.Finding, error) {
	rows, err := p.db.Query(
		`SELECT f.cve,f.source_package,f.ecosystem,f.installed_version,f.fixed_version,f.urgency,f.status,f.running,f.reachability,COALESCE(f.running_binaries,'[]'),COALESCE(f.running_pid,0),f.description,
		        COALESCE(c.cvss_score,0), COALESCE(c.cvss_severity,'UNKNOWN'), COALESCE(c.cvss_vector,''),
		        COALESCE(c.kev_listed,false), COALESCE(c.epss_score,0), COALESCE(c.epss_percentile,0),
		        f.first_seen, f.last_seen,
		        COALESCE(t.state,''), t.until_ts, COALESCE(t.note,'')
		 FROM findings f
		 LEFT JOIN cve c ON c.cve = f.cve
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.agent_id=$1 AND f.resolved_at IS NULL
		 ORDER BY f.running DESC, COALESCE(c.cvss_score,0) DESC, f.cve`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		var f model.Finding
		var triageUntil sql.NullTime
		var runBins string
		if err := rows.Scan(&f.CVE, &f.SourcePackage, &f.Ecosystem, &f.InstalledVersion, &f.FixedVersion,
			&f.Urgency, &f.Status, &f.Running, &f.Reachability, &runBins, &f.RunningPID, &f.Description,
			&f.CVSSScore, &f.CVSSSeverity, &f.CVSSVector,
			&f.KEVListed, &f.EPSSScore, &f.EPSSPercentile, &f.FirstSeen, &f.LastSeen,
			&f.TriageState, &triageUntil, &f.TriageNote); err != nil {
			return nil, err
		}
		f.RunningBinaries = unmarshalStrs([]byte(runBins))
		f.TriageUntil = triageUntil.Time
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *Postgres) ListCVEs() ([]model.CVESummary, error) {
	rows, err := p.db.Query(
		`SELECT f.cve, COALESCE(c.cvss_severity,'UNKNOWN'), COALESCE(c.cvss_score,0), COALESCE(c.summary,''),
		        count(DISTINCT f.agent_id),
		        count(DISTINCT f.agent_id) FILTER (WHERE f.running),
		        COALESCE(c.kev_listed,false), COALESCE(c.epss_score,0)
		 FROM findings f
		 LEFT JOIN cve c ON c.cve = f.cve
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.resolved_at IS NULL
		   AND NOT COALESCE(t.state='muted' OR (t.state IN ('snoozed','risk_accepted') AND (t.until_ts IS NULL OR t.until_ts > now())), false)
		 GROUP BY f.cve, c.cvss_severity, c.cvss_score, c.summary, c.kev_listed, c.epss_score`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.CVESummary
	for rows.Next() {
		var s model.CVESummary
		if err := rows.Scan(&s.CVE, &s.CVSSSeverity, &s.CVSSScore, &s.Summary,
			&s.AffectedHosts, &s.RunningHosts, &s.KEVListed, &s.EPSSScore); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) HostsForCVE(cve string) ([]model.CVEHost, error) {
	rows, err := p.db.Query(
		`SELECT f.agent_id, a.hostname, a.os_id, a.os_version_id, f.source_package, f.ecosystem,
		        f.installed_version, f.fixed_version, f.running, f.reachability, f.status
		 FROM findings f JOIN agents a ON a.id = f.agent_id
		 WHERE f.cve=$1 AND f.resolved_at IS NULL
		 ORDER BY f.running DESC, a.hostname`, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.CVEHost
	for rows.Next() {
		var h model.CVEHost
		if err := rows.Scan(&h.AgentID, &h.Hostname, &h.OSID, &h.OSVersionID, &h.SourcePackage, &h.Ecosystem,
			&h.InstalledVersion, &h.FixedVersion, &h.Running, &h.Reachability, &h.Status); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (p *Postgres) ReplaceTracker(advs []model.Advisory) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`TRUNCATE debian_tracker`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		`INSERT INTO debian_tracker(source_package,cve,release,status,fixed_version,urgency,description)
		 VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range advs {
		if _, err := stmt.Exec(a.SourcePackage, a.CVE, a.Release, a.Status,
			a.FixedVersion, a.Urgency, a.Description); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MergeTracker upserts advisories by primary key, leaving rows absent from advs
// untouched (additive load for restarts/refreshes).
func (p *Postgres) MergeTracker(advs []model.Advisory) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(
		`INSERT INTO debian_tracker(source_package,cve,release,status,fixed_version,urgency,description)
		 VALUES($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (source_package,cve,release) DO UPDATE SET
		   status=EXCLUDED.status, fixed_version=EXCLUDED.fixed_version,
		   urgency=EXCLUDED.urgency, description=EXCLUDED.description`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range advs {
		if _, err := stmt.Exec(a.SourcePackage, a.CVE, a.Release, a.Status,
			a.FixedVersion, a.Urgency, a.Description); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (p *Postgres) ForPackage(src, release string) []model.Advisory {
	rows, err := p.db.Query(
		`SELECT cve,source_package,release,status,fixed_version,urgency,description
		 FROM debian_tracker WHERE source_package=$1 AND release=$2`, src, release)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []model.Advisory
	for rows.Next() {
		var a model.Advisory
		if err := rows.Scan(&a.CVE, &a.SourcePackage, &a.Release, &a.Status,
			&a.FixedVersion, &a.Urgency, &a.Description); err != nil {
			return out
		}
		out = append(out, a)
	}
	return out
}

func (p *Postgres) TrackerCount() (int, error) {
	var n int
	err := p.db.QueryRow(`SELECT count(*) FROM debian_tracker`).Scan(&n)
	return n, err
}

func (p *Postgres) DistinctTrackerCVEs() ([]string, error) {
	rows, err := p.db.Query(`SELECT DISTINCT cve FROM debian_tracker`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) UpsertEnrichment(e model.Enrichment) error {
	_, err := p.db.Exec(
		`INSERT INTO cve(cve,cvss_score,cvss_severity,cvss_vector,source,summary,aliases,refs,published,modified)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (cve) DO UPDATE SET
		   cvss_score=EXCLUDED.cvss_score, cvss_severity=EXCLUDED.cvss_severity,
		   cvss_vector=EXCLUDED.cvss_vector, source=EXCLUDED.source, summary=EXCLUDED.summary,
		   aliases=EXCLUDED.aliases, refs=EXCLUDED.refs,
		   published=EXCLUDED.published, modified=EXCLUDED.modified`,
		e.CVE, e.CVSSScore, e.CVSSSeverity, e.CVSSVector, e.Source, e.Summary,
		pq.Array(e.Aliases), pq.Array(e.References), nullTime(e.Published), nullTime(e.Modified))
	return err
}

func (p *Postgres) EnrichmentFor(cve string) (model.Enrichment, bool, error) {
	var e model.Enrichment
	var pub, mod sql.NullTime
	var kevAdded, kevDue sql.NullTime
	err := p.db.QueryRow(
		`SELECT cve,cvss_score,cvss_severity,cvss_vector,source,summary,aliases,refs,published,modified,
		        kev_listed,kev_date_added,kev_due_date,kev_ransomware,epss_score,epss_percentile,affected_symbols
		 FROM cve WHERE cve=$1`, cve).
		Scan(&e.CVE, &e.CVSSScore, &e.CVSSSeverity, &e.CVSSVector, &e.Source, &e.Summary,
			pq.Array(&e.Aliases), pq.Array(&e.References), &pub, &mod,
			&e.KEVListed, &kevAdded, &kevDue, &e.KEVRansomware, &e.EPSSScore, &e.EPSSPercentile, pq.Array(&e.AffectedSymbols))
	if err == sql.ErrNoRows {
		return model.Enrichment{}, false, nil
	}
	if err != nil {
		return model.Enrichment{}, false, err
	}
	e.Published, e.Modified = pub.Time, mod.Time
	e.KEVDateAdded, e.KEVDueDate = kevAdded.Time, kevDue.Time
	return e, true, nil
}

func (p *Postgres) UpsertKEV(cve string, dateAdded, dueDate time.Time, ransomware bool) error {
	_, err := p.db.Exec(
		`INSERT INTO cve(cve,cvss_severity,kev_listed,kev_date_added,kev_due_date,kev_ransomware)
		 VALUES($1,'UNKNOWN',TRUE,$2,$3,$4)
		 ON CONFLICT (cve) DO UPDATE SET kev_listed=TRUE,
		   kev_date_added=EXCLUDED.kev_date_added, kev_due_date=EXCLUDED.kev_due_date,
		   kev_ransomware=EXCLUDED.kev_ransomware`,
		cve, nullTime(dateAdded), nullTime(dueDate), ransomware)
	return err
}

func (p *Postgres) UpsertEPSS(cve string, score, percentile float64) error {
	_, err := p.db.Exec(
		`INSERT INTO cve(cve,cvss_severity,epss_score,epss_percentile)
		 VALUES($1,'UNKNOWN',$2,$3)
		 ON CONFLICT (cve) DO UPDATE SET epss_score=EXCLUDED.epss_score, epss_percentile=EXCLUDED.epss_percentile`,
		cve, score, percentile)
	return err
}

func (p *Postgres) EnrichedCVEs() (map[string]bool, error) {
	rows, err := p.db.Query(`SELECT cve FROM cve`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out[c] = true
	}
	return out, rows.Err()
}

func (p *Postgres) EnrichmentCount() (int, error) {
	var n int
	err := p.db.QueryRow(`SELECT count(*) FROM cve`).Scan(&n)
	return n, err
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// MergeOSVPackages upserts advisories by (ecosystem,name,vuln_id) without a
// TRUNCATE, so restarts/refreshes are incremental (no empty window).
func (p *Postgres) MergeOSVPackages(advs []model.LangAdvisory) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO osv_pkg(ecosystem,name,vuln_id,advisory) VALUES($1,$2,$3,$4) ` +
		`ON CONFLICT (ecosystem,name,vuln_id) DO UPDATE SET advisory=EXCLUDED.advisory`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range advs {
		blob, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(a.Ecosystem, a.Package, a.VulnID, blob); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (p *Postgres) ReplaceOSVPackages(advs []model.LangAdvisory) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`TRUNCATE osv_pkg`); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO osv_pkg(ecosystem,name,vuln_id,advisory) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range advs {
		blob, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(a.Ecosystem, a.Package, a.VulnID, blob); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (p *Postgres) ForLangPackage(ecosystem, name string) []model.LangAdvisory {
	rows, err := p.db.Query(`SELECT advisory FROM osv_pkg WHERE ecosystem=$1 AND name=$2`, ecosystem, name)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []model.LangAdvisory
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return out
		}
		var a model.LangAdvisory
		if json.Unmarshal(blob, &a) == nil {
			out = append(out, a)
		}
	}
	return out
}

func (p *Postgres) OSVPackageCount() (int, error) {
	var n int
	err := p.db.QueryRow(`SELECT count(*) FROM osv_pkg`).Scan(&n)
	return n, err
}

func (p *Postgres) SetTriage(t model.Triage) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if t.State == "" || t.State == model.TriageActive {
		if _, err := tx.Exec(
			`DELETE FROM triage WHERE agent_id=$1 AND cve=$2 AND source_package=$3 AND ecosystem=$4`,
			t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(
			`INSERT INTO triage(agent_id,cve,source_package,ecosystem,state,until_ts,note,actor,updated_at)
			 VALUES($1,$2,$3,$4,$5,$6,$7,$8,now())
			 ON CONFLICT (agent_id,cve,source_package,ecosystem) DO UPDATE SET
			   state=EXCLUDED.state, until_ts=EXCLUDED.until_ts, note=EXCLUDED.note,
			   actor=EXCLUDED.actor, updated_at=now()`,
			t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem, t.State, nullTime(t.Until), t.Note, t.Actor); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO triage_events(actor,action,agent_id,cve,source_package,ecosystem,until_ts,note)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		t.Actor, t.State, t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem, nullTime(t.Until), t.Note); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *Postgres) TriageFor(agentID, cve, source, eco string) (model.Triage, bool, error) {
	var t model.Triage
	var until sql.NullTime
	err := p.db.QueryRow(
		`SELECT agent_id,cve,source_package,ecosystem,state,until_ts,note,actor,updated_at
		 FROM triage WHERE agent_id=$1 AND cve=$2 AND source_package=$3 AND ecosystem=$4`,
		agentID, cve, source, eco).
		Scan(&t.AgentID, &t.CVE, &t.SourcePackage, &t.Ecosystem, &t.State, &until, &t.Note, &t.Actor, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return model.Triage{}, false, nil
	}
	if err != nil {
		return model.Triage{}, false, err
	}
	t.Until = until.Time
	return t, true, nil
}

func (p *Postgres) AuditLog(limit int) ([]model.TriageEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := p.db.Query(
		`SELECT e.ts, e.actor, e.action, e.agent_id, COALESCE(a.hostname,e.agent_id),
		        e.cve, e.source_package, e.ecosystem, e.until_ts, e.note
		 FROM triage_events e LEFT JOIN agents a ON a.id=e.agent_id
		 ORDER BY e.ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.TriageEvent
	for rows.Next() {
		var ev model.TriageEvent
		var until sql.NullTime
		if err := rows.Scan(&ev.When, &ev.Actor, &ev.Action, &ev.AgentID, &ev.Hostname,
			&ev.CVE, &ev.SourcePackage, &ev.Ecosystem, &until, &ev.Note); err != nil {
			return nil, err
		}
		ev.Until = until.Time
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (p *Postgres) SetAgentTags(agentID string, tags map[string]string) error {
	b, err := json.Marshal(tagsOrEmpty(tags))
	if err != nil {
		return err
	}
	_, err = p.db.Exec(`UPDATE agents SET tags=$2 WHERE id=$1`, agentID, b)
	return err
}

func (p *Postgres) SetReportedTags(agentID string, tags map[string]string) error {
	b, err := json.Marshal(tagsOrEmpty(tags))
	if err != nil {
		return err
	}
	_, err = p.db.Exec(`UPDATE agents SET reported_tags=$2 WHERE id=$1`, agentID, b)
	return err
}

func tagsOrEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func (p *Postgres) UpsertAffectedSymbols(cve string, symbols []string) error {
	_, err := p.db.Exec(
		`INSERT INTO cve(cve,cvss_severity,summary,aliases,refs,affected_symbols)
		 VALUES($1,'UNKNOWN','', '{}','{}',$2)
		 ON CONFLICT (cve) DO UPDATE SET affected_symbols=EXCLUDED.affected_symbols`,
		cve, pq.Array(symbols))
	return err
}

func (p *Postgres) CreateUser(u model.User) error {
	_, err := p.db.Exec(`INSERT INTO users(username,pass_hash,is_admin) VALUES($1,$2,$3)`,
		u.Username, u.PassHash, u.IsAdmin)
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return ErrExists
	}
	return err
}

func (p *Postgres) GetUser(username string) (model.User, bool, error) {
	var u model.User
	err := p.db.QueryRow(`SELECT username,pass_hash,is_admin,created_at,updated_at FROM users WHERE username=$1`, username).
		Scan(&u.Username, &u.PassHash, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return model.User{}, false, nil
	}
	return u, err == nil, err
}

func (p *Postgres) ListUsers() ([]model.User, error) {
	rows, err := p.db.Query(`SELECT username,pass_hash,is_admin,created_at,updated_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		if err := rows.Scan(&u.Username, &u.PassHash, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *Postgres) SetUserPassword(username, passHash string) error {
	res, err := p.db.Exec(`UPDATE users SET pass_hash=$2, updated_at=now() WHERE username=$1`, username, passHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) SetUserAdmin(username string, isAdmin bool) error {
	res, err := p.db.Exec(`UPDATE users SET is_admin=$2, updated_at=now() WHERE username=$1`, username, isAdmin)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteUser(username string) error {
	res, err := p.db.Exec(`DELETE FROM users WHERE username=$1`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) CountUsers() (int, error) {
	var n int
	err := p.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (p *Postgres) CountAdmins() (int, error) {
	var n int
	err := p.db.QueryRow(`SELECT count(*) FROM users WHERE is_admin`).Scan(&n)
	return n, err
}

func (p *Postgres) Close() error { return p.db.Close() }

func (p *Postgres) SearchAdvisories(q AdvisoryQuery) ([]model.Advisory, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	add := func(cond string, val any) { args = append(args, val); where += fmt.Sprintf(" AND %s$%d", cond, len(args)) }
	if q.Text != "" {
		args = append(args, "%"+strings.ToLower(q.Text)+"%")
		where += fmt.Sprintf(" AND (lower(cve) LIKE $%d OR lower(source_package) LIKE $%d OR lower(description) LIKE $%d)", len(args), len(args), len(args))
	}
	if q.SourcePackage != "" {
		args = append(args, "%"+strings.ToLower(q.SourcePackage)+"%")
		where += fmt.Sprintf(" AND lower(source_package) LIKE $%d", len(args))
	}
	if q.Release != "" {
		add("release=", q.Release)
	}
	if q.Status != "" {
		add("status=", q.Status)
	}
	var total int
	if err := p.db.QueryRow(`SELECT count(*) FROM debian_tracker `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, clampLimit(q.Limit), q.Offset)
	rows, err := p.db.Query(
		`SELECT cve,source_package,release,status,fixed_version,urgency,description FROM debian_tracker `+
			where+fmt.Sprintf(` ORDER BY cve DESC, source_package, release LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.Advisory
	for rows.Next() {
		var a model.Advisory
		if err := rows.Scan(&a.CVE, &a.SourcePackage, &a.Release, &a.Status, &a.FixedVersion, &a.Urgency, &a.Description); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (p *Postgres) AdvisoriesForCVE(cve string) ([]model.Advisory, error) {
	rows, err := p.db.Query(
		`SELECT cve,source_package,release,status,fixed_version,urgency,description
		 FROM debian_tracker WHERE cve=$1 ORDER BY source_package, release`, cve)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Advisory
	for rows.Next() {
		var a model.Advisory
		if err := rows.Scan(&a.CVE, &a.SourcePackage, &a.Release, &a.Status, &a.FixedVersion, &a.Urgency, &a.Description); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) TrackerReleases() ([]string, error) {
	rows, err := p.db.Query(`SELECT DISTINCT release FROM debian_tracker ORDER BY release`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) SearchCVEs(q CVEQuery) ([]model.Enrichment, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	if q.Text != "" {
		args = append(args, "%"+strings.ToLower(q.Text)+"%")
		where += fmt.Sprintf(" AND (lower(cve) LIKE $%d OR lower(summary) LIKE $%d)", len(args), len(args))
	}
	if q.Severity != "" {
		args = append(args, q.Severity)
		where += fmt.Sprintf(" AND cvss_severity=$%d", len(args))
	}
	if q.KEVOnly {
		where += " AND kev_listed"
	}
	var total int
	if err := p.db.QueryRow(`SELECT count(*) FROM cve `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, clampLimit(q.Limit), q.Offset)
	rows, err := p.db.Query(
		`SELECT cve,cvss_score,cvss_severity,summary,kev_listed,epss_score FROM cve `+
			where+fmt.Sprintf(` ORDER BY kev_listed DESC, cvss_score DESC, cve DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.Enrichment
	for rows.Next() {
		var e model.Enrichment
		if err := rows.Scan(&e.CVE, &e.CVSSScore, &e.CVSSSeverity, &e.Summary, &e.KEVListed, &e.EPSSScore); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
