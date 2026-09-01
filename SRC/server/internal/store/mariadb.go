package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/yourorg/cve-fleet/server/internal/model"
)

// Compile-time checks that every backend satisfies the Store interface.
var (
	_ Store = (*Memory)(nil)
	_ Store = (*Postgres)(nil)
	_ Store = (*MariaDB)(nil)
)

// MariaDB is a production Store backed by MariaDB/MySQL. It implements the same
// Store interface as Postgres; the SQL is translated to the MariaDB dialect.
//
// The "one open episode per finding identity" guarantee (a partial unique index
// in Postgres, which MariaDB lacks) is reproduced with a generated column
// `open_key` that equals a hash of the identity while the episode is open and
// NULL once resolved — NULLs don't collide, so resolved episodes accumulate.
type MariaDB struct{ db *sql.DB }

// OpenMariaDB connects using a go-sql-driver/mysql DSN. The DSN SHOULD set
// parseTime=true and loc=UTC, e.g.
// "user:pass@tcp(host:3306)/cobra?parseTime=true&loc=UTC&charset=utf8mb4".
func OpenMariaDB(dsn string) (*MariaDB, error) {
	if dsn != "" && !strings.Contains(dsn, "parseTime=") {
		if strings.Contains(dsn, "?") {
			dsn += "&parseTime=true&loc=UTC"
		} else {
			dsn += "?parseTime=true&loc=UTC"
		}
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping mariadb: %w", err)
	}
	return &MariaDB{db: db}, nil
}

// mariaSchema is a list of statements (go-sql-driver executes one per Exec unless
// multiStatements is enabled, so Migrate runs them individually).
const mariaSchema = `
CREATE TABLE IF NOT EXISTS users (
	username   VARCHAR(128) PRIMARY KEY,
	pass_hash  VARCHAR(255) NOT NULL,
	is_admin   BOOL NOT NULL DEFAULT FALSE,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS enrollment_tokens (
	token       VARCHAR(191) PRIMARY KEY,
	description TEXT NOT NULL,
	max_uses    INT  NOT NULL DEFAULT 0,
	uses        INT  NOT NULL DEFAULT 0,
	revoked     BOOL NOT NULL DEFAULT FALSE,
	created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS agents (
	id            VARCHAR(191) PRIMARY KEY,
	machine_id    VARCHAR(191) UNIQUE NOT NULL,
	hostname      VARCHAR(255) NOT NULL DEFAULT '',
	os_id         VARCHAR(64)  NOT NULL DEFAULT '',
	os_version_id VARCHAR(64)  NOT NULL DEFAULT '',
	arch          VARCHAR(32)  NOT NULL DEFAULT '',
	kernel        VARCHAR(128) NOT NULL DEFAULT '',
	agent_version VARCHAR(64)  NOT NULL DEFAULT '',
	api_token_hash VARCHAR(128) NOT NULL,
	enrolled_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	tags          JSON NOT NULL,
	reported_tags JSON NOT NULL,
	INDEX agents_token_idx (api_token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS findings (
	id                BIGINT AUTO_INCREMENT PRIMARY KEY,
	agent_id          VARCHAR(191) NOT NULL,
	cve               VARCHAR(64)  NOT NULL,
	source_package    VARCHAR(191) NOT NULL,
	ecosystem         VARCHAR(64)  NOT NULL DEFAULT '',
	installed_version VARCHAR(191) NOT NULL DEFAULT '',
	fixed_version     VARCHAR(191) NOT NULL DEFAULT '',
	urgency           VARCHAR(64)  NOT NULL DEFAULT '',
	status            VARCHAR(64)  NOT NULL DEFAULT '',
	running           BOOL NOT NULL DEFAULT FALSE,
	reachability      VARCHAR(32) NOT NULL DEFAULT 'installed',
	description       TEXT NOT NULL,
	first_seen        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	resolved_at       DATETIME NULL,
	open_key CHAR(32) AS (IF(resolved_at IS NULL, MD5(CONCAT_WS('|',agent_id,cve,source_package,ecosystem)), NULL)) VIRTUAL,
	UNIQUE KEY findings_open_uk (open_key),
	INDEX findings_agent_idx (agent_id),
	INDEX findings_cve_idx (cve),
	CONSTRAINT findings_agent_fk FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
ALTER TABLE findings ADD COLUMN IF NOT EXISTS running_binaries TEXT;
||
ALTER TABLE findings ADD COLUMN IF NOT EXISTS running_pid INT NOT NULL DEFAULT 0;
||
CREATE TABLE IF NOT EXISTS osv_pkg (
	ecosystem VARCHAR(64)  NOT NULL,
	name      VARCHAR(512) NOT NULL,
	vuln_id   VARCHAR(64)  NOT NULL,
	advisory  JSON NOT NULL,
	PRIMARY KEY (ecosystem, name, vuln_id),
	INDEX osv_pkg_lookup_idx (ecosystem, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS triage (
	agent_id       VARCHAR(191) NOT NULL,
	cve            VARCHAR(64)  NOT NULL,
	source_package VARCHAR(191) NOT NULL,
	ecosystem      VARCHAR(64)  NOT NULL DEFAULT '',
	state          VARCHAR(32)  NOT NULL,
	until_ts       DATETIME NULL,
	note           TEXT NOT NULL,
	actor          VARCHAR(128) NOT NULL DEFAULT '',
	updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (agent_id, cve, source_package, ecosystem)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS triage_events (
	id             BIGINT AUTO_INCREMENT PRIMARY KEY,
	ts             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	actor          VARCHAR(128) NOT NULL DEFAULT '',
	action         VARCHAR(32)  NOT NULL,
	agent_id       VARCHAR(191) NOT NULL,
	cve            VARCHAR(64)  NOT NULL,
	source_package VARCHAR(191) NOT NULL,
	ecosystem      VARCHAR(64)  NOT NULL DEFAULT '',
	until_ts       DATETIME NULL,
	note           TEXT NOT NULL,
	INDEX triage_events_ts_idx (ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS debian_tracker (
	source_package VARCHAR(191) NOT NULL,
	cve            VARCHAR(64)  NOT NULL,
	` + "`release`" + ` VARCHAR(32) NOT NULL,
	status         VARCHAR(64)  NOT NULL DEFAULT '',
	fixed_version  VARCHAR(191) NOT NULL DEFAULT '',
	urgency        VARCHAR(64)  NOT NULL DEFAULT '',
	description    TEXT NOT NULL,
	PRIMARY KEY (source_package, cve, ` + "`release`" + `),
	INDEX tracker_pkg_rel_idx (source_package, ` + "`release`" + `)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
||
CREATE TABLE IF NOT EXISTS cve (
	cve           VARCHAR(64) PRIMARY KEY,
	cvss_score    DOUBLE NOT NULL DEFAULT 0,
	cvss_severity VARCHAR(16) NOT NULL DEFAULT 'UNKNOWN',
	cvss_vector   VARCHAR(128) NOT NULL DEFAULT '',
	source        VARCHAR(32) NOT NULL DEFAULT '',
	summary       TEXT NOT NULL,
	aliases       JSON NOT NULL,
	refs          JSON NOT NULL,
	published     DATETIME NULL,
	modified      DATETIME NULL,
	kev_listed      BOOL NOT NULL DEFAULT FALSE,
	kev_date_added  DATETIME NULL,
	kev_due_date    DATETIME NULL,
	kev_ransomware  BOOL NOT NULL DEFAULT FALSE,
	epss_score      DOUBLE NOT NULL DEFAULT 0,
	epss_percentile DOUBLE NOT NULL DEFAULT 0,
	affected_symbols JSON NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 ROW_FORMAT=DYNAMIC;
`

// mariaSuppressed is the SQL predicate (on a LEFT JOINed triage alias `t`) that
// is true when a finding is triaged away. UTC_TIMESTAMP keeps expiry comparisons
// in UTC regardless of the server's time zone.
const mariaSuppressed = `COALESCE(t.state='muted' OR (t.state IN ('snoozed','risk_accepted') AND (t.until_ts IS NULL OR t.until_ts > UTC_TIMESTAMP())), 0)`

func (m *MariaDB) Migrate() error {
	for _, stmt := range strings.Split(mariaSchema, "||") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := m.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w\n%s", err, stmt)
		}
	}
	// Widen osv_pkg.name on databases created before it was enlarged. Long Go
	// module paths and scoped npm names exceed the original VARCHAR(191).
	var nlen sql.NullInt64
	_ = m.db.QueryRow(
		`SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS
		 WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='osv_pkg' AND COLUMN_NAME='name'`).Scan(&nlen)
	if nlen.Valid && nlen.Int64 < 512 {
		if _, err := m.db.Exec("ALTER TABLE osv_pkg MODIFY COLUMN name VARCHAR(512) NOT NULL"); err != nil {
			return fmt.Errorf("widen osv_pkg.name: %w", err)
		}
	}
	return nil
}

func (m *MariaDB) UpsertAffectedSymbols(cve string, symbols []string) error {
	_, err := m.db.Exec(
		`INSERT INTO cve(cve,cvss_severity,summary,aliases,refs,affected_symbols)
		 VALUES(?,'UNKNOWN','','[]','[]',?)
		 ON DUPLICATE KEY UPDATE affected_symbols=VALUES(affected_symbols)`,
		cve, marshalStrs(symbols))
	return err
}

func (m *MariaDB) CreateUser(u model.User) error {
	_, err := m.db.Exec(`INSERT INTO users(username,pass_hash,is_admin) VALUES(?,?,?)`,
		u.Username, u.PassHash, u.IsAdmin)
	if err != nil && strings.Contains(err.Error(), "Duplicate entry") {
		return ErrExists
	}
	return err
}

func (m *MariaDB) GetUser(username string) (model.User, bool, error) {
	var u model.User
	err := m.db.QueryRow(`SELECT username,pass_hash,is_admin,created_at,updated_at FROM users WHERE username=?`, username).
		Scan(&u.Username, &u.PassHash, &u.IsAdmin, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return model.User{}, false, nil
	}
	return u, err == nil, err
}

func (m *MariaDB) ListUsers() ([]model.User, error) {
	rows, err := m.db.Query(`SELECT username,pass_hash,is_admin,created_at,updated_at FROM users ORDER BY username`)
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

func (m *MariaDB) SetUserPassword(username, passHash string) error {
	res, err := m.db.Exec(`UPDATE users SET pass_hash=?, updated_at=UTC_TIMESTAMP() WHERE username=?`, passHash, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *MariaDB) SetUserAdmin(username string, isAdmin bool) error {
	res, err := m.db.Exec(`UPDATE users SET is_admin=?, updated_at=UTC_TIMESTAMP() WHERE username=?`, isAdmin, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *MariaDB) DeleteUser(username string) error {
	res, err := m.db.Exec(`DELETE FROM users WHERE username=?`, username)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (m *MariaDB) CountUsers() (int, error) {
	var n int
	err := m.db.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (m *MariaDB) CountAdmins() (int, error) {
	var n int
	err := m.db.QueryRow(`SELECT count(*) FROM users WHERE is_admin`).Scan(&n)
	return n, err
}

func (m *MariaDB) Close() error { return m.db.Close() }

// ---- Enrollment tokens ----

func (m *MariaDB) CreateEnrollmentToken(t EnrollmentToken) error {
	_, err := m.db.Exec(
		`INSERT INTO enrollment_tokens(token,description,max_uses,uses,revoked) VALUES(?,?,?,?,?)`,
		t.Token, t.Description, t.MaxUses, t.Uses, t.Revoked)
	if err != nil && strings.Contains(err.Error(), "Duplicate entry") {
		return ErrExists
	}
	return err
}

func (m *MariaDB) ConsumeEnrollmentToken(token string) error {
	res, err := m.db.Exec(
		`UPDATE enrollment_tokens SET uses = uses + 1
		 WHERE token = ? AND revoked = FALSE AND (max_uses = 0 OR uses < max_uses)`, token)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTokenInvalid
	}
	return nil
}

// ---- Agents ----

func (m *MariaDB) UpsertAgent(a model.Agent) (model.Agent, error) {
	// Reuse the id for a known machine; rotate token + host fields. Preserve tags.
	_, err := m.db.Exec(
		`INSERT INTO agents(id,machine_id,hostname,os_id,os_version_id,arch,kernel,agent_version,api_token_hash,tags,reported_tags)
		 VALUES(?,?,?,?,?,?,?,?,?,'{}','{}')
		 ON DUPLICATE KEY UPDATE
		   hostname=VALUES(hostname), os_id=VALUES(os_id), os_version_id=VALUES(os_version_id),
		   arch=VALUES(arch), kernel=VALUES(kernel), agent_version=VALUES(agent_version),
		   api_token_hash=VALUES(api_token_hash), last_seen_at=UTC_TIMESTAMP()`,
		a.ID, a.MachineID, a.Hostname, a.OSID, a.OSVersionID, a.Arch, a.Kernel, a.AgentVersion, a.APITokenHash)
	if err != nil {
		return model.Agent{}, err
	}
	// Return the canonical row (id may map to an existing machine).
	return m.scanAgentRow(m.db.QueryRow(mariaAgentCols+` WHERE machine_id=?`, a.MachineID))
}

func (m *MariaDB) AgentByTokenHash(hash string) (model.Agent, error) {
	return m.scanAgentRow(m.db.QueryRow(mariaAgentCols+` WHERE api_token_hash=?`, hash))
}

func (m *MariaDB) GetAgent(id string) (model.Agent, error) {
	return m.scanAgentRow(m.db.QueryRow(mariaAgentCols+` WHERE id=?`, id))
}

const mariaAgentCols = `SELECT id,machine_id,hostname,os_id,os_version_id,arch,kernel,agent_version,api_token_hash,enrolled_at,last_seen_at,tags,reported_tags FROM agents`

func (m *MariaDB) scanAgentRow(row *sql.Row) (model.Agent, error) {
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

func (m *MariaDB) TouchAgent(id string) error {
	_, err := m.db.Exec(`UPDATE agents SET last_seen_at=UTC_TIMESTAMP() WHERE id=?`, id)
	return err
}

func (m *MariaDB) ListAgents() ([]model.AgentSummary, error) {
	rows, err := m.db.Query(mariaAgentCols + ` ORDER BY hostname`)
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
	byID := map[string]*model.AgentSummary{}
	for i := range out {
		byID[out[i].ID] = &out[i]
	}
	// Severity breakdown per agent (excluding suppressed).
	cnt, err := m.db.Query(
		`SELECT f.agent_id, COALESCE(c.cvss_severity,'UNKNOWN'), f.running, count(*)
		 FROM findings f
		 LEFT JOIN cve c ON c.cve = f.cve
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.resolved_at IS NULL AND NOT ` + mariaSuppressed + `
		 GROUP BY f.agent_id, COALESCE(c.cvss_severity,'UNKNOWN'), f.running`)
	if err != nil {
		return nil, err
	}
	defer cnt.Close()
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
	krows, err := m.db.Query(
		`SELECT f.agent_id, count(*)
		 FROM findings f
		 JOIN cve c ON c.cve = f.cve AND c.kev_listed
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.resolved_at IS NULL AND NOT ` + mariaSuppressed + `
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

// ---- Findings lifecycle ----

func (m *MariaDB) ReconcileFindings(agentID string, current []model.Finding, observedAt time.Time) ([]model.Finding, []model.Finding, error) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	// Dedup current by identity, preserving first-seen order (matches Memory).
	curByKey := map[string]model.Finding{}
	order := []string{}
	for _, f := range current {
		k := f.CVE + "|" + f.SourcePackage + "|" + f.Ecosystem
		if _, ok := curByKey[k]; !ok {
			order = append(order, k)
		}
		curByKey[k] = f
	}

	tx, err := m.db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	// Load current open episodes for this agent.
	type openRow struct {
		id  int64
		fnd model.Finding
	}
	openByKey := map[string]openRow{}
	rows, err := tx.Query(
		`SELECT id,cve,source_package,ecosystem,first_seen FROM findings
		 WHERE agent_id=? AND resolved_at IS NULL FOR UPDATE`, agentID)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var r openRow
		if err := rows.Scan(&r.id, &r.fnd.CVE, &r.fnd.SourcePackage, &r.fnd.Ecosystem, &r.fnd.FirstSeen); err != nil {
			rows.Close()
			return nil, nil, err
		}
		openByKey[r.fnd.CVE+"|"+r.fnd.SourcePackage+"|"+r.fnd.Ecosystem] = r
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// Resolve open episodes no longer present; collect them for alerting.
	var resolved []model.Finding
	for k, r := range openByKey {
		if _, ok := curByKey[k]; ok {
			continue
		}
		var f model.Finding
		if err := tx.QueryRow(
			`SELECT cve,source_package,ecosystem,installed_version,fixed_version,urgency,status,running,description
			 FROM findings WHERE id=?`, r.id).
			Scan(&f.CVE, &f.SourcePackage, &f.Ecosystem, &f.InstalledVersion, &f.FixedVersion,
				&f.Urgency, &f.Status, &f.Running, &f.Description); err != nil {
			return nil, nil, err
		}
		if _, err := tx.Exec(`UPDATE findings SET resolved_at=? WHERE id=?`, observedAt, r.id); err != nil {
			return nil, nil, err
		}
		resolved = append(resolved, f)
	}

	// Insert new episodes / refresh existing ones; collect newly-appeared.
	var appeared []model.Finding
	for _, k := range order {
		f := curByKey[k]
		if r, ok := openByKey[k]; ok {
			if _, err := tx.Exec(
				`UPDATE findings SET installed_version=?, fixed_version=?, urgency=?, status=?, running=?, reachability=?, running_binaries=?, running_pid=?, description=?, last_seen=?
				 WHERE id=?`,
				f.InstalledVersion, f.FixedVersion, f.Urgency, f.Status, f.Running, f.Reachability, marshalStrs(f.RunningBinaries), f.RunningPID, f.Description, observedAt, r.id); err != nil {
				return nil, nil, err
			}
			continue
		}
		if _, err := tx.Exec(
			`INSERT INTO findings(agent_id,cve,source_package,ecosystem,installed_version,fixed_version,urgency,status,running,reachability,running_binaries,running_pid,description,first_seen,last_seen)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			agentID, f.CVE, f.SourcePackage, f.Ecosystem, f.InstalledVersion, f.FixedVersion,
			f.Urgency, f.Status, f.Running, f.Reachability, marshalStrs(f.RunningBinaries), f.RunningPID, f.Description, observedAt, observedAt); err != nil {
			return nil, nil, err
		}
		appeared = append(appeared, f)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return appeared, resolved, nil
}

func (m *MariaDB) FindingLifecycles() ([]model.FindingLifecycle, error) {
	rows, err := m.db.Query(
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

func (m *MariaDB) ListFindings(agentID string) ([]model.Finding, error) {
	rows, err := m.db.Query(
		`SELECT f.cve,f.source_package,f.ecosystem,f.installed_version,f.fixed_version,f.urgency,f.status,f.running,f.reachability,COALESCE(f.running_binaries,'[]'),COALESCE(f.running_pid,0),f.description,
		        COALESCE(c.cvss_score,0), COALESCE(c.cvss_severity,'UNKNOWN'), COALESCE(c.cvss_vector,''),
		        COALESCE(c.kev_listed,0), COALESCE(c.epss_score,0), COALESCE(c.epss_percentile,0),
		        f.first_seen, f.last_seen,
		        COALESCE(t.state,''), t.until_ts, COALESCE(t.note,'')
		 FROM findings f
		 LEFT JOIN cve c ON c.cve = f.cve
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.agent_id=? AND f.resolved_at IS NULL
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

func (m *MariaDB) ListCVEs() ([]model.CVESummary, error) {
	rows, err := m.db.Query(
		`SELECT f.cve, COALESCE(c.cvss_severity,'UNKNOWN'), COALESCE(c.cvss_score,0), COALESCE(c.summary,''),
		        count(DISTINCT f.agent_id),
		        count(DISTINCT CASE WHEN f.running THEN f.agent_id END),
		        COALESCE(c.kev_listed,0), COALESCE(c.epss_score,0)
		 FROM findings f
		 LEFT JOIN cve c ON c.cve = f.cve
		 LEFT JOIN triage t ON t.agent_id=f.agent_id AND t.cve=f.cve AND t.source_package=f.source_package AND t.ecosystem=f.ecosystem
		 WHERE f.resolved_at IS NULL AND NOT ` + mariaSuppressed + `
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

func (m *MariaDB) HostsForCVE(cve string) ([]model.CVEHost, error) {
	rows, err := m.db.Query(
		`SELECT f.agent_id, a.hostname, a.os_id, a.os_version_id, f.source_package, f.ecosystem,
		        f.installed_version, f.fixed_version, f.running, f.reachability, f.status
		 FROM findings f JOIN agents a ON a.id = f.agent_id
		 WHERE f.cve=? AND f.resolved_at IS NULL
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

// ---- Debian tracker ----

func (m *MariaDB) ReplaceTracker(advs []model.Advisory) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("TRUNCATE debian_tracker"); err != nil {
		return err
	}
	stmt, err := tx.Prepare(
		"INSERT IGNORE INTO debian_tracker(source_package,cve,`release`,status,fixed_version,urgency,description) VALUES(?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range advs {
		if _, err := stmt.Exec(a.SourcePackage, a.CVE, a.Release, a.Status, a.FixedVersion, a.Urgency, a.Description); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// MergeTracker upserts advisories by primary key, leaving rows absent from advs
// untouched (additive load for restarts/refreshes).
func (m *MariaDB) MergeTracker(advs []model.Advisory) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(
		"INSERT INTO debian_tracker(source_package,cve,`release`,status,fixed_version,urgency,description) VALUES(?,?,?,?,?,?,?) " +
			"ON DUPLICATE KEY UPDATE status=VALUES(status), fixed_version=VALUES(fixed_version), urgency=VALUES(urgency), description=VALUES(description)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, a := range advs {
		if _, err := stmt.Exec(a.SourcePackage, a.CVE, a.Release, a.Status, a.FixedVersion, a.Urgency, a.Description); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *MariaDB) ForPackage(src, release string) []model.Advisory {
	rows, err := m.db.Query(
		"SELECT cve,source_package,`release`,status,fixed_version,urgency,description FROM debian_tracker WHERE source_package=? AND `release`=?",
		src, release)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []model.Advisory
	for rows.Next() {
		var a model.Advisory
		if err := rows.Scan(&a.CVE, &a.SourcePackage, &a.Release, &a.Status, &a.FixedVersion, &a.Urgency, &a.Description); err != nil {
			return out
		}
		out = append(out, a)
	}
	return out
}

func (m *MariaDB) TrackerCount() (int, error) {
	var n int
	err := m.db.QueryRow(`SELECT count(*) FROM debian_tracker`).Scan(&n)
	return n, err
}

func (m *MariaDB) DistinctTrackerCVEs() ([]string, error) {
	rows, err := m.db.Query(`SELECT DISTINCT cve FROM debian_tracker`)
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

// ---- Enrichment (NVD/OSV + KEV/EPSS) ----

func (m *MariaDB) UpsertEnrichment(e model.Enrichment) error {
	_, err := m.db.Exec(
		`INSERT INTO cve(cve,cvss_score,cvss_severity,cvss_vector,source,summary,aliases,refs,published,modified,affected_symbols)
		 VALUES(?,?,?,?,?,?,?,?,?,?,'[]')
		 ON DUPLICATE KEY UPDATE
		   cvss_score=VALUES(cvss_score), cvss_severity=VALUES(cvss_severity), cvss_vector=VALUES(cvss_vector),
		   source=VALUES(source), summary=VALUES(summary), aliases=VALUES(aliases), refs=VALUES(refs),
		   published=VALUES(published), modified=VALUES(modified)`,
		e.CVE, e.CVSSScore, e.CVSSSeverity, e.CVSSVector, e.Source, e.Summary,
		marshalStrs(e.Aliases), marshalStrs(e.References), nullTime(e.Published), nullTime(e.Modified))
	return err
}

func (m *MariaDB) EnrichmentFor(cve string) (model.Enrichment, bool, error) {
	var e model.Enrichment
	var pub, mod, kevAdded, kevDue sql.NullTime
	var aliases, refs, affSyms []byte
	err := m.db.QueryRow(
		`SELECT cve,cvss_score,cvss_severity,cvss_vector,source,summary,aliases,refs,published,modified,
		        kev_listed,kev_date_added,kev_due_date,kev_ransomware,epss_score,epss_percentile,affected_symbols
		 FROM cve WHERE cve=?`, cve).
		Scan(&e.CVE, &e.CVSSScore, &e.CVSSSeverity, &e.CVSSVector, &e.Source, &e.Summary,
			&aliases, &refs, &pub, &mod,
			&e.KEVListed, &kevAdded, &kevDue, &e.KEVRansomware, &e.EPSSScore, &e.EPSSPercentile, &affSyms)
	if err == sql.ErrNoRows {
		return model.Enrichment{}, false, nil
	}
	if err != nil {
		return model.Enrichment{}, false, err
	}
	e.Aliases = unmarshalStrs(aliases)
	e.References = unmarshalStrs(refs)
	e.AffectedSymbols = unmarshalStrs(affSyms)
	e.Published, e.Modified = pub.Time, mod.Time
	e.KEVDateAdded, e.KEVDueDate = kevAdded.Time, kevDue.Time
	return e, true, nil
}

func (m *MariaDB) UpsertKEV(cve string, dateAdded, dueDate time.Time, ransomware bool) error {
	_, err := m.db.Exec(
		`INSERT INTO cve(cve,cvss_severity,summary,aliases,refs,affected_symbols,kev_listed,kev_date_added,kev_due_date,kev_ransomware)
		 VALUES(?,'UNKNOWN','','[]','[]','[]',TRUE,?,?,?)
		 ON DUPLICATE KEY UPDATE kev_listed=TRUE,
		   kev_date_added=VALUES(kev_date_added), kev_due_date=VALUES(kev_due_date), kev_ransomware=VALUES(kev_ransomware)`,
		cve, nullTime(dateAdded), nullTime(dueDate), ransomware)
	return err
}

func (m *MariaDB) UpsertEPSS(cve string, score, percentile float64) error {
	_, err := m.db.Exec(
		`INSERT INTO cve(cve,cvss_severity,summary,aliases,refs,affected_symbols,epss_score,epss_percentile)
		 VALUES(?,'UNKNOWN','','[]','[]','[]',?,?)
		 ON DUPLICATE KEY UPDATE epss_score=VALUES(epss_score), epss_percentile=VALUES(epss_percentile)`,
		cve, score, percentile)
	return err
}

func (m *MariaDB) EnrichedCVEs() (map[string]bool, error) {
	rows, err := m.db.Query(`SELECT cve FROM cve`)
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

func (m *MariaDB) EnrichmentCount() (int, error) {
	var n int
	err := m.db.QueryRow(`SELECT count(*) FROM cve`).Scan(&n)
	return n, err
}

// ---- OSV language-package index ----

// MergeOSVPackages upserts advisories by (ecosystem,name,vuln_id) without a
// TRUNCATE, so restarts/refreshes are incremental (no empty window).
func (m *MariaDB) MergeOSVPackages(advs []model.LangAdvisory) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO osv_pkg(ecosystem,name,vuln_id,advisory) VALUES(?,?,?,?) ` +
		`ON DUPLICATE KEY UPDATE advisory=VALUES(advisory)`)
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

func (m *MariaDB) ReplaceOSVPackages(advs []model.LangAdvisory) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("TRUNCATE osv_pkg"); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT IGNORE INTO osv_pkg(ecosystem,name,vuln_id,advisory) VALUES(?,?,?,?)`)
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

func (m *MariaDB) ForLangPackage(ecosystem, name string) []model.LangAdvisory {
	rows, err := m.db.Query(`SELECT advisory FROM osv_pkg WHERE ecosystem=? AND name=?`, ecosystem, name)
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

func (m *MariaDB) OSVPackageCount() (int, error) {
	var n int
	err := m.db.QueryRow(`SELECT count(*) FROM osv_pkg`).Scan(&n)
	return n, err
}

// ---- Triage ----

func (m *MariaDB) SetTriage(t model.Triage) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if t.State == "" || t.State == model.TriageActive {
		if _, err := tx.Exec(
			`DELETE FROM triage WHERE agent_id=? AND cve=? AND source_package=? AND ecosystem=?`,
			t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(
			`INSERT INTO triage(agent_id,cve,source_package,ecosystem,state,until_ts,note,actor,updated_at)
			 VALUES(?,?,?,?,?,?,?,?,UTC_TIMESTAMP())
			 ON DUPLICATE KEY UPDATE state=VALUES(state), until_ts=VALUES(until_ts), note=VALUES(note),
			   actor=VALUES(actor), updated_at=UTC_TIMESTAMP()`,
			t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem, t.State, nullTime(t.Until), t.Note, t.Actor); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO triage_events(actor,action,agent_id,cve,source_package,ecosystem,until_ts,note)
		 VALUES(?,?,?,?,?,?,?,?)`,
		t.Actor, t.State, t.AgentID, t.CVE, t.SourcePackage, t.Ecosystem, nullTime(t.Until), t.Note); err != nil {
		return err
	}
	return tx.Commit()
}

func (m *MariaDB) TriageFor(agentID, cve, source, eco string) (model.Triage, bool, error) {
	var t model.Triage
	var until sql.NullTime
	err := m.db.QueryRow(
		`SELECT agent_id,cve,source_package,ecosystem,state,until_ts,note,actor,updated_at
		 FROM triage WHERE agent_id=? AND cve=? AND source_package=? AND ecosystem=?`,
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

func (m *MariaDB) AuditLog(limit int) ([]model.TriageEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := m.db.Query(
		`SELECT e.ts, e.actor, e.action, e.agent_id, COALESCE(a.hostname,e.agent_id),
		        e.cve, e.source_package, e.ecosystem, e.until_ts, e.note
		 FROM triage_events e LEFT JOIN agents a ON a.id=e.agent_id
		 ORDER BY e.ts DESC LIMIT ?`, limit)
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

// ---- Host tags ----

func (m *MariaDB) SetAgentTags(agentID string, tags map[string]string) error {
	b, err := json.Marshal(tagsOrEmpty(tags))
	if err != nil {
		return err
	}
	_, err = m.db.Exec(`UPDATE agents SET tags=? WHERE id=?`, b, agentID)
	return err
}

func (m *MariaDB) SetReportedTags(agentID string, tags map[string]string) error {
	b, err := json.Marshal(tagsOrEmpty(tags))
	if err != nil {
		return err
	}
	_, err = m.db.Exec(`UPDATE agents SET reported_tags=? WHERE id=?`, b, agentID)
	return err
}

// ---- helpers ----

func marshalStrs(s []string) []byte {
	if s == nil {
		return []byte("[]")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func unmarshalStrs(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	var out []string
	_ = json.Unmarshal(b, &out)
	return out
}

func (m *MariaDB) SearchAdvisories(q AdvisoryQuery) ([]model.Advisory, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	if q.Text != "" {
		like := "%" + strings.ToLower(q.Text) + "%"
		where += " AND (LOWER(cve) LIKE ? OR LOWER(source_package) LIKE ? OR LOWER(description) LIKE ?)"
		args = append(args, like, like, like)
	}
	if q.SourcePackage != "" {
		where += " AND LOWER(source_package) LIKE ?"
		args = append(args, "%"+strings.ToLower(q.SourcePackage)+"%")
	}
	if q.Release != "" {
		where += " AND `release`=?"
		args = append(args, q.Release)
	}
	if q.Status != "" {
		where += " AND status=?"
		args = append(args, q.Status)
	}
	var total int
	if err := m.db.QueryRow("SELECT count(*) FROM debian_tracker "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, clampLimit(q.Limit), q.Offset)
	rows, err := m.db.Query(
		"SELECT cve,source_package,`release`,status,fixed_version,urgency,description FROM debian_tracker "+
			where+" ORDER BY cve DESC, source_package, `release` LIMIT ? OFFSET ?", args...)
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

func (m *MariaDB) AdvisoriesForCVE(cve string) ([]model.Advisory, error) {
	rows, err := m.db.Query(
		"SELECT cve,source_package,`release`,status,fixed_version,urgency,description FROM debian_tracker WHERE cve=? ORDER BY source_package, `release`", cve)
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

func (m *MariaDB) TrackerReleases() ([]string, error) {
	rows, err := m.db.Query("SELECT DISTINCT `release` FROM debian_tracker ORDER BY `release`")
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

func (m *MariaDB) SearchCVEs(q CVEQuery) ([]model.Enrichment, int, error) {
	where := "WHERE 1=1"
	args := []any{}
	if q.Text != "" {
		like := "%" + strings.ToLower(q.Text) + "%"
		where += " AND (LOWER(cve) LIKE ? OR LOWER(summary) LIKE ?)"
		args = append(args, like, like)
	}
	if q.Severity != "" {
		where += " AND cvss_severity=?"
		args = append(args, q.Severity)
	}
	if q.KEVOnly {
		where += " AND kev_listed"
	}
	var total int
	if err := m.db.QueryRow("SELECT count(*) FROM cve "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	args = append(args, clampLimit(q.Limit), q.Offset)
	rows, err := m.db.Query(
		"SELECT cve,cvss_score,cvss_severity,summary,kev_listed,epss_score FROM cve "+
			where+" ORDER BY kev_listed DESC, cvss_score DESC, cve DESC LIMIT ? OFFSET ?", args...)
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
