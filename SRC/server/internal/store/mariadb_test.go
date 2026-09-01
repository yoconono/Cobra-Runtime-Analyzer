package store

import (
	"strings"
	"testing"
)

// These checks don't need a live database — they guard the schema string and the
// dialect-specific bits that are easy to break accidentally.

func TestMariaSchemaStatements(t *testing.T) {
	var stmts []string
	for _, s := range strings.Split(mariaSchema, "||") {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	// users, enrollment_tokens, agents, findings, osv_pkg, triage, triage_events,
	// debian_tracker, cve = 9 CREATE TABLEs, plus 1 guarded ALTER (running_binaries).
	if len(stmts) != 11 {
		t.Fatalf("expected 11 schema statements, got %d", len(stmts))
	}
	for _, s := range stmts {
		guardedCreate := strings.Contains(s, "CREATE TABLE IF NOT EXISTS")
		guardedAlter := strings.Contains(s, "ALTER TABLE") && strings.Contains(s, "IF NOT EXISTS")
		if !guardedCreate && !guardedAlter {
			t.Errorf("statement is not a guarded CREATE TABLE or ALTER TABLE:\n%s", s)
		}
	}
}

func TestMariaFindingsOpenKey(t *testing.T) {
	// The partial-unique-index replacement: a generated open_key that is NULL
	// once resolved, with a UNIQUE index, is what enforces one open episode.
	if !strings.Contains(mariaSchema, "open_key CHAR(32) AS (IF(resolved_at IS NULL") {
		t.Error("findings.open_key generated column missing or changed")
	}
	if !strings.Contains(mariaSchema, "UNIQUE KEY findings_open_uk (open_key)") {
		t.Error("unique index on open_key missing")
	}
}

func TestMariaSuppressedPredicate(t *testing.T) {
	// Expiry comparisons must be in UTC, not server-local.
	if !strings.Contains(mariaSuppressed, "UTC_TIMESTAMP()") {
		t.Error("suppression predicate should compare against UTC_TIMESTAMP()")
	}
	for _, want := range []string{"'muted'", "'snoozed'", "'risk_accepted'"} {
		if !strings.Contains(mariaSuppressed, want) {
			t.Errorf("suppression predicate missing state %s", want)
		}
	}
}
