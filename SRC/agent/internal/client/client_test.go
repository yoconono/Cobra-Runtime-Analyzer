package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yourorg/cve-fleet/agent/internal/config"
	"github.com/yourorg/cve-fleet/agent/internal/model"
)

func testServer() *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agents/enroll" {
			_ = json.NewEncoder(w).Encode(model.EnrollResponse{AgentID: "agent-xyz", APIToken: "tok-123"})
			return
		}
		http.NotFound(w, r)
	}))
}

func newClient(t *testing.T, srv *httptest.Server, stateDir string) *Client {
	t.Helper()
	cfg := config.Config{ServerURL: srv.URL, InsecureSkipVerify: true, StateDir: stateDir, HTTPTimeout: 5 * time.Second}
	c, err := New(cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnrollThenPersistAndLoad(t *testing.T) {
	srv := testServer()
	defer srv.Close()
	dir := t.TempDir()

	c := newClient(t, srv, dir)
	if c.LoadCredential() {
		t.Fatal("should not load a credential before enrolling")
	}
	if err := c.Enroll(model.EnrollRequest{EnrollmentToken: "x", MachineID: "m"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !c.Enrolled() {
		t.Fatal("in-memory credential should be set after Enroll")
	}
	if err := c.PersistCredential(); err != nil {
		t.Fatalf("persist: %v", err)
	}
	// A fresh client must load it and NOT need to re-enroll.
	c2 := newClient(t, srv, dir)
	if !c2.LoadCredential() {
		t.Fatal("second client should load the persisted credential (no re-enroll)")
	}
	if c2.cred.AgentID != "agent-xyz" || c2.cred.APIToken != "tok-123" {
		t.Fatalf("loaded wrong credential: %+v", c2.cred)
	}
}

func TestPersistFailureDoesNotDiscardCredential(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	// A regular file as a path component => MkdirAll fails with ENOTDIR for any
	// uid (root included), deterministically simulating an unwritable state dir.
	base := t.TempDir()
	notDir := filepath.Join(base, "afile")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv, filepath.Join(notDir, "state"))

	if err := c.Enroll(model.EnrollRequest{EnrollmentToken: "x", MachineID: "m"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if !c.Enrolled() {
		t.Fatal("credential should be held in memory even if it can't be saved")
	}
	if err := c.PersistCredential(); err == nil {
		t.Fatal("expected persist to fail on a read-only state dir")
	}
}
