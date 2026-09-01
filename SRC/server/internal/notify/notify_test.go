package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

func TestPolicyMatch(t *testing.T) {
	p := Policy{MinSeverity: "HIGH"}
	if !p.Match("CRITICAL", false) {
		t.Error("CRITICAL should match >=HIGH")
	}
	if !p.Match("HIGH", false) {
		t.Error("HIGH should match >=HIGH")
	}
	if p.Match("MEDIUM", false) {
		t.Error("MEDIUM should not match >=HIGH")
	}

	pr := Policy{MinSeverity: "LOW", RunningOnly: true}
	if pr.Match("CRITICAL", false) {
		t.Error("running-only policy should skip non-running")
	}
	if !pr.Match("LOW", true) {
		t.Error("running-only policy should match running at >=LOW")
	}
}

func TestWebhookPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d := &Dispatcher{
		Policy:       Policy{MinSeverity: "HIGH"},
		Notifier:     Webhook{URL: srv.URL},
		DashboardURL: "https://cve.example.com/",
		OnResolved:   true,
	}
	appeared := []model.Finding{
		{CVE: "CVE-1", SourcePackage: "openssl", InstalledVersion: "1.0", CVSSSeverity: "CRITICAL", CVSSScore: 9.8, Running: true},
		{CVE: "CVE-2", SourcePackage: "foo", CVSSSeverity: "MEDIUM"}, // filtered out (below HIGH)
	}
	resolved := []model.Finding{
		{CVE: "CVE-3", SourcePackage: "bar", CVSSSeverity: "HIGH"}, // "all clear"
	}
	d.Handle("agent-1", "host-a", appeared, resolved)

	// Handle dispatches asynchronously; poll briefly.
	if !waitFor(func() bool { return got != nil }) {
		t.Fatal("webhook was not called")
	}
	if int(got["count"].(float64)) != 2 {
		t.Errorf("expected 2 alerts (1 new + 1 resolved), got %v", got["count"])
	}
	if int(got["new_count"].(float64)) != 1 || int(got["resolved_count"].(float64)) != 1 {
		t.Errorf("expected new_count=1 resolved_count=1, got %v/%v", got["new_count"], got["resolved_count"])
	}
	byCVE := map[string]map[string]any{}
	for _, x := range got["alerts"].([]any) {
		a := x.(map[string]any)
		byCVE[a["cve"].(string)] = a
	}
	if byCVE["CVE-1"]["kind"] != "new" || byCVE["CVE-1"]["url"] != "https://cve.example.com/cves/CVE-1" {
		t.Errorf("CVE-1 alert wrong: %v", byCVE["CVE-1"])
	}
	if byCVE["CVE-3"]["kind"] != "resolved" {
		t.Errorf("CVE-3 should be a resolved notice: %v", byCVE["CVE-3"])
	}
	if _, ok := byCVE["CVE-2"]; ok {
		t.Error("CVE-2 (MEDIUM) should have been filtered out")
	}
}

func waitFor(cond func() bool) bool {
	for i := 0; i < 200; i++ {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

var _ = context.Background
