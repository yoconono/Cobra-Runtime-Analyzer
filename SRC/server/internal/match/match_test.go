package match

import (
	"testing"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// fakeSource returns advisories from an in-memory map keyed by source+release.
type fakeSource map[string][]model.Advisory

func (f fakeSource) ForPackage(src, rel string) []model.Advisory { return f[src+"|"+rel] }

func adv(cve, src, rel, status, fixed, urgency string) model.Advisory {
	return model.Advisory{CVE: cve, SourcePackage: src, Release: rel, Status: status, FixedVersion: fixed, Urgency: urgency}
}

func TestMatchSemantics(t *testing.T) {
	src := fakeSource{
		"openssl|bookworm": {
			adv("CVE-1", "openssl", "bookworm", "resolved", "3.0.11-1~deb12u1", "high"), // installed older -> vuln
			adv("CVE-2", "openssl", "bookworm", "resolved", "3.0.9-1", "medium"),        // installed newer -> safe
			adv("CVE-3", "openssl", "bookworm", "open", "", "high"),                     // open -> vuln
			adv("CVE-4", "openssl", "bookworm", "resolved", "0", "low"),                 // not affected
			adv("CVE-5", "openssl", "bookworm", "undetermined", "", "low"),              // excluded by default
		},
	}
	pkgs := []model.Package{
		{Name: "libssl3", Source: "openssl", SourceVersion: "3.0.10-1", Running: true},
		{Name: "openssl", Source: "openssl", SourceVersion: "3.0.10-1", Running: false},
	}

	got := Match(pkgs, "bookworm", "", src, Options{})
	found := map[string]model.Finding{}
	for _, f := range got {
		found[f.CVE] = f
	}

	if _, ok := found["CVE-1"]; !ok {
		t.Error("CVE-1 should be vulnerable (installed older than fix)")
	}
	if !found["CVE-1"].Running {
		t.Error("CVE-1 should be marked running (libssl3 is running)")
	}
	if _, ok := found["CVE-2"]; ok {
		t.Error("CVE-2 should be safe (installed newer than fix)")
	}
	if _, ok := found["CVE-3"]; !ok {
		t.Error("CVE-3 should be vulnerable (open, no fix)")
	}
	if found["CVE-3"].FixedVersion != "" {
		t.Error("CVE-3 (open) should have no fixed version")
	}
	if _, ok := found["CVE-4"]; ok {
		t.Error("CVE-4 should be safe (fixed_version 0 = not affected)")
	}
	if _, ok := found["CVE-5"]; ok {
		t.Error("CVE-5 (undetermined) should be excluded by default")
	}
	if len(got) != 2 { // CVE-1 and CVE-3, deduped across the two binary packages
		t.Errorf("expected 2 findings, got %d", len(got))
	}
}

func TestMatchUndeterminedOptIn(t *testing.T) {
	src := fakeSource{"foo|trixie": {adv("CVE-9", "foo", "trixie", "undetermined", "", "low")}}
	pkgs := []model.Package{{Name: "foo", Source: "foo", SourceVersion: "1-1"}}
	if got := Match(pkgs, "trixie", "", src, Options{IncludeUndetermined: true}); len(got) != 1 {
		t.Errorf("expected undetermined to be included, got %d findings", len(got))
	}
}
