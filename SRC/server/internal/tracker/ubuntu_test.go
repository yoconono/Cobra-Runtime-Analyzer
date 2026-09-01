package tracker

import (
	"os"
	"testing"
)

func TestParseUSN(t *testing.T) {
	f, err := os.Open("../../testdata/sample-usn.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	advs, err := ParseUSN(f)
	if err != nil {
		t.Fatal(err)
	}
	// 6800-1: noble(openssl x2 CVEs) + jammy(openssl x2 CVEs) = 4; 6801-1: noble(curl x1) = 1 => 5
	if len(advs) != 5 {
		t.Fatalf("got %d advisories, want 5", len(advs))
	}
	found := 0
	for i := range advs {
		a := advs[i]
		if a.SourcePackage == "openssl" && a.Release == "noble" && a.CVE == "CVE-2025-DEMO-0001" {
			if a.Status != "resolved" || a.FixedVersion != "3.0.13-0ubuntu3.10" {
				t.Errorf("noble openssl fix wrong: %+v", a)
			}
			found++
		}
		if a.SourcePackage == "curl" && a.Release == "noble" && a.FixedVersion != "8.5.0-2ubuntu10.1" {
			t.Errorf("curl fix wrong: %+v", a)
		}
	}
	if found != 1 {
		t.Errorf("expected exactly one noble/openssl/0001 advisory, got %d", found)
	}
}

func TestUbuntuCodename(t *testing.T) {
	if Codename("ubuntu", "24.04") != "noble" {
		t.Error("ubuntu 24.04 should be noble")
	}
	if Codename("debian", "12") != "bookworm" {
		t.Error("debian 12 should be bookworm")
	}
	if Codename("ubuntu", "22.04") != "jammy" {
		t.Error("ubuntu 22.04 should be jammy")
	}
	if Codename("ubuntu", "noble") != "noble" {
		t.Error("codename passthrough failed")
	}
}
