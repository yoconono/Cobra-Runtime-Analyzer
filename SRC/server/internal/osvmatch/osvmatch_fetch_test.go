package osvmatch

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

const rec1 = `{"id":"GO-2024-0001","summary":"demo","affected":[{"package":{"ecosystem":"Go","name":"example.com/x"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`
const rec2 = `{"id":"GHSA-aaaa","aliases":["CVE-2024-9999"],"summary":"demo2","affected":[{"package":{"ecosystem":"Go","name":"example.com/y"},"versions":["1.0.0"]}]}`

func makeZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"GO-2024-0001.json": rec1, "GHSA-aaaa.json": rec2, "notes.txt": "ignore me"} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	return buf.Bytes()
}

func TestParseAllZip(t *testing.T) {
	z := makeZip(t)
	advs, err := ParseAllZip(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 {
		t.Fatalf("got %d advisories want 2 (txt ignored)", len(advs))
	}
	var sawFix, sawVer bool
	for _, a := range advs {
		if a.VulnID == "GO-2024-0001" && len(a.Ranges) == 1 && a.Ranges[0].Fixed == "1.2.3" {
			sawFix = true
		}
		if a.VulnID == "GHSA-aaaa" && len(a.Versions) == 1 && a.Versions[0] == "1.0.0" {
			sawVer = true
		}
	}
	if !sawFix || !sawVer {
		t.Errorf("parsed advisories missing expected data: fix=%v ver=%v", sawFix, sawVer)
	}
}

func TestFetchIndexLocalMirror(t *testing.T) {
	z := makeZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/Go/all.zip" {
			w.Write(z)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	advs, err := FetchIndex(srv.URL, []string{"Go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(advs) != 2 {
		t.Fatalf("fetched %d advisories want 2", len(advs))
	}
	// a missing ecosystem yields a partial error but keeps the good data
	advs, err = FetchIndex(srv.URL, []string{"Go", "PyPI"})
	if err == nil {
		t.Error("expected partial error for missing PyPI")
	}
	if len(advs) != 2 {
		t.Errorf("partial fetch should still return Go's 2 advisories, got %d", len(advs))
	}
}
