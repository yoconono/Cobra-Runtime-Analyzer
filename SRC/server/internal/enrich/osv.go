package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/cvss"
	"github.com/yourorg/cve-fleet/server/internal/model"
)

// OSVBaseURL is the OSV.dev API root.
const OSVBaseURL = "https://api.osv.dev"

// OSVClient talks to the OSV.dev API.
type OSVClient struct {
	Base string
	http *http.Client
}

func NewOSVClient() *OSVClient {
	return &OSVClient{Base: OSVBaseURL, http: &http.Client{Timeout: 30 * time.Second}}
}

// osvVuln mirrors the OSV schema fields we use.
type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"` // a CVSS vector string in OSV
	} `json:"severity"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// FetchByID returns enrichment for a CVE from OSV. The stored CVE is `cve` (the
// key we care about); OSV's own record id may differ (e.g. a GHSA).
func (c *OSVClient) FetchByID(ctx context.Context, cve string) (model.Enrichment, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/v1/vulns/"+cve, nil)
	if err != nil {
		return model.Enrichment{}, false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return model.Enrichment{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return model.Enrichment{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return model.Enrichment{}, false, fmt.Errorf("osv: http %d for %s", resp.StatusCode, cve)
	}
	var v osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return model.Enrichment{}, false, err
	}
	e := v.toEnrichment()
	e.CVE = cve
	return e, true, nil
}

// PackageVuln is a vulnerability affecting a language-ecosystem package.
type PackageVuln struct {
	ID      string
	Summary string
	Aliases []string
}

// QueryPackage asks OSV which vulnerabilities affect a given ecosystem package
// version (e.g. ecosystem "PyPI", name "requests", version "2.19.1"). This is
// the entry point for the planned SBOM/language-scan phase that will cover the
// agent's unmanaged_running_files.
func (c *OSVClient) QueryPackage(ctx context.Context, ecosystem, name, version string) ([]PackageVuln, error) {
	body, _ := json.Marshal(map[string]any{
		"version": version,
		"package": map[string]string{"ecosystem": ecosystem, "name": name},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: query http %d", resp.StatusCode)
	}
	return parseOSVQuery(resp.Body)
}

func parseOSVQuery(r io.Reader) ([]PackageVuln, error) {
	var out struct {
		Vulns []osvVuln `json:"vulns"`
	}
	if err := json.NewDecoder(r).Decode(&out); err != nil {
		return nil, err
	}
	res := make([]PackageVuln, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		res = append(res, PackageVuln{ID: v.ID, Summary: v.Summary, Aliases: v.Aliases})
	}
	return res, nil
}

// ParseOSVList parses a JSON array of OSV vulnerability records (offline
// ingestion). Each record is keyed by every CVE id found in its id/aliases.
func ParseOSVList(r io.Reader) (map[string]model.Enrichment, error) {
	var vulns []osvVuln
	if err := json.NewDecoder(r).Decode(&vulns); err != nil {
		return nil, fmt.Errorf("osv: decode list: %w", err)
	}
	out := map[string]model.Enrichment{}
	for _, v := range vulns {
		e := v.toEnrichment()
		for _, id := range append([]string{v.ID}, v.Aliases...) {
			if strings.HasPrefix(id, "CVE-") {
				ce := e
				ce.CVE = id
				out[id] = ce
			}
		}
	}
	return out, nil
}

// ParseOSVFile parses an OSV list from disk.
func ParseOSVFile(path string) (map[string]model.Enrichment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseOSVList(f)
}

func (v osvVuln) toEnrichment() model.Enrichment {
	e := model.Enrichment{CVE: v.ID, Source: "osv", CVSSSeverity: "UNKNOWN"}
	e.Summary = v.Summary
	if e.Summary == "" {
		e.Summary = v.Details
	}
	e.Aliases = v.Aliases
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Score, "CVSS:3") {
			if score, sev, err := cvss.BaseScore(s.Score); err == nil {
				e.CVSSVector, e.CVSSScore, e.CVSSSeverity = s.Score, score, sev
				break
			}
		}
		// CVSS_V4 or unparseable: keep the vector, leave severity UNKNOWN.
		if e.CVSSVector == "" {
			e.CVSSVector = s.Score
		}
	}
	for i, ref := range v.References {
		if i >= 20 {
			break
		}
		e.References = append(e.References, ref.URL)
	}
	e.Published = parseNVDTime(v.Published)
	e.Modified = parseNVDTime(v.Modified)
	return e
}
