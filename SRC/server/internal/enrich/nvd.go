// Package enrich pulls CVE severity/metadata from NVD and OSV and stores it as
// enrichment that findings are joined against at read time.
package enrich

import (
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

// NVDBaseURL is the NVD 2.0 CVE API endpoint.
const NVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVDClient fetches CVSS data from the NVD 2.0 API. An API key raises the rate
// limit substantially (see https://nvd.nist.gov/developers/request-an-api-key).
type NVDClient struct {
	APIKey string
	Base   string
	http   *http.Client
}

func NewNVDClient(apiKey string) *NVDClient {
	return &NVDClient{APIKey: apiKey, Base: NVDBaseURL, http: &http.Client{Timeout: 30 * time.Second}}
}

// FetchByID returns enrichment for a single CVE. ok=false means NVD has no
// record (or no CVSS data) for it.
func (c *NVDClient) FetchByID(ctx context.Context, cve string) (model.Enrichment, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"?cveId="+cve, nil)
	if err != nil {
		return model.Enrichment{}, false, err
	}
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
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
		return model.Enrichment{}, false, fmt.Errorf("nvd: http %d for %s", resp.StatusCode, cve)
	}
	es, err := ParseNVD(resp.Body)
	if err != nil {
		return model.Enrichment{}, false, err
	}
	for _, e := range es {
		if strings.EqualFold(e.CVE, cve) {
			return e, true, nil
		}
	}
	if len(es) > 0 {
		return es[0], true, nil
	}
	return model.Enrichment{}, false, nil
}

// ParseNVD parses an NVD 2.0 API response body into enrichments.
func ParseNVD(r io.Reader) ([]model.Enrichment, error) {
	var resp struct {
		Vulnerabilities []struct {
			CVE nvdCVE `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("nvd: decode: %w", err)
	}
	out := make([]model.Enrichment, 0, len(resp.Vulnerabilities))
	for _, v := range resp.Vulnerabilities {
		out = append(out, v.CVE.toEnrichment())
	}
	return out, nil
}

// ParseNVDFile parses an NVD 2.0 response saved to disk (offline ingestion).
func ParseNVDFile(path string) ([]model.Enrichment, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseNVD(f)
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []nvdMetricV3 `json:"cvssMetricV31"`
		V30 []nvdMetricV3 `json:"cvssMetricV30"`
		V2  []nvdMetricV2 `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdMetricV3 struct {
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdMetricV2 struct {
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

func (c nvdCVE) toEnrichment() model.Enrichment {
	e := model.Enrichment{CVE: c.ID, Source: "nvd", CVSSSeverity: "UNKNOWN"}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			e.Summary = d.Value
			break
		}
	}
	switch {
	case len(c.Metrics.V31) > 0:
		m := pickV3(c.Metrics.V31)
		e.CVSSVector, e.CVSSScore, e.CVSSSeverity = m.CVSSData.VectorString, m.CVSSData.BaseScore, up(m.CVSSData.BaseSeverity)
	case len(c.Metrics.V30) > 0:
		m := pickV3(c.Metrics.V30)
		e.CVSSVector, e.CVSSScore, e.CVSSSeverity = m.CVSSData.VectorString, m.CVSSData.BaseScore, up(m.CVSSData.BaseSeverity)
	case len(c.Metrics.V2) > 0:
		m := c.Metrics.V2[0]
		e.CVSSVector, e.CVSSScore, e.CVSSSeverity = m.CVSSData.VectorString, m.CVSSData.BaseScore, up(m.BaseSeverity)
	}
	// If a score/severity is missing but we have a v3 vector, compute it.
	if (e.CVSSSeverity == "UNKNOWN" || e.CVSSScore == 0) && strings.HasPrefix(e.CVSSVector, "CVSS:3") {
		if s, sev, err := cvss.BaseScore(e.CVSSVector); err == nil {
			e.CVSSScore, e.CVSSSeverity = s, sev
		}
	}
	if e.CVSSSeverity == "" {
		e.CVSSSeverity = "UNKNOWN"
	}
	for i, ref := range c.References {
		if i >= 20 {
			break
		}
		e.References = append(e.References, ref.URL)
	}
	e.Published = parseNVDTime(c.Published)
	e.Modified = parseNVDTime(c.LastModified)
	return e
}

// pickV3 prefers the Primary metric when present.
func pickV3(ms []nvdMetricV3) nvdMetricV3 {
	for _, m := range ms {
		if m.Type == "Primary" {
			return m
		}
	}
	return ms[0]
}

func up(s string) string {
	if s == "" {
		return "UNKNOWN"
	}
	return strings.ToUpper(s)
}

func parseNVDTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02T15:04:05.000", "2006-01-02T15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
