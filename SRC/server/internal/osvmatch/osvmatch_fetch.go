package osvmatch

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// DefaultOSVBaseURL is the OSV.dev bulk mirror. Each ecosystem is published as
// "<base>/<Ecosystem>/all.zip", a zip of one OSV JSON record per vulnerability.
const DefaultOSVBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// DefaultOSVEcosystems are the language ecosystems the agent's SBOM covers.
var DefaultOSVEcosystems = []string{"Go", "PyPI", "npm", "crates.io"}

// FetchIndex downloads the given ecosystems' all.zip archives from an OSV mirror
// and flattens them into advisories — the same shape ParseIndex produces from a
// local index file, so the ingestion path is identical.
func FetchIndex(baseURL string, ecosystems []string) ([]model.LangAdvisory, error) {
	if baseURL == "" {
		baseURL = DefaultOSVBaseURL
	}
	if len(ecosystems) == 0 {
		ecosystems = DefaultOSVEcosystems
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	var out []model.LangAdvisory
	var errs []string
	for _, eco := range ecosystems {
		advs, err := fetchEcosystem(client, baseURL, eco)
		if err != nil {
			errs = append(errs, eco+": "+err.Error())
			continue
		}
		out = append(out, advs...)
	}
	if len(out) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if len(errs) > 0 {
		return out, fmt.Errorf("partial OSV download: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

func fetchEcosystem(client *http.Client, baseURL, eco string) ([]model.LangAdvisory, error) {
	url := strings.TrimRight(baseURL, "/") + "/" + eco + "/all.zip"
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: http %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseAllZip(bytes.NewReader(body), int64(len(body)))
}

// ParseAllZip reads an OSV "all.zip" (one JSON record per entry) into advisories.
// Exposed so the archive can also be ingested from a local file.
func ParseAllZip(r io.ReaderAt, size int64) ([]model.LangAdvisory, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	var out []model.LangAdvisory
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		var rec osvRecord
		dec := json.NewDecoder(rc)
		derr := dec.Decode(&rec)
		rc.Close()
		if derr != nil {
			continue // skip a malformed record rather than fail the whole archive
		}
		out = append(out, recordToAdvisories(rec)...)
	}
	return out, nil
}
