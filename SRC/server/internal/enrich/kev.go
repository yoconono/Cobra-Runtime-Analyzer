package enrich

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultKEVURL is the CISA Known Exploited Vulnerabilities catalog feed.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVInfo is the exploitation record for one CVE in the KEV catalog.
type KEVInfo struct {
	DateAdded  time.Time
	DueDate    time.Time
	Ransomware bool
}

// ParseKEV parses the KEV JSON feed into a map keyed by CVE id.
func ParseKEV(r io.Reader) (map[string]KEVInfo, error) {
	var feed struct {
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return nil, fmt.Errorf("kev: decode: %w", err)
	}
	out := make(map[string]KEVInfo, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		if v.CveID == "" {
			continue
		}
		out[v.CveID] = KEVInfo{
			DateAdded:  parseDay(v.DateAdded),
			DueDate:    parseDay(v.DueDate),
			Ransomware: strings.EqualFold(v.KnownRansomwareCampaignUse, "known"),
		}
	}
	return out, nil
}

// FetchKEVFile parses a KEV catalog from disk.
func FetchKEVFile(path string) (map[string]KEVInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseKEV(f)
}

// FetchKEVURL downloads and parses the KEV catalog.
func FetchKEVURL(url string) (map[string]KEVInfo, error) {
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev: http %d", resp.StatusCode)
	}
	return ParseKEV(resp.Body)
}

func parseDay(s string) time.Time {
	if t, err := time.Parse("2006-01-02", strings.TrimSpace(s)); err == nil {
		return t
	}
	return time.Time{}
}
