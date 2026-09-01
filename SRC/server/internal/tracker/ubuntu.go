package tracker

import (
	"compress/bzip2"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// flexStrings accepts a JSON value that Canonical's USN feed encodes
// inconsistently for some notices: either an array of CVE ids (["CVE-…", …]),
// a single string, or a whitespace/comma-separated string. All decode to a
// []string so one oddly-shaped notice can't fail the whole load.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = trimJSONSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*f = nil
		return nil
	}
	switch b[0] {
	case '[': // normal case: array of strings
		var xs []string
		if err := json.Unmarshal(b, &xs); err != nil {
			var raw []interface{} // tolerate a mixed array by coercing elements
			if err2 := json.Unmarshal(b, &raw); err2 != nil {
				return err
			}
			for _, v := range raw {
				if s, ok := v.(string); ok && s != "" {
					xs = append(xs, s)
				}
			}
		}
		*f = xs
	case '"': // a single string, possibly space/comma separated
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = splitList(s)
	default:
		return fmt.Errorf("cves: unexpected JSON")
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n' || r == ';'
	}) {
		if tok = strings.TrimSpace(tok); tok != "" {
			out = append(out, tok)
		}
	}
	return out
}

func trimJSONSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		if c := b[len(b)-1]; c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			b = b[:len(b)-1]
		} else {
			break
		}
	}
	return b
}

// DefaultUSNURL is Canonical's Ubuntu Security Notices database (bzip2 JSON).
// It lists, per USN, the fixed source-package versions per release codename and
// the CVEs each notice addresses.
const DefaultUSNURL = "https://usn.ubuntu.com/usn-db/database.json.bz2"

// usnDB mirrors the USN database shape we consume:
//
//	{ "<usn-id>": {
//	    "title": "...", "description": "...",
//	    "cves": ["CVE-...", ...],
//	    "releases": { "<codename>": {
//	        "sources": { "<srcpkg>": { "version": "<fixed>", "description": "..." } } } } } }
type usnDB map[string]struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	CVEs        flexStrings `json:"cves"`
	Releases    map[string]struct {
		Sources map[string]struct {
			Version     string `json:"version"`
			Description string `json:"description"`
		} `json:"sources"`
	} `json:"releases"`
}

// ParseUSN converts the Ubuntu USN database into flat advisories. Each notice
// yields, per release and affected source package, one "resolved" advisory per
// CVE with the fixed version — matching the Debian tracker's "resolved" shape,
// so the same dpkg-accurate matcher flags a host whose installed version is
// older than the fix.
func ParseUSN(r io.Reader) ([]model.Advisory, error) {
	var db usnDB
	dec := json.NewDecoder(r)
	if err := dec.Decode(&db); err != nil {
		return nil, fmt.Errorf("decode USN json: %w", err)
	}
	var out []model.Advisory
	for _, usn := range db {
		if len(usn.CVEs) == 0 {
			continue
		}
		desc := usn.Title
		if desc == "" {
			desc = usn.Description
		}
		for codename, rel := range usn.Releases {
			for src, s := range rel.Sources {
				if s.Version == "" {
					continue
				}
				for _, cve := range usn.CVEs {
					if !strings.HasPrefix(cve, "CVE-") {
						continue
					}
					out = append(out, model.Advisory{
						CVE:           cve,
						SourcePackage: src,
						Release:       codename,
						Status:        "resolved",
						FixedVersion:  s.Version,
						Urgency:       "",
						Description:   desc,
					})
				}
			}
		}
	}
	return out, nil
}

// maybeBunzip wraps a reader in a bzip2 decoder when the name ends in .bz2.
func maybeBunzip(r io.Reader, name string) io.Reader {
	if strings.HasSuffix(name, ".bz2") {
		return bzip2.NewReader(r)
	}
	return r
}

// FetchUSNFile parses a USN database already on disk (.json or .json.bz2).
func FetchUSNFile(path string) ([]model.Advisory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseUSN(maybeBunzip(f, path))
}

// FetchUSNURL downloads and parses the USN database (bzip2-aware).
func FetchUSNURL(url string) ([]model.Advisory, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: http %d", url, resp.StatusCode)
	}
	return ParseUSN(maybeBunzip(resp.Body, url))
}
