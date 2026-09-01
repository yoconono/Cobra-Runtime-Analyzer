// Package osvmatch parses OSV vulnerability records for language ecosystems and
// matches reported language packages against them. It complements the Debian
// tracker path: Debian data covers OS packages; OSV covers pip/npm/Go deps.
package osvmatch

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/yourorg/cve-fleet/server/internal/cvss"
	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/semver"
)

// Source provides OSV advisories for a given ecosystem package.
type Source interface {
	ForLangPackage(ecosystem, name string) []model.LangAdvisory
}

// Match returns findings for the reported language packages. Results are
// deduplicated per (vuln, ecosystem, package); Running is OR'd across duplicates.
func Match(pkgs []model.LangPackage, src Source) []model.Finding {
	type key struct{ vuln, eco, pkg string }
	seen := map[key]*model.Finding{}
	order := []key{}

	for _, p := range pkgs {
		for _, adv := range src.ForLangPackage(p.Ecosystem, p.Name) {
			vulnerable, fixed := evaluate(adv, p.Version)
			if !vulnerable {
				continue
			}
			k := key{adv.VulnID, p.Ecosystem, p.Name}
			if f, ok := seen[k]; ok {
				f.Running = f.Running || p.Running
				continue
			}
			f := &model.Finding{
				CVE:              preferCVE(adv),
				SourcePackage:    p.Name,
				Ecosystem:        p.Ecosystem,
				InstalledVersion: p.Version,
				FixedVersion:     fixed,
				Status:           statusFor(fixed),
				Running:          p.Running,
				Description:      adv.Summary,
			}
			seen[k] = f
			order = append(order, k)
		}
	}
	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *seen[k])
	}
	return out
}

// evaluate decides whether an installed version is affected by an advisory, and
// returns the fixing version if one is known.
func evaluate(adv model.LangAdvisory, version string) (vulnerable bool, fixed string) {
	for _, v := range adv.Versions { // explicit affected list
		if v == version {
			return true, firstFixed(adv)
		}
	}
	for _, r := range adv.Ranges {
		if semver.InRange(version, r.Introduced, r.Fixed) {
			return true, r.Fixed
		}
	}
	return false, ""
}

func firstFixed(adv model.LangAdvisory) string {
	for _, r := range adv.Ranges {
		if r.Fixed != "" {
			return r.Fixed
		}
	}
	return ""
}

func statusFor(fixed string) string {
	if fixed == "" {
		return "open"
	}
	return "resolved"
}

func preferCVE(adv model.LangAdvisory) string {
	if strings.HasPrefix(adv.VulnID, "CVE-") {
		return adv.VulnID
	}
	for _, a := range adv.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return adv.VulnID // fall back to the OSV id (e.g. GHSA-...)
}

// ---- Parsing OSV records into flat advisories ----

type osvRecord struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	Aliases    []string `json:"aliases"`
	Severity   []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
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

// ParseIndex reads a JSON array of OSV records into flat advisories (one per
// affected package).
func ParseIndex(r io.Reader) ([]model.LangAdvisory, error) {
	var recs []osvRecord
	if err := json.NewDecoder(r).Decode(&recs); err != nil {
		return nil, err
	}
	var out []model.LangAdvisory
	for _, rec := range recs {
		out = append(out, recordToAdvisories(rec)...)
	}
	return out, nil
}

// recordToAdvisories flattens a single OSV record into per-affected-package
// advisories. Shared by the JSON-array index parser and the bulk downloader.
func recordToAdvisories(rec osvRecord) []model.LangAdvisory {
	vector := ""
	for _, s := range rec.Severity {
		if strings.HasPrefix(s.Score, "CVSS:3") {
			vector = s.Score
			break
		}
	}
	summary := rec.Summary
	if summary == "" {
		summary = rec.Details
	}
	var out []model.LangAdvisory
	for _, aff := range rec.Affected {
		adv := model.LangAdvisory{
			VulnID:         rec.ID,
			Aliases:        rec.Aliases,
			Ecosystem:      aff.Package.Ecosystem,
			Package:        aff.Package.Name,
			Versions:       aff.Versions,
			SeverityVector: vector,
			Summary:        summary,
		}
		for _, rg := range aff.Ranges {
			var cur model.VersionRange
			open := false
			for _, ev := range rg.Events {
				if v, ok := ev["introduced"]; ok {
					cur = model.VersionRange{Introduced: v}
					open = true
				}
				if v, ok := ev["fixed"]; ok {
					cur.Fixed = v
					adv.Ranges = append(adv.Ranges, cur)
					open = false
				}
			}
			if open { // introduced with no fix => open-ended range
				adv.Ranges = append(adv.Ranges, cur)
			}
		}
		out = append(out, adv)
	}
	return out
}

// ParseIndexFile reads an OSV index from disk.
func ParseIndexFile(path string) ([]model.LangAdvisory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseIndex(f)
}

// Enrichment builds CVE enrichment from an advisory (so language findings get a
// severity even before NVD is consulted). Keyed by the advisory's display id.
func Enrichment(adv model.LangAdvisory) model.Enrichment {
	e := model.Enrichment{CVE: preferCVE(adv), Source: "osv", CVSSSeverity: "UNKNOWN", Summary: adv.Summary, Aliases: adv.Aliases}
	if strings.HasPrefix(adv.SeverityVector, "CVSS:3") {
		if score, sev, err := cvss.BaseScore(adv.SeverityVector); err == nil {
			e.CVSSScore, e.CVSSSeverity, e.CVSSVector = score, sev, adv.SeverityVector
		}
	}
	return e
}
