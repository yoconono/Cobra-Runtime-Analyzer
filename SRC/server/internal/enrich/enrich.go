package enrich

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/store"
)

// Enricher fills the store's CVE enrichment table from NVD and OSV.
type Enricher struct {
	Store store.Store
	NVD   *NVDClient // nil to skip NVD
	OSV   *OSVClient // nil to skip OSV
	Log   *log.Logger
}

// Options tune a live enrichment run.
type Options struct {
	RefreshAll bool          // re-fetch even CVEs already enriched
	PerRequest time.Duration // delay between upstream calls (rate limiting)
	Limit      int           // cap number of CVEs processed (0 = all)
}

// RunFromStore enriches the CVEs referenced by the ingested Debian tracker.
// It fetches from NVD (authoritative CVSS) and OSV (aliases + fallback CVSS)
// and merges the two before storing.
func (e *Enricher) RunFromStore(ctx context.Context, opt Options) error {
	cves, err := e.Store.DistinctTrackerCVEs()
	if err != nil {
		return err
	}
	done := map[string]bool{}
	if !opt.RefreshAll {
		if done, err = e.Store.EnrichedCVEs(); err != nil {
			return err
		}
	}

	processed := 0
	for _, cve := range cves {
		if !strings.HasPrefix(cve, "CVE-") || done[cve] {
			continue
		}
		if opt.Limit > 0 && processed >= opt.Limit {
			break
		}
		processed++

		var nvdE, osvE *model.Enrichment
		if e.NVD != nil {
			if v, ok, err := e.NVD.FetchByID(ctx, cve); err != nil {
				e.logf("nvd %s: %v", cve, err)
			} else if ok {
				nvdE = &v
			}
			e.sleep(ctx, opt.PerRequest)
		}
		if e.OSV != nil {
			if v, ok, err := e.OSV.FetchByID(ctx, cve); err != nil {
				e.logf("osv %s: %v", cve, err)
			} else if ok {
				osvE = &v
			}
			e.sleep(ctx, opt.PerRequest)
		}

		merged, ok := Merge(cve, nvdE, osvE)
		if !ok {
			continue
		}
		if err := e.Store.UpsertEnrichment(merged); err != nil {
			e.logf("store %s: %v", cve, err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	e.logf("enriched %d CVEs", processed)
	return nil
}

// RunFromFiles ingests enrichment from saved NVD and/or OSV files (offline).
func (e *Enricher) RunFromFiles(nvdFile, osvFile string) error {
	nvdByCVE := map[string]model.Enrichment{}
	if nvdFile != "" {
		es, err := ParseNVDFile(nvdFile)
		if err != nil {
			return err
		}
		for _, en := range es {
			nvdByCVE[en.CVE] = en
		}
	}
	osvByCVE := map[string]model.Enrichment{}
	if osvFile != "" {
		var err error
		if osvByCVE, err = ParseOSVFile(osvFile); err != nil {
			return err
		}
	}

	seen := map[string]bool{}
	upsert := func(cve string) {
		if seen[cve] {
			return
		}
		seen[cve] = true
		var n, o *model.Enrichment
		if v, ok := nvdByCVE[cve]; ok {
			n = &v
		}
		if v, ok := osvByCVE[cve]; ok {
			o = &v
		}
		if merged, ok := Merge(cve, n, o); ok {
			if err := e.Store.UpsertEnrichment(merged); err != nil {
				e.logf("store %s: %v", cve, err)
			}
		}
	}
	for cve := range nvdByCVE {
		upsert(cve)
	}
	for cve := range osvByCVE {
		upsert(cve)
	}
	n, _ := e.Store.EnrichmentCount()
	e.logf("enrichment store now holds %d CVEs", n)
	return nil
}

// Merge combines NVD (authoritative CVSS) with OSV (aliases + fallback CVSS).
// Returns ok=false when neither source had anything.
func Merge(cve string, nvd, osv *model.Enrichment) (model.Enrichment, bool) {
	if nvd == nil && osv == nil {
		return model.Enrichment{}, false
	}
	out := model.Enrichment{CVE: cve, CVSSSeverity: "UNKNOWN"}
	var sources []string

	if nvd != nil {
		out.CVSSScore = nvd.CVSSScore
		out.CVSSSeverity = nvd.CVSSSeverity
		out.CVSSVector = nvd.CVSSVector
		out.Summary = nvd.Summary
		out.References = nvd.References
		out.Aliases = nvd.Aliases
		out.Published = nvd.Published
		out.Modified = nvd.Modified
		sources = append(sources, "nvd")
	}
	if osv != nil {
		// Fall back to OSV's CVSS only where NVD lacked it.
		if out.CVSSSeverity == "UNKNOWN" && osv.CVSSSeverity != "UNKNOWN" {
			out.CVSSScore = osv.CVSSScore
			out.CVSSSeverity = osv.CVSSSeverity
			out.CVSSVector = osv.CVSSVector
		}
		if out.Summary == "" {
			out.Summary = osv.Summary
		}
		out.Aliases = union(out.Aliases, osv.Aliases)
		if len(out.References) == 0 {
			out.References = osv.References
		}
		if out.Published.IsZero() {
			out.Published = osv.Published
		}
		if out.Modified.IsZero() {
			out.Modified = osv.Modified
		}
		sources = append(sources, "osv")
	}
	out.Source = strings.Join(sources, "+")
	return out, true
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func (e *Enricher) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (e *Enricher) logf(format string, args ...any) {
	if e.Log != nil {
		e.Log.Printf(format, args...)
	}
}
