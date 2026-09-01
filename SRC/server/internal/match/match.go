// Package match decides which installed packages are vulnerable, using security
// tracker advisories and distribution-appropriate version comparison (dpkg for
// Debian/Ubuntu, rpm EVR for Red Hat family).
package match

import (
	"github.com/yourorg/cve-fleet/server/internal/debver"
	"github.com/yourorg/cve-fleet/server/internal/model"
	"github.com/yourorg/cve-fleet/server/internal/rpmver"
)

// AdvisorySource provides the advisories for a given source package + release.
type AdvisorySource interface {
	ForPackage(sourcePackage, release string) []model.Advisory
}

// Options tunes matching behavior.
type Options struct {
	// IncludeUndetermined includes advisories Debian hasn't triaged for the
	// release yet. Off by default to avoid unconfirmed noise.
	IncludeUndetermined bool
}

// lessFunc reports whether installed version a is older than fixed version b.
type lessFunc func(a, b string) bool

// comparatorFor returns the version comparator for an OS family.
func comparatorFor(family string) lessFunc {
	if family == "rhel" {
		return rpmver.LessThanEVR
	}
	return debver.LessThan
}

// Match returns confirmed vulnerabilities for the given package inventory.
// family selects the version comparator ("rhel" -> rpm EVR, else dpkg). Results
// are deduplicated per (CVE, source package); Running is the OR across all
// binary packages built from that source.
func Match(pkgs []model.Package, release, family string, src AdvisorySource, opt Options) []model.Finding {
	less := comparatorFor(family)
	type key struct{ cve, source string }
	seen := make(map[key]*model.Finding)
	order := make([]key, 0)

	for _, p := range pkgs {
		for _, adv := range src.ForPackage(p.Source, release) {
			vuln, fixed := evaluate(adv, p.SourceVersion, less, opt)
			if !vuln {
				continue
			}
			k := key{adv.CVE, adv.SourcePackage}
			if f, ok := seen[k]; ok {
				f.Running = f.Running || p.Running
				continue
			}
			f := &model.Finding{
				CVE:              adv.CVE,
				SourcePackage:    adv.SourcePackage,
				InstalledVersion: p.SourceVersion,
				FixedVersion:     fixed,
				Urgency:          adv.Urgency,
				Status:           adv.Status,
				Running:          p.Running,
				Description:      adv.Description,
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

// evaluate applies tracker semantics for one advisory against an installed
// source version, using the supplied version comparator.
func evaluate(adv model.Advisory, installed string, less lessFunc, opt Options) (vulnerable bool, fixedVersion string) {
	switch adv.Status {
	case "open":
		// Known vulnerable in this release, no fix released yet.
		return true, ""
	case "resolved":
		// fixed_version "" or "0" means the package was never vulnerable here.
		if adv.FixedVersion == "" || adv.FixedVersion == "0" {
			return false, ""
		}
		// Vulnerable iff what's installed is older than the fix.
		if less(installed, adv.FixedVersion) {
			return true, adv.FixedVersion
		}
		return false, adv.FixedVersion
	case "undetermined":
		if opt.IncludeUndetermined {
			return true, ""
		}
		return false, ""
	default:
		return false, ""
	}
}
