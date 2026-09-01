// Package redhat ingests Red Hat security data (CSAF/VEX) into the same
// model.Advisory shape used for the Debian/Ubuntu tracker, so the existing
// matcher can evaluate Red Hat family hosts using rpm (EVR) version comparison.
//
// Red Hat publishes one CSAF VEX document per CVE. Each document's
// vulnerabilities[].product_status lists product_ids that are "fixed" or
// "known_affected"; a product_id encodes both the RHEL release and a package
// NEVRA, e.g.:
//
//	red_hat_enterprise_linux_9:openssl-1:3.0.7-27.el9_2.src
//	└ product ref ────────────┘ └ name ┘└epoch┘└ ver ┘└rel┘└arch┘
//
// We key advisories on the SOURCE package (arch "src"), matching the source
// package + source EVR that the agent reports from rpm, and derive the release
// token ("el9") from the product ref so it lines up with tracker.Codename.
package redhat

import (
	"encoding/json"
	"strings"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

type csafDoc struct {
	Document struct {
		Tracking          struct{ ID string `json:"id"` } `json:"tracking"`
		AggregateSeverity struct{ Text string `json:"text"` } `json:"aggregate_severity"`
	} `json:"document"`
	Vulnerabilities []struct {
		CVE           string `json:"cve"`
		ProductStatus struct {
			Fixed         []string `json:"fixed"`
			KnownAffected []string `json:"known_affected"`
		} `json:"product_status"`
		Threats []struct {
			Category string `json:"category"`
			Details  string `json:"details"`
		} `json:"threats"`
	} `json:"vulnerabilities"`
}

// ParseCSAF turns one CSAF VEX document into advisories (possibly several: one
// per affected source package × RHEL release).
func ParseCSAF(data []byte) ([]model.Advisory, error) {
	var d csafDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	type key struct{ cve, src, rel string }
	seen := map[key]int{} // index into out
	var out []model.Advisory

	add := func(cve, sev string, pid string, status, fixed string) {
		rel, name, evr, arch, ok := parseProductID(pid)
		if !ok || arch != "src" { // key on the source rpm
			return
		}
		fv := ""
		if status == "resolved" {
			fv = evr
		}
		k := key{cve, name, rel}
		if idx, dup := seen[k]; dup {
			// Prefer a resolved advisory (with a fixed version) over an open one.
			if out[idx].Status != "resolved" && status == "resolved" {
				out[idx].Status = "resolved"
				out[idx].FixedVersion = fv
			}
			return
		}
		seen[k] = len(out)
		out = append(out, model.Advisory{
			CVE:           cve,
			SourcePackage: name,
			Release:       rel,
			Status:        status,
			FixedVersion:  fixed_or(fv, fixed),
			Urgency:       sev,
		})
	}

	for _, v := range d.Vulnerabilities {
		cve := v.CVE
		if cve == "" {
			cve = d.Document.Tracking.ID
		}
		sev := severity(v.Threats, d.Document.AggregateSeverity.Text)
		for _, pid := range v.ProductStatus.Fixed {
			add(cve, sev, pid, "resolved", "")
		}
		for _, pid := range v.ProductStatus.KnownAffected {
			add(cve, sev, pid, "open", "")
		}
	}
	return out, nil
}

func fixed_or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// severity picks the Red Hat impact for the vulnerability: the per-vuln
// "impact" threat if present, else the document aggregate severity.
func severity(threats []struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}, aggregate string) string {
	for _, t := range threats {
		if t.Category == "impact" && t.Details != "" {
			return t.Details
		}
	}
	return aggregate
}

// knownArch reports whether tok is an rpm architecture (the final NEVRA token).
func knownArch(tok string) bool {
	switch tok {
	case "src", "noarch", "x86_64", "i686", "i386", "aarch64", "ppc64le", "ppc64", "s390x", "riscv64":
		return true
	}
	return false
}

// parseProductID splits a CSAF product_id into release token, package name, EVR
// and arch. Returns ok=false for non-RHEL products or unparseable ids.
func parseProductID(pid string) (release, name, evr, arch string, ok bool) {
	// Split the product reference from the NEVRA on the FIRST ':'. The NEVRA
	// itself contains a ':' for the epoch, so we cannot split on the last one.
	colon := strings.IndexByte(pid, ':')
	if colon < 0 {
		return "", "", "", "", false
	}
	ref := pid[:colon]
	nevra := pid[colon+1:]
	release, ok = releaseFromRef(ref)
	if !ok {
		return "", "", "", "", false
	}
	name, evr, arch, ok = parseNEVRA(nevra)
	if !ok {
		return "", "", "", "", false
	}
	return release, name, evr, arch, true
}

// releaseFromRef derives "elN" from a product reference such as
// "red_hat_enterprise_linux_9" or "red_hat_enterprise_linux_8.6:appstream".
// Non-RHEL products (OpenShift, etc.) return ok=false so they are skipped.
func releaseFromRef(ref string) (string, bool) {
	low := strings.ToLower(ref)
	i := strings.Index(low, "enterprise_linux_")
	if i < 0 {
		return "", false
	}
	rest := low[i+len("enterprise_linux_"):]
	// Take the leading integer (major version), stopping at '.', '_' or ':'.
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return "", false
	}
	return "el" + rest[:j], true
}

// parseNEVRA parses "openssl-1:3.0.7-27.el9_2.src" into name, EVR
// ("1:3.0.7-27.el9_2") and arch ("src"). Epoch is required (Red Hat product ids
// always include it), which is what lets us split the name from the version.
func parseNEVRA(nevra string) (name, evr, arch string, ok bool) {
	// arch is the final dot-component, but only when it is a real arch token
	// (release strings also contain dots, e.g. ".el9_2").
	if dot := strings.LastIndexByte(nevra, '.'); dot >= 0 {
		if a := nevra[dot+1:]; knownArch(a) {
			arch = a
			nevra = nevra[:dot]
		}
	}
	// nevra is now name-epoch:version-release. Split on the epoch ':'.
	colon := strings.IndexByte(nevra, ':')
	if colon < 0 {
		return "", "", "", false
	}
	left := nevra[:colon]  // name-epoch
	right := nevra[colon+1:] // version-release
	dash := strings.LastIndexByte(left, '-')
	if dash < 0 {
		return "", "", "", false
	}
	name = left[:dash]
	epoch := left[dash+1:]
	if name == "" || epoch == "" || right == "" {
		return "", "", "", false
	}
	evr = epoch + ":" + right
	return name, evr, arch, true
}
