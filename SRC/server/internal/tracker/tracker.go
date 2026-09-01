// Package tracker parses the Debian Security Tracker feed
// (https://security-tracker.debian.org/tracker/data/json) into flat advisories.
package tracker

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// DefaultURL is the canonical Debian Security Tracker JSON feed.
const DefaultURL = "https://security-tracker.debian.org/tracker/data/json"

// releaseByVersionID maps an os-release VERSION_ID to a Debian codename.
var releaseByVersionID = map[string]string{
	"10": "buster",
	"11": "bullseye",
	"12": "bookworm",
	"13": "trixie",
	"14": "forky",
}

// ubuntuReleaseByVersionID maps an Ubuntu VERSION_ID to its codename (as used by
// the Ubuntu Security Notices feed).
var ubuntuReleaseByVersionID = map[string]string{
	"16.04": "xenial",
	"18.04": "bionic",
	"20.04": "focal",
	"22.04": "jammy",
	"22.10": "kinetic",
	"23.04": "lunar",
	"23.10": "mantic",
	"24.04": "noble",
	"24.10": "oracular",
	"25.04": "plucky",
	"25.10": "questing",
}

// Codename returns the distro codename for an os-release ID + VERSION_ID. Ubuntu
// and Debian use different release names for the same version string, so the os
// ID disambiguates. If the version already looks like a codename it's returned
// unchanged.
func Codename(osID, versionID string) string {
	switch osID {
	case "ubuntu":
		if c, ok := ubuntuReleaseByVersionID[versionID]; ok {
			return c
		}
	case "rhel", "redhat", "centos", "fedora", "rocky", "almalinux", "ol", "oracle",
		"oraclelinux", "amzn", "amazon", "scientific", "cloudlinux", "eurolinux", "circle":
		// Red Hat family: the release token is "el"+major, matching the tokens
		// the CSAF ingester derives from Red Hat product ids.
		if m := major(versionID); m != "" {
			return "el" + m
		}
	default: // debian (and unknown, which historically meant Debian)
		if c, ok := releaseByVersionID[versionID]; ok {
			return c
		}
	}
	return versionID
}

// Family classifies an OS ID into the version-comparison family used by the
// matcher: "rhel" (rpm/EVR) or "debian" (dpkg). Anything not recognised as Red
// Hat family is treated as Debian, preserving existing behaviour.
func Family(osID string) string {
	switch osID {
	case "rhel", "redhat", "centos", "fedora", "rocky", "almalinux", "ol", "oracle",
		"oraclelinux", "amzn", "amazon", "scientific", "cloudlinux", "eurolinux", "circle":
		return "rhel"
	default:
		return "debian"
	}
}

// major returns the leading integer of a version id ("9.4" -> "9", "9" -> "9").
func major(versionID string) string {
	i := 0
	for i < len(versionID) && versionID[i] >= '0' && versionID[i] <= '9' {
		i++
	}
	return versionID[:i]
}

// raw mirrors the tracker JSON shape we care about:
//
//	{ "<source>": { "<CVE>": { "description": "...",
//	    "releases": { "<codename>": { "status","fixed_version","urgency" } } } } }
type raw map[string]map[string]struct {
	Description string `json:"description"`
	Releases    map[string]struct {
		Status       string `json:"status"`
		FixedVersion string `json:"fixed_version"`
		Urgency      string `json:"urgency"`
	} `json:"releases"`
}

// Parse converts the tracker JSON into a flat slice of advisories.
func Parse(r io.Reader) ([]model.Advisory, error) {
	var data raw
	dec := json.NewDecoder(r)
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("decode tracker json: %w", err)
	}
	var out []model.Advisory
	for src, cves := range data {
		for cve, info := range cves {
			for codename, rel := range info.Releases {
				out = append(out, model.Advisory{
					CVE:           cve,
					SourcePackage: src,
					Release:       codename,
					Status:        rel.Status,
					FixedVersion:  rel.FixedVersion,
					Urgency:       rel.Urgency,
					Description:   info.Description,
				})
			}
		}
	}
	return out, nil
}

// FetchFile parses a tracker feed already on disk (useful offline/testing).
func FetchFile(path string) ([]model.Advisory, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// FetchURL downloads and parses the tracker feed.
func FetchURL(url string) ([]model.Advisory, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: http %d", url, resp.StatusCode)
	}
	return Parse(resp.Body)
}
