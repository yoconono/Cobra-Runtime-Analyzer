package redhat

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yourorg/cve-fleet/server/internal/model"
)

// LoadPath ingests CSAF VEX advisories from a filesystem path, which may be:
//   - a single .json CSAF document,
//   - a directory tree of .json documents, or
//   - a .tar / .tar.gz / .tgz archive of .json documents (Red Hat ships the VEX
//     corpus as an archive).
func LoadPath(path string) ([]model.Advisory, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return loadDir(path)
	}
	low := strings.ToLower(path)
	switch {
	case strings.HasSuffix(low, ".tar.gz"), strings.HasSuffix(low, ".tgz"), strings.HasSuffix(low, ".tar"):
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return loadTar(f, strings.HasSuffix(low, ".gz") || strings.HasSuffix(low, ".tgz"))
	case strings.HasSuffix(low, ".zst"), strings.HasSuffix(low, ".tar.zst"):
		return nil, fmt.Errorf("zstd archives are not supported without an extra dependency; " +
			"decompress to .tar (zstd -d %s) or point --redhat-csaf at the extracted directory", path)
	default: // single json document
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ParseCSAF(b)
	}
}

func loadDir(dir string) ([]model.Advisory, error) {
	var all []model.Advisory
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(strings.ToLower(p), ".json") {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil // skip unreadable file
		}
		advs, perr := ParseCSAF(b)
		if perr != nil {
			return nil // skip non-CSAF json
		}
		all = append(all, advs...)
		return nil
	})
	return all, err
}

func loadTar(r io.Reader, gzipped bool) ([]model.Advisory, error) {
	if gzipped {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	var all []model.Advisory
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return all, err
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(strings.ToLower(h.Name), ".json") {
			continue
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tr); err != nil { //nolint:gosec // entries are size-bounded by the archive
			return all, err
		}
		if advs, perr := ParseCSAF(buf.Bytes()); perr == nil {
			all = append(all, advs...)
		}
	}
	return all, nil
}

// DefaultCSAFArchiveURL is the Red Hat CSAF VEX corpus. Red Hat currently ships
// it as .tar.zst; download and decompress to .tar(.gz) or a directory, then use
// LoadPath. Kept here for documentation and for future zstd support.
const DefaultCSAFArchiveURL = "https://security.access.redhat.com/data/csaf/v2/vex/archive_latest.txt"

// FetchArchive downloads a CSAF archive from url and parses it. Only .tar and
// .tar.gz/.tgz are supported (stdlib); a .zst URL returns a clear error.
func FetchArchive(url string) ([]model.Advisory, error) {
	low := strings.ToLower(url)
	if strings.HasSuffix(low, ".zst") {
		return nil, fmt.Errorf("zstd archive %s is unsupported; fetch/decompress to .tar.gz and use --redhat-csaf", url)
	}
	cl := &http.Client{Timeout: 10 * time.Minute}
	resp, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return loadTar(resp.Body, strings.HasSuffix(low, ".gz") || strings.HasSuffix(low, ".tgz"))
}
