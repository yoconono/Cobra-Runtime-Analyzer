package enrich

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultEPSSURL is the daily EPSS scores dump (gzipped CSV).
const DefaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

// EPSSInfo is the exploit-prediction record for one CVE.
type EPSSInfo struct {
	Score      float64 // probability 0..1
	Percentile float64 // 0..1
}

// ParseEPSS parses the EPSS CSV (cve,epss,percentile), skipping the leading
// "#model_version..." comment lines and the header row.
func ParseEPSS(r io.Reader) (map[string]EPSSInfo, error) {
	out := map[string]EPSSInfo{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	seenHeader := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !seenHeader && strings.HasPrefix(strings.ToLower(line), "cve,") {
			seenHeader = true
			continue
		}
		cols := strings.Split(line, ",")
		if len(cols) < 3 {
			continue
		}
		score, err1 := strconv.ParseFloat(cols[1], 64)
		pct, err2 := strconv.ParseFloat(cols[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out[cols[0]] = EPSSInfo{Score: score, Percentile: pct}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("epss: read: %w", err)
	}
	return out, nil
}

// FetchEPSSFile parses an EPSS CSV from disk (transparently gunzips .gz).
func FetchEPSSFile(path string) (map[string]EPSSInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	return ParseEPSS(r)
}

// FetchEPSSURL downloads and parses the EPSS dump (gzipped CSV).
func FetchEPSSURL(url string) (map[string]EPSSInfo, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss: http %d", resp.StatusCode)
	}
	var r io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	return ParseEPSS(r)
}
