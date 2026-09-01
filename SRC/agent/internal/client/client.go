// Package client speaks to the CVE Fleet server over HTTPS only. It handles
// one-time enrollment (exchanging a registration token for a durable credential)
// and authenticated report submission.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/yourorg/cve-fleet/agent/internal/config"
	"github.com/yourorg/cve-fleet/agent/internal/model"
)

// Credential is the per-agent identity issued at enrollment and stored on disk.
type Credential struct {
	AgentID  string `json:"agent_id"`
	APIToken string `json:"api_token"`
}

type Client struct {
	cfg  config.Config
	http *http.Client
	cred Credential
	ua   string
}

func New(cfg config.Config, userAgent string) (*Client, error) {
	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // testing only; gated by config validation
	}
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_cert_file: no certificates found")
		}
		tlsConf.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConf,
		DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.HTTPTimeout, Transport: transport},
		ua:   userAgent,
	}, nil
}

func (c *Client) credPath() string { return filepath.Join(c.cfg.StateDir, "credentials.json") }

// CredPath is the on-disk location of the durable credential.
func (c *Client) CredPath() string { return c.credPath() }

// CredentialFileExists reports whether a credential file is present (regardless
// of whether it could be read) — used to tell "first run" apart from a
// permissions problem.
func (c *Client) CredentialFileExists() bool {
	_, err := os.Stat(c.credPath())
	return err == nil
}

// LoadCredential reads a previously stored credential. Returns true if a valid
// one was loaded.
func (c *Client) LoadCredential() bool {
	b, err := os.ReadFile(c.credPath())
	if err != nil {
		return false
	}
	if json.Unmarshal(b, &c.cred) != nil {
		return false
	}
	return c.cred.AgentID != "" && c.cred.APIToken != ""
}

func (c *Client) Enrolled() bool { return c.cred.AgentID != "" && c.cred.APIToken != "" }

// Enroll exchanges the registration token for a durable credential and holds it
// in memory. Persisting it to disk is a separate step (PersistCredential) so a
// write failure doesn't discard a credential the server already issued.
func (c *Client) Enroll(req model.EnrollRequest) error {
	var resp model.EnrollResponse
	if err := c.doJSON(http.MethodPost, "/api/v1/agents/enroll", "", req, &resp); err != nil {
		return err
	}
	if resp.AgentID == "" || resp.APIToken == "" {
		return fmt.Errorf("server returned an empty credential")
	}
	c.cred = Credential{AgentID: resp.AgentID, APIToken: resp.APIToken}
	return nil
}

// PersistCredential writes the in-memory credential to disk so future runs skip
// enrollment.
func (c *Client) PersistCredential() error {
	if c.cred.AgentID == "" || c.cred.APIToken == "" {
		return fmt.Errorf("no credential to persist")
	}
	if err := os.MkdirAll(c.cfg.StateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir %s: %w", c.cfg.StateDir, err)
	}
	b, _ := json.Marshal(c.cred)
	if err := os.WriteFile(c.credPath(), b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", c.credPath(), err)
	}
	return nil
}

// Report submits a scan result using the stored credential.
func (c *Client) Report(r model.Report) (model.ReportResponse, error) {
	var resp model.ReportResponse
	path := "/api/v1/agents/" + c.cred.AgentID + "/report"
	err := c.doJSON(http.MethodPost, path, c.cred.APIToken, r, &resp)
	return resp, err
}

func (c *Client) doJSON(method, path, bearer string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, c.cfg.ServerURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: http %d: %s", method, path, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
