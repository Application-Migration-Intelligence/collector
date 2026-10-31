// Package upload sends a package to the customer's MigrateIntel project over
// HTTPS. It talks only to MigrateIntel: the endpoint must be https and one of
// the MigrateIntel hosts, and redirects are not followed.
package upload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// DefaultEndpoint is where packages go unless --endpoint names another MigrateIntel host.
const DefaultEndpoint = "https://migrateintel.com"

// Path is the intake API path on the endpoint.
const Path = "/api/collector/v1/packages"

// Hosts the collector may send to: production and staging.
var allowedHosts = map[string]bool{
	"migrateintel.com": true, "www.migrateintel.com": true,
	"migrateintel.net": true, "www.migrateintel.net": true,
}

// A one-time project key from the dashboard.
var keyFormat = regexp.MustCompile(`^[A-Za-z0-9_\-]{20,200}$`)

// Result is the intake's reply.
type Result struct {
	PackageID  string `json:"package_id"`
	ProjectURL string `json:"project_url"`
}

// Client sends packages.
type Client struct {
	HTTP      *http.Client
	UserAgent string
}

// New returns a client that never follows redirects.
func New(version string) *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout:       30 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		UserAgent: "mig-collector/" + version,
	}
}

// CheckEndpoint returns the intake URL for an endpoint, or why it is refused.
func CheckEndpoint(endpoint string) (string, error) {
	base, err := BaseURL(endpoint)
	if err != nil {
		return "", err
	}
	return base + Path, nil
}

// BaseURL returns https://<host> for an endpoint, or why it is refused: it
// must be https and one of the MigrateIntel hosts.
func BaseURL(endpoint string) (string, error) {
	u, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("the endpoint must be https://<MigrateIntel host> with no path, got %q", endpoint)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] || (u.Port() != "" && u.Port() != "443") {
		return "", fmt.Errorf("%s is not a MigrateIntel host; the collector only sends to MigrateIntel", u.Host)
	}
	return "https://" + strings.ToLower(u.Hostname()), nil
}

// CheckKey validates a project key's shape (the intake checks it for real).
func CheckKey(key string) error {
	if !keyFormat.MatchString(key) {
		return errors.New("the project key is missing or malformed; copy the command again from your project page")
	}
	return nil
}

// Send uploads the package file to intakeURL.
func (c *Client) Send(ctx context.Context, intakeURL, key, file string) (*Result, error) {
	if err := CheckKey(key); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, intakeURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/vnd.mig.collector-package+gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("X-Mig-Package-Sha256", hex.EncodeToString(sum[:]))

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var problem struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		_ = json.Unmarshal(body, &problem)
		msg := problem.Message
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, fmt.Errorf("upload refused (%d %s): %s", resp.StatusCode, problem.Code, msg)
	}
	var res Result
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("unexpected reply from the intake: %w", err)
	}
	return &res, nil
}
