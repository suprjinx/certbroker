// Package bao is a minimal OpenBao client: AppRole auth with token lifecycle,
// plus sign/issue/ca_chain. Avoids the full SDK to keep the audit surface small.
package bao

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures the OpenBao client. File/env resolution happens in the
// wiring layer; this package takes already-resolved values.
type Config struct {
	Address        string        // e.g. https://openbao.internal:8200
	PKIMount       string        // PKI secrets mount, e.g. "pki_int"
	CACertPEM      []byte        // PEM trust anchor for the API TLS; nil = system roots
	AppRoleMount   string        // auth mount, e.g. "approle"
	RoleID         string        // AppRole RoleID
	SecretID       string        // AppRole SecretID (secret; never logged)
	RenewThreshold time.Duration // renew/re-login when the token is within this of expiry
	MaxRetries     int           // request retries on transient failures (network / 5xx)
}

// Client is a concurrency-safe OpenBao client. A single Client should be shared
// across the process; token state is guarded internally.
type Client struct {
	cfg    Config
	hc     *http.Client
	logger *slog.Logger

	mu          sync.Mutex // guards the token fields
	token       string
	tokenExpiry time.Time // absolute time the current token lease ends
	renewable   bool
}

// New builds a Client with the configured CA trust anchor. It does not log in;
// the first request (or an explicit Login) authenticates.
func New(cfg Config, logger *slog.Logger) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("bao: address is required")
	}
	if cfg.PKIMount == "" {
		return nil, errors.New("bao: PKI mount is required")
	}
	if cfg.RoleID == "" || cfg.SecretID == "" {
		return nil, errors.New("bao: AppRole role_id and secret_id are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.AppRoleMount == "" {
		cfg.AppRoleMount = "approle"
	}
	if cfg.RenewThreshold <= 0 {
		cfg.RenewThreshold = 5 * time.Minute
	}
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 0
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(cfg.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, errors.New("bao: no valid certificates in CACertPEM")
		}
		tlsCfg.RootCAs = pool
	}

	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:     tlsCfg,
			MaxIdleConnsPerHost: 4,
			ForceAttemptHTTP2:   true,
		},
	}

	return &Client{
		cfg:    cfg,
		hc:     hc,
		logger: logger,
	}, nil
}

// authResponse is the subset of the auth envelope the broker consumes.
type authResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

// Login performs (or forces a fresh) AppRole login, replacing any current token.
func (c *Client) Login(ctx context.Context) error {
	body := map[string]string{
		"role_id":   c.cfg.RoleID,
		"secret_id": c.cfg.SecretID,
	}
	path := fmt.Sprintf("v1/auth/%s/login", c.cfg.AppRoleMount)

	var out authResponse
	// Login must not attach a token and must not recurse into ensureToken.
	if err := c.doRaw(ctx, http.MethodPost, path, body, "", &out); err != nil {
		return fmt.Errorf("bao: approle login: %w", err)
	}
	if out.Auth == nil || out.Auth.ClientToken == "" {
		return errors.New("bao: approle login returned no token")
	}

	c.mu.Lock()
	c.token = out.Auth.ClientToken
	c.renewable = out.Auth.Renewable
	c.tokenExpiry = leaseExpiry(out.Auth.LeaseDuration)
	c.mu.Unlock()

	c.logger.Info("openbao login ok",
		"renewable", out.Auth.Renewable,
		"lease_seconds", out.Auth.LeaseDuration,
	)
	return nil
}

// renewSelf attempts to extend the current token's lease. Returns an error if
// the token is not renewable or the renewal is rejected.
func (c *Client) renewSelf(ctx context.Context) error {
	var out authResponse
	if err := c.doRaw(ctx, http.MethodPost, "v1/auth/token/renew-self", nil, c.currentToken(), &out); err != nil {
		return err
	}
	if out.Auth == nil {
		return errors.New("bao: renew-self returned no auth")
	}
	c.mu.Lock()
	c.renewable = out.Auth.Renewable
	c.tokenExpiry = leaseExpiry(out.Auth.LeaseDuration)
	c.mu.Unlock()
	return nil
}

// ensureToken guarantees a usable token, renewing or re-authenticating. Safe
// for concurrent callers.
func (c *Client) ensureToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	tok := c.token
	expiry := c.tokenExpiry
	renewable := c.renewable
	c.mu.Unlock()

	// Token is present and comfortably valid.
	if tok != "" && time.Until(expiry) > c.cfg.RenewThreshold {
		return tok, nil
	}

	// Near expiry (or absent). Try a cheap renewal first when possible.
	if tok != "" && renewable && time.Until(expiry) > 0 {
		if err := c.renewSelf(ctx); err != nil {
			c.logger.Warn("openbao token renew failed, re-authenticating", "err", err)
		} else {
			return c.currentToken(), nil
		}
	}

	if err := c.Login(ctx); err != nil {
		return "", err
	}
	return c.currentToken(), nil
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.token
}

// do issues an authenticated request and decodes JSON into out (may be nil).
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	tok, err := c.ensureToken(ctx)
	if err != nil {
		return err
	}
	return c.doRaw(ctx, method, path, body, tok, out)
}

// doRaw performs one request with retry/backoff on transient failures. An empty
// token is allowed (login); a nil out discards the body.
func (c *Client) doRaw(ctx context.Context, method, path string, body any, token string, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("bao: marshal request: %w", err)
		}
	}

	url := strings.TrimRight(c.cfg.Address, "/") + "/" + strings.TrimLeft(path, "/")

	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}

		var rdr io.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rdr)
		if err != nil {
			return fmt.Errorf("bao: build request: %w", err)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("X-Vault-Token", token)
		}

		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("bao: %s %s: %w", method, path, err)
			continue // network error: retry
		}

		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("bao: read response: %w", err)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = apiError(method, path, resp.StatusCode, respBody)
			continue // server error: retry
		}
		if resp.StatusCode >= 400 {
			return apiError(method, path, resp.StatusCode, respBody) // client error: do not retry
		}

		if out != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, out); err != nil {
				return fmt.Errorf("bao: decode response: %w", err)
			}
		}
		return nil
	}
	return lastErr
}

// doRawBytes returns the raw body, for endpoints like ca_chain that emit PEM.
func (c *Client) doRawBytes(ctx context.Context, method, path string) ([]byte, error) {
	tok, err := c.ensureToken(ctx)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(c.cfg.Address, "/") + "/" + strings.TrimLeft(path, "/")

	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, fmt.Errorf("bao: build request: %w", err)
		}
		if tok != "" {
			req.Header.Set("X-Vault-Token", tok)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("bao: %s %s: %w", method, path, err)
			continue
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("bao: read response: %w", err)
			continue
		}
		if resp.StatusCode >= 500 {
			lastErr = apiError(method, path, resp.StatusCode, respBody)
			continue
		}
		if resp.StatusCode >= 400 {
			return nil, apiError(method, path, resp.StatusCode, respBody)
		}
		return respBody, nil
	}
	return nil, lastErr
}

// leaseExpiry converts lease seconds to an absolute expiry; non-positive (root
// tokens) becomes far-future so the client never renews needlessly.
func leaseExpiry(seconds int) time.Time {
	if seconds <= 0 {
		return time.Now().Add(100 * 365 * 24 * time.Hour)
	}
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

// backoff returns an exponential backoff with jitter for the given 1-based attempt.
func backoff(attempt int) time.Duration {
	base := 100 * time.Millisecond * time.Duration(1<<uint(attempt-1))
	if base > 5*time.Second {
		base = 5 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(base)/2 + 1))
	return base + jitter
}

// APIError describes a non-2xx OpenBao response.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Errors     []string
}

func (e *APIError) Error() string {
	msg := strings.Join(e.Errors, "; ")
	if msg == "" {
		msg = "(no error detail)"
	}
	return fmt.Sprintf("bao: %s %s -> %d: %s", e.Method, e.Path, e.StatusCode, msg)
}

func apiError(method, path string, status int, body []byte) *APIError {
	e := &APIError{Method: method, Path: path, StatusCode: status}
	var parsed struct {
		Errors []string `json:"errors"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && len(parsed.Errors) > 0 {
		e.Errors = parsed.Errors
	} else if len(body) > 0 {
		e.Errors = []string{strings.TrimSpace(string(body))}
	}
	return e
}
