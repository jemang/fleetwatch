// Package client sends enrollment and report requests to the Hub.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fleetwatch/internal/protocol"
)

var ErrUnauthorized = errors.New("client: hub rejected the credential")

type ReplayError struct{ LastTS int64 }

func (e *ReplayError) Error() string {
	return fmt.Sprintf("client: hub already has a report with ts %d or newer", e.LastTS)
}

type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("client: hub answered HTTP %d", e.Code) }

type Client struct {
	HubURL string
	Token  string
	HTTP   *http.Client
}

func New(hubURL, token string) *Client {
	return &Client{
		HubURL: strings.TrimRight(hubURL, "/"),
		Token:  token,
		HTTP: &http.Client{
			Timeout: 10 * time.Second,
			// A redirect could carry the bearer token to another scheme or host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Client) post(ctx context.Context, path string, body any, compress bool) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	if compress {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(b)
		if err := zw.Close(); err != nil {
			return 0, nil, err
		}
		b = buf.Bytes()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.HubURL+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if compress {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, out, nil
}

// Self asks the Hub how it knows this agent.
func (c *Client) Self(ctx context.Context) (protocol.SelfResponse, error) {
	var out protocol.SelfResponse
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.HubURL+"/api/v1/agent/self", nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
			return out, fmt.Errorf("client: unreadable self response")
		}
		return out, nil
	case http.StatusUnauthorized:
		return out, ErrUnauthorized
	}
	return out, &StatusError{Code: resp.StatusCode}
}

// MaxDownload bounds one release file.
const MaxDownload = 64 << 20

// Download fetches one release file. It sends no credential: the files are
// public and are trusted only after their signature is verified.
func (c *Client) Download(ctx context.Context, name string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.HubURL+"/dl/"+name, nil)
	if err != nil {
		return nil, err
	}
	// The agent file is several megabytes, so the report timeout is too short.
	hc := *c.HTTP
	hc.Timeout = 5 * time.Minute
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{Code: resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownload+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxDownload {
		return nil, fmt.Errorf("client: %s is larger than %d bytes", name, MaxDownload)
	}
	return b, nil
}

func (c *Client) Send(ctx context.Context, r protocol.Report) error {
	code, body, err := c.post(ctx, "/api/v1/agent/report", r, true)
	if err != nil {
		return err
	}
	switch code {
	case http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusConflict:
		var rr protocol.ReplayResponse
		json.Unmarshal(body, &rr)
		return &ReplayError{LastTS: rr.LastTS}
	}
	return &StatusError{Code: code}
}

func (c *Client) Enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var out protocol.EnrollResponse
	code, body, err := c.post(ctx, "/api/v1/agent/enroll", req, false)
	if err != nil {
		return out, err
	}
	switch code {
	case http.StatusOK:
		if err := json.Unmarshal(body, &out); err != nil || out.AgentToken == "" {
			return out, fmt.Errorf("client: unreadable enroll response")
		}
		return out, nil
	case http.StatusUnauthorized:
		return out, ErrUnauthorized
	}
	return out, &StatusError{Code: code}
}
