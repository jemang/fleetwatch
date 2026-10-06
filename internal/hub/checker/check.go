package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/version"
)

const (
	maxRedirects = 5
	maxBody      = 64 << 10
)

var errTooManyRedirects = errors.New("too many redirects")

// client makes a fresh connection for every check: a pooled connection would
// hide a service that stopped accepting new ones. The self-signed switch
// turns certificate verification off for internal services with their own
// certificate; the connection is still encrypted.
func client(sv store.Service) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	if sv.AcceptSelfSigned {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   time.Duration(sv.TimeoutS) * time.Second,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errTooManyRedirects
			}
			return nil
		},
	}
}

// Check requests the service once. Ms is the time to the response headers.
func Check(ctx context.Context, sv store.Service, now func() time.Time) Result {
	c := client(sv)
	defer c.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sv.URL, nil)
	if err != nil {
		return Result{Reason: "request failed", At: now()}
	}
	req.Header.Set("User-Agent", "FleetWatch/"+version.Version)
	start := time.Now()
	resp, err := c.Do(req)
	ms := int(time.Since(start).Milliseconds())
	if err != nil {
		return Result{Ms: ms, Reason: reason(err), At: now()}
	}
	io.CopyN(io.Discard, resp.Body, maxBody)
	resp.Body.Close()
	r := Result{Ms: ms, Code: resp.StatusCode, At: now()}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.CertExpires = resp.TLS.PeerCertificates[0].NotAfter
	}
	if sv.ExpectedStatus != 0 {
		r.OK = resp.StatusCode == sv.ExpectedStatus
	} else {
		r.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	if !r.OK {
		r.Reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return r
}

// reason names a failure without the URL, which can carry a token.
func reason(err error) string {
	var (
		dnsErr  *net.DNSError
		invalid x509.CertificateInvalidError
		unknown x509.UnknownAuthorityError
		host    x509.HostnameError
		alert   tls.AlertError
		record  tls.RecordHeaderError
		netErr  net.Error
		opErr   *net.OpError
	)
	switch {
	case errors.Is(err, errTooManyRedirects):
		return "too many redirects"
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return "TLS: certificate expired"
		}
		return "TLS: handshake failed"
	case errors.As(err, &unknown):
		return "TLS: unknown certificate authority"
	case errors.As(err, &host):
		return "TLS: wrong host name"
	case errors.As(err, &alert), errors.As(err, &record):
		return "TLS: handshake failed"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "network unreachable"
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "connection failed"
	}
	return "request failed"
}
