// Package svcicon fetches the icon of a web application the way a browser
// finds a favicon, with bounds on time and size.
package svcicon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"fleetwatch/internal/version"
)

const (
	maxPage      = 512 << 10
	maxIcon      = 256 << 10
	maxRedirects = 5
)

// Options are the per-service settings every request of a fetch uses.
type Options struct {
	Timeout          time.Duration
	AcceptSelfSigned bool
}

// Client is an HTTP client for requests to a service. AcceptSelfSigned turns
// certificate verification off, for internal services with their own
// certificate (a Proxmox UI); the connection is still encrypted.
func Client(o Options) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if o.AcceptSelfSigned {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// get reads at most limit+1 bytes, so a caller can tell an over-size body.
func get(ctx context.Context, c *http.Client, u string, limit int64) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "FleetWatch/"+version.Version)
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, resp, fmt.Errorf("answered HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	return b, resp, err
}

// Fetch loads the page, follows its icon link, and falls back to
// /favicon.ico on the page's origin.
func Fetch(ctx context.Context, pageURL string, o Options) ([]byte, string, error) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, "", err
	}
	if base.Host == "" {
		return nil, "", errors.New("the URL has no host")
	}
	c := Client(o)
	defer c.CloseIdleConnections()
	var tried []string
	body, resp, err := get(ctx, c, pageURL, maxPage)
	if resp != nil {
		base = resp.Request.URL // after redirects
	}
	if err == nil {
		if href := findIconHref(body); href != "" {
			if ref, perr := url.Parse(href); perr == nil {
				tried = append(tried, base.ResolveReference(ref).String())
			}
		}
	}
	fallback := (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: "/favicon.ico"}).String()
	if len(tried) == 0 || tried[0] != fallback {
		tried = append(tried, fallback)
	}
	last := err
	for _, u := range tried {
		data, typ, ierr := icon(ctx, c, u)
		if ierr == nil {
			return data, typ, nil
		}
		last = ierr
	}
	return nil, "", last
}

func icon(ctx context.Context, c *http.Client, u string) ([]byte, string, error) {
	data, resp, err := get(ctx, c, u, maxIcon)
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxIcon {
		return nil, "", fmt.Errorf("icon larger than %d KB", maxIcon>>10)
	}
	typ, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(typ, "image/") {
		typ, _, _ = mime.ParseMediaType(http.DetectContentType(data))
	}
	if !strings.HasPrefix(typ, "image/") {
		return nil, "", errors.New("the icon is not an image")
	}
	return data, typ, nil
}

var (
	linkTag = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	attr    = regexp.MustCompile(`(?is)\b(rel|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// findIconHref returns the href of the first <link> whose rel has the token
// "icon" or "apple-touch-icon", or "".
func findIconHref(page []byte) string {
	for _, tag := range linkTag.FindAll(page, -1) {
		var rel, href string
		for _, m := range attr.FindAllSubmatch(tag, -1) {
			v := html.UnescapeString(string(m[2]) + string(m[3]) + string(m[4]))
			if strings.EqualFold(string(m[1]), "rel") {
				rel = v
			} else {
				href = v
			}
		}
		for _, tok := range strings.Fields(strings.ToLower(rel)) {
			if (tok == "icon" || tok == "apple-touch-icon") && href != "" {
				return href
			}
		}
	}
	return ""
}

// Reason is the error text for a log line. The URL a *url.Error carries is
// dropped, because its query can hold a token.
func Reason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}
