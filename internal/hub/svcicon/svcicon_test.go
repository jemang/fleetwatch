package svcicon

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var (
	png = append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 40)...)
	ico = append([]byte{0, 0, 1, 0}, make([]byte, 40)...)
	opt = Options{Timeout: 2 * time.Second}
)

type routes map[string]http.HandlerFunc

func site(t *testing.T, r routes) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for p, h := range r {
		mux.HandleFunc(p, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func page(html string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	}
}

func file(typ string, b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if typ != "" {
			w.Header().Set("Content-Type", typ)
		}
		w.Write(b)
	}
}

func TestLinkTagWithRelativeHref(t *testing.T) {
	srv := site(t, routes{
		"/app/{$}": page(`<html><head><LINK href="img/i.png?a=1&amp;b=2" REL='shortcut icon'></head>`),
		"/app/img/i.png": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "a=1&b=2" {
				t.Errorf("query = %q, want the href unescaped", r.URL.RawQuery)
			}
			file("image/png", png)(w, r)
		},
	})
	data, typ, err := Fetch(context.Background(), srv.URL+"/app/", opt)
	if err != nil || typ != "image/png" || !bytes.Equal(data, png) {
		t.Fatalf("got %q %v", typ, err)
	}
}

func TestAppleTouchIconAndSniffedType(t *testing.T) {
	srv := site(t, routes{
		"/{$}":   page(`<link rel="stylesheet" href="/s.css"><link rel="apple-touch-icon" href="/t.png">`),
		"/t.png": file("application/octet-stream", png),
	})
	if _, typ, err := Fetch(context.Background(), srv.URL, opt); err != nil || typ != "image/png" {
		t.Fatalf("got %q %v", typ, err)
	}
}

func TestFallsBackToFaviconIco(t *testing.T) {
	srv := site(t, routes{
		"/{$}":         page(`<html>no icon here</html>`),
		"/favicon.ico": file("", ico),
	})
	if _, typ, err := Fetch(context.Background(), srv.URL, opt); err != nil || typ != "image/x-icon" {
		t.Fatalf("got %q %v", typ, err)
	}
}

func TestBrokenLinkFallsBackToFaviconIco(t *testing.T) {
	srv := site(t, routes{
		"/{$}":         page(`<link rel=icon href=/missing.png>`),
		"/favicon.ico": file("image/vnd.microsoft.icon", ico),
	})
	if _, typ, err := Fetch(context.Background(), srv.URL, opt); err != nil || typ != "image/vnd.microsoft.icon" {
		t.Fatalf("got %q %v", typ, err)
	}
}

func TestSVGKeepsItsType(t *testing.T) {
	srv := site(t, routes{
		"/{$}":   page(`<link rel="icon" type="image/svg+xml" href="/i.svg">`),
		"/i.svg": file("image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)),
	})
	if _, typ, err := Fetch(context.Background(), srv.URL, opt); err != nil || typ != "image/svg+xml" {
		t.Fatalf("got %q %v", typ, err)
	}
}

// Hostile or broken sites end in an error, and nothing is returned.
func TestRefusals(t *testing.T) {
	cases := map[string]routes{
		"404 everywhere": {"/{$}": http.NotFound},
		"html as icon":   {"/{$}": page(`x`), "/favicon.ico": page(`<html>not an image</html>`)},
		"too large":      {"/{$}": page(`x`), "/favicon.ico": file("image/png", append(png, make([]byte, 300<<10)...))},
		"redirect loop": {"/{$}": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) },
			"/favicon.ico": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/favicon.ico", http.StatusFound) }},
	}
	for name, r := range cases {
		srv := site(t, r)
		if data, _, err := Fetch(context.Background(), srv.URL, opt); err == nil || data != nil {
			t.Errorf("%s: err = %v, data %d bytes", name, err, len(data))
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}

func TestTimeoutIsHonoured(t *testing.T) {
	release := make(chan struct{})
	srv := site(t, routes{
		"/": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		},
	})
	defer close(release)
	start := time.Now()
	if _, _, err := Fetch(context.Background(), srv.URL, Options{Timeout: 200 * time.Millisecond}); err == nil {
		t.Fatal("a site that never answers must fail")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestSelfSignedNeedsTheSwitch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", page(`<link rel=icon href=/i.png>`))
	mux.HandleFunc("/i.png", file("image/png", png))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	if _, _, err := Fetch(context.Background(), srv.URL, opt); err == nil {
		t.Error("an unknown certificate must be refused by default")
	}
	if _, _, err := Fetch(context.Background(), srv.URL, Options{Timeout: 2 * time.Second, AcceptSelfSigned: true}); err != nil {
		t.Errorf("with the switch on: %v", err)
	}
}

// The reason never carries the URL, which may hold a token.
func TestReasonDropsTheURL(t *testing.T) {
	_, _, err := Fetch(context.Background(), "http://127.0.0.1:1/?token=s3cret", Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("port 1 must refuse")
	}
	var ue *url.Error
	if !errors.As(err, &ue) {
		t.Fatalf("want a *url.Error inside, got %T", err)
	}
	if r := Reason(err); strings.Contains(r, "s3cret") || strings.Contains(r, "127.0.0.1:1/?") || r == "" {
		t.Errorf("Reason = %q", r)
	}
}

func TestFindIconHref(t *testing.T) {
	if h := findIconHref([]byte(`<link rel="preload" href="/a"><link href="/b.ico" rel="Icon">`)); h != "/b.ico" {
		t.Errorf("href = %q", h)
	}
	if h := findIconHref([]byte(`<link rel="iconic" href="/no">`)); h != "" {
		t.Errorf("rel must contain the token icon, not the text: %q", h)
	}
}

func TestReasonHidesABrokenRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://x/%zz?token=s3cret")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	_, _, err := Fetch(context.Background(), srv.URL, Options{Timeout: time.Second})
	if err == nil {
		t.Fatal("a broken redirect must fail")
	}
	if r := Reason(err); strings.Contains(r, "s3cret") || r != "bad redirect" {
		t.Errorf("Reason = %q", r)
	}
}
