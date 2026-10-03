package web

import (
	"regexp"
	"strings"
	"testing"

	"fleetwatch/internal/version"
)

// A proxy such as Cloudflare caches /static/ files by extension for hours, so
// scripts and the stylesheet carry the version: a new release is a new URL.
func TestStaticLinksCarryVersion(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	want := "?v=" + version.Version
	for _, path := range []string{"/login", "/", "/settings"} {
		body := h.do("GET", path, c, nil, false).Body.String()
		for _, m := range regexp.MustCompile(`(?:href|src)="(/static/[^"]+\.(?:css|js)[^"]*)"`).FindAllStringSubmatch(body, -1) {
			if !strings.HasSuffix(m[1], want) {
				t.Errorf("%s links %s, want it to end in %s", path, m[1], want)
			}
		}
	}
	if w := h.do("GET", "/static/app.css"+want, nil, nil, false); w.Code != 200 {
		t.Errorf("versioned URL: status %d", w.Code)
	}
}
