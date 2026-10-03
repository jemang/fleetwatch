package limit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiterBlocksAfterMaxFailuresWithinWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(5, time.Minute, func() time.Time { return now })
	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("attempt %d must be allowed", i+1)
		}
		l.Fail("1.2.3.4")
	}
	if l.Allow("1.2.3.4") {
		t.Error("the sixth attempt within a minute must be blocked")
	}
	if !l.Allow("5.6.7.8") {
		t.Error("another address must not be affected")
	}
	now = now.Add(61 * time.Second)
	if !l.Allow("1.2.3.4") {
		t.Error("failures older than the window must be forgotten")
	}
}

func TestRemoteIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.9:51234"
	if got := RemoteIP(r); got != "192.168.1.9" {
		t.Errorf("RemoteIP = %q", got)
	}
	r.RemoteAddr = "[2001:db8::1]:443"
	if got := RemoteIP(r); got != "2001:db8::1" {
		t.Errorf("RemoteIP = %q", got)
	}
}

func TestRemoteIPBehindATrustedProxy(t *testing.T) {
	defer SetTrustedProxies(nil)
	req := func(remote, xff string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	if got := RemoteIP(req("203.0.113.9:4000", "198.51.100.7")); got != "203.0.113.9" {
		t.Errorf("without trusted proxies the header is ignored: %q", got)
	}
	prefixes, err := ParsePrefixes("172.20.0.0/16, 10.0.0.1")
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("ParsePrefixes: %v %v", prefixes, err)
	}
	SetTrustedProxies(prefixes)
	cases := map[string]struct{ remote, xff, want string }{
		"from the proxy":            {"172.20.0.1:5000", "198.51.100.7", "198.51.100.7"},
		"chain, last hop counts":    {"172.20.0.1:5000", "1.2.3.4, 198.51.100.7", "198.51.100.7"},
		"proxy behind proxy":        {"172.20.0.1:5000", "198.51.100.7, 10.0.0.1", "198.51.100.7"},
		"spaces and ipv6":           {"10.0.0.1:1", " 2001:db8::5 ", "2001:db8::5"},
		"not from the proxy":        {"203.0.113.9:4000", "198.51.100.7", "203.0.113.9"},
		"proxy without the header":  {"172.20.0.1:5000", "", "172.20.0.1"},
		"garbage in the header":     {"172.20.0.1:5000", "not-an-ip", "172.20.0.1"},
	}
	for name, c := range cases {
		if got := RemoteIP(req(c.remote, c.xff)); got != c.want {
			t.Errorf("%s: RemoteIP = %q, want %q", name, got, c.want)
		}
	}
	if _, err := ParsePrefixes("172.20.0.0/16, nope"); err == nil {
		t.Error("a bad entry must be an error")
	}
	if p, err := ParsePrefixes(" "); err != nil || len(p) != 0 {
		t.Errorf("empty list: %v %v", p, err)
	}
}
