package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestLoadConfigDefaults(t *testing.T) {
	c, err := LoadConfig(envOf(map[string]string{"FLEETWATCH_PUBLIC_URL": "https://hub.example.com/"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/data" || c.Listen != ":8080" || c.PublicURL != "https://hub.example.com" || c.TLS() {
		t.Errorf("config = %+v", c)
	}
	if c.DLDir != "/usr/share/fleetwatch/dl" {
		t.Errorf("default directory of the agent files = %q", c.DLDir)
	}
	c, _ = LoadConfig(envOf(map[string]string{"FLEETWATCH_PUBLIC_URL": "https://hub", "FLEETWATCH_DL_DIR": "/srv/dl"}))
	if c.DLDir != "/srv/dl" {
		t.Errorf("FLEETWATCH_DL_DIR is not used: %q", c.DLDir)
	}
}

func TestRetentionFromEnvironment(t *testing.T) {
	base := map[string]string{"FLEETWATCH_PUBLIC_URL": "https://hub"}
	c, err := LoadConfig(envOf(base))
	if err != nil || c.Retention != store.DefaultRetention {
		t.Fatalf("default retention = %+v, %v", c.Retention, err)
	}
	base["FLEETWATCH_RETENTION_RAW"] = "48h"
	base["FLEETWATCH_RETENTION_1H"] = "17520h"
	c, err = LoadConfig(envOf(base))
	if err != nil || c.Retention.Raw != 48*time.Hour || c.Retention.Hour1 != 17520*time.Hour || c.Retention.Min1 != store.DefaultRetention.Min1 {
		t.Errorf("retention = %+v, %v", c.Retention, err)
	}
	for _, bad := range []string{"soon", "-1h", "0"} {
		base["FLEETWATCH_RETENTION_5M"] = bad
		if _, err := LoadConfig(envOf(base)); err == nil || !strings.Contains(err.Error(), "FLEETWATCH_RETENTION_5M") {
			t.Errorf("retention %q: err = %v, want it to name the variable", bad, err)
		}
	}
}

func TestServerTimeouts(t *testing.T) {
	srv := newServer(":0", http.NewServeMux())
	if srv.ReadHeaderTimeout != 10*time.Second || srv.ReadTimeout != 30*time.Second || srv.IdleTimeout != 2*time.Minute {
		t.Errorf("a client that sends slowly must not hold a connection open: header %v, read %v, idle %v", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.IdleTimeout)
	}
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v; the dashboard event stream must not have a write deadline", srv.WriteTimeout)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	cases := []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{}, "FLEETWATCH_PUBLIC_URL"},
		{map[string]string{"FLEETWATCH_PUBLIC_URL": "hub.example.com"}, "FLEETWATCH_PUBLIC_URL"},
		{map[string]string{"FLEETWATCH_PUBLIC_URL": "https://hub", "FLEETWATCH_TLS_CERT": "/c.pem"}, "FLEETWATCH_TLS_KEY"},
	}
	for _, tc := range cases {
		if _, err := LoadConfig(envOf(tc.env)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("env %v: err = %v, want it to mention %s", tc.env, err, tc.want)
		}
	}
	c, err := LoadConfig(envOf(map[string]string{"FLEETWATCH_PUBLIC_URL": "https://hub", "FLEETWATCH_TLS_CERT": "/c.pem", "FLEETWATCH_TLS_KEY": "/k.pem"}))
	if err != nil || !c.TLS() {
		t.Errorf("cert and key together must enable TLS: %+v, %v", c, err)
	}
}

func TestSlowRequestsAreLogged(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	h := logSlow(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			now = now.Add(2 * time.Second)
		case "/broken":
			w.WriteHeader(http.StatusInternalServerError)
		case "/events":
			now = now.Add(time.Hour)
		}
	}), logf, clock)
	for _, path := range []string{"/fast", "/slow", "/broken", "/events"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "GET /slow 200 2s") || !strings.Contains(lines[1], "GET /broken 500") {
		t.Errorf("logged = %q; want the slow and the failed request only", lines)
	}
}

func TestProxySettings(t *testing.T) {
	c, err := LoadConfig(envOf(map[string]string{"FLEETWATCH_PUBLIC_URL": "https://monitor.example.com", "FLEETWATCH_TRUSTED_PROXIES": "172.20.0.0/16, 10.0.0.1"}))
	if err != nil || len(c.TrustedProxies) != 2 || c.TrustedProxies[0].String() != "172.20.0.0/16" || c.TrustedProxies[1].String() != "10.0.0.1/32" {
		t.Errorf("trusted proxies = %v, %v", c.TrustedProxies, err)
	}
	if !c.SecureCookies() {
		t.Error("an https:// public URL means cookies travel over HTTPS, even when a proxy does the TLS")
	}
	if c, _ := LoadConfig(envOf(map[string]string{"FLEETWATCH_PUBLIC_URL": "http://hub:8080"})); c.SecureCookies() || len(c.TrustedProxies) != 0 {
		t.Errorf("plain HTTP without proxies: secure %v, proxies %v", c.SecureCookies(), c.TrustedProxies)
	}
	if _, err := LoadConfig(envOf(map[string]string{"FLEETWATCH_PUBLIC_URL": "https://hub", "FLEETWATCH_TRUSTED_PROXIES": "nope"})); err == nil || !strings.Contains(err.Error(), "FLEETWATCH_TRUSTED_PROXIES") {
		t.Errorf("a bad list must name the variable: %v", err)
	}
}
