package web

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"fleetwatch/internal/hub/store"
)

func TestEnsureAdminRefusesShortPassword(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	if err := EnsureAdmin(ctx, st, "change-me"); err == nil || !strings.Contains(err.Error(), "12 characters") {
		t.Errorf("9-character password: err = %v, want it to name the minimum", err)
	}
	if exists, _ := st.AdminExists(ctx); exists {
		t.Error("a refused password must not create the admin")
	}
	if err := EnsureAdmin(ctx, st, strings.Repeat("x", 73)); err == nil || !strings.Contains(err.Error(), "72") {
		t.Errorf("73-byte password: err = %v, want it to name the maximum", err)
	}
}

func changePassword(h *harness, c *http.Cookie, current, next, repeat string) *http.Response {
	return h.do("POST", "/settings/password", c, url.Values{"current": {current}, "new": {next}, "repeat": {repeat}}, false).Result()
}

func TestChangePassword(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	other := h.login()
	const next = "correct horse battery"

	for _, tc := range []struct{ current, next, repeat, want string }{
		{"pw", "short", "short", "at least 12 characters"},
		{"pw", next, next + "!", "do not match"},
		{"pw", strings.Repeat("x", 73), strings.Repeat("x", 73), "at most 72 bytes"},
		{"wrong", next, next, "Current password is wrong"},
	} {
		res := changePassword(h, c, tc.current, tc.next, tc.repeat)
		body := new(strings.Builder)
		res.Write(body)
		if res.StatusCode == http.StatusSeeOther || !strings.Contains(body.String(), tc.want) {
			t.Errorf("current %q new %q: status %d, want an error with %q", tc.current, tc.next, res.StatusCode, tc.want)
		}
	}

	res := changePassword(h, c, "pw", next, next)
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/settings?password=1" {
		t.Fatalf("change: status %d, location %q", res.StatusCode, res.Header.Get("Location"))
	}
	if w := h.do("GET", "/settings?password=1", c, nil, false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Password changed") {
		t.Errorf("this session must stay logged in and see the result: status %d", w.Code)
	}
	if w := h.do("GET", "/", other, nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("another session must be logged out: status %d", w.Code)
	}
	if w := h.do("POST", "/login", nil, url.Values{"password": {"pw"}}, false); w.Code != http.StatusUnauthorized {
		t.Errorf("old password: status %d, want 401", w.Code)
	}
	if w := h.do("POST", "/login", nil, url.Values{"password": {next}}, false); w.Code != http.StatusSeeOther {
		t.Errorf("new password: status %d, want 303", w.Code)
	}
	logged := h.logs.Text()
	if !strings.Contains(logged, "admin password changed") || !strings.Contains(logged, "password change refused") {
		t.Errorf("log must record the change and the refusal:\n%s", logged)
	}
	if strings.Contains(logged, next) || strings.Contains(logged, "wrong\n") {
		t.Errorf("log must not contain a password:\n%s", logged)
	}
}

func TestChangePasswordRateLimit(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	const next = "correct horse battery"
	for i := 0; i < 5; i++ {
		changePassword(h, c, "wrong", next, next)
	}
	if res := changePassword(h, c, "pw", next, next); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("sixth attempt within a minute: %d, want 429", res.StatusCode)
	}
}

func TestChangePasswordNeedsSession(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	if res := changePassword(h, nil, "pw", "correct horse battery", "correct horse battery"); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		t.Errorf("without a session: status %d, location %q", res.StatusCode, res.Header.Get("Location"))
	}
}
