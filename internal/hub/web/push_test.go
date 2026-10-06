package web

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"fleetwatch/internal/hub/store"
)

func browserKeys(t *testing.T) (string, string) {
	t.Helper()
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	a := make([]byte, 16)
	rand.Read(a)
	return base64.RawURLEncoding.EncodeToString(p.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(a)
}

func TestServiceWorkerIsPublic(t *testing.T) {
	h := newHarness(t, "http://localhost:8080", false)
	w := h.do("GET", "/sw.js", nil, nil, false)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/javascript") || w.Header().Get("Cache-Control") != "no-cache" ||
		!strings.Contains(w.Body.String(), "showNotification") {
		t.Errorf("sw.js: %d %v", w.Code, w.Header())
	}
}

func TestPushSubscribe(t *testing.T) {
	h := newHarness(t, "http://localhost:8080", false)
	c := h.login()
	ctx := context.Background()
	p256dh, auth := browserKeys(t)
	body := func(endpoint, p, a string) string {
		return `{"endpoint":"` + endpoint + `","keys":{"p256dh":"` + p + `","auth":"` + a + `"},"label":"Chrome on Android"}`
	}
	if w := h.postJSON("/push/subscribe", nil, body("https://push.example/x", p256dh, auth)); w.Code == http.StatusNoContent {
		t.Error("subscribe needs a login")
	}
	for name, b := range map[string]string{
		"http endpoint": body("http://push.example/x", p256dh, auth),
		"no host":       body("https:///x", p256dh, auth),
		"long endpoint": body("https://push.example/"+strings.Repeat("a", 1100), p256dh, auth),
		"bad key":       body("https://push.example/x", "AAAA", auth),
		"bad auth":      body("https://push.example/x", p256dh, "AAAA"),
		"not json":      `{`,
	} {
		if w := h.postJSON("/push/subscribe", []*http.Cookie{c}, b); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	if w := h.postJSON("/push/subscribe", []*http.Cookie{c}, body("https://push.example/secret-x", p256dh, auth)); w.Code != http.StatusNoContent {
		t.Fatalf("subscribe: %d %s", w.Code, w.Body)
	}
	subs, _ := h.st.PushSubscriptions(ctx)
	if len(subs) != 1 || subs[0].Label != "Chrome on Android" {
		t.Fatalf("stored: %+v", subs)
	}
	if strings.Contains(h.logs.Text(), "secret-x") {
		t.Error("the endpoint must not be logged")
	}
	if w := h.postJSON("/push/state", []*http.Cookie{c}, `{"endpoint":"https://push.example/secret-x"}`); !strings.Contains(w.Body.String(), `"stored":true`) {
		t.Errorf("state: %s", w.Body)
	}
	if w := h.postJSON("/push/state", []*http.Cookie{c}, `{"endpoint":"https://push.example/other"}`); !strings.Contains(w.Body.String(), `"stored":false`) {
		t.Errorf("state of an unknown browser: %s", w.Body)
	}
	if w := h.postJSON("/push/unsubscribe", []*http.Cookie{c}, `{"endpoint":"https://push.example/secret-x"}`); w.Code != http.StatusNoContent {
		t.Errorf("unsubscribe: %d", w.Code)
	}
	if subs, _ := h.st.PushSubscriptions(ctx); len(subs) != 0 {
		t.Errorf("left after unsubscribe: %+v", subs)
	}
}

func TestSettingsPushSection(t *testing.T) {
	h := newHarness(t, "http://localhost:8080", false)
	c := h.login()
	ctx := context.Background()
	h.st.SavePushSubscription(ctx, store.PushSubscription{Endpoint: "https://push.example/secret-y", P256dh: "k", Auth: "a", Label: "Safari on iPhone"}, h.clock)
	page := h.do("GET", "/settings", c, nil, false).Body.String()
	set, _ := h.st.Settings(ctx)
	key := set["push_vapid_key"]
	if key == "" || strings.Contains(page, key) {
		t.Fatal("the page must make the key and never show the private key")
	}
	for _, want := range []string{`id="push"`, `data-key="B`, "Phone and browser notifications", "Safari on iPhone", "/static/push.js"} {
		if !strings.Contains(page, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	if strings.Contains(page, "secret-y") {
		t.Error("the page must not show an endpoint")
	}
	// A Settings save keeps the key.
	h.do("POST", "/settings", c, url.Values{"telegram_chat_id": {""}}, false)
	if set, _ := h.st.Settings(ctx); set["push_vapid_key"] != key {
		t.Error("a Settings save changed the key")
	}
	subs, _ := h.st.PushSubscriptions(ctx)
	if w := h.do("POST", "/push/"+itoa(subs[0].ID)+"/delete", c, url.Values{}, false); w.Code != http.StatusSeeOther {
		t.Errorf("delete: %d", w.Code)
	}
	if w := h.do("POST", "/push/"+itoa(subs[0].ID)+"/delete", c, url.Values{}, false); w.Code != http.StatusNotFound {
		t.Errorf("second delete: %d", w.Code)
	}
}

// After the login expires, the page script gets a plain 401 with a message,
// not the login page through a followed redirect.
func TestPushRoutesAnswer401WithoutLogin(t *testing.T) {
	h := newHarness(t, "http://localhost:8080", false)
	for _, path := range []string{"/push/subscribe", "/push/unsubscribe", "/push/state", "/push/test"} {
		w := h.postJSON(path, nil, `{"endpoint":"https://push.example/x"}`)
		if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "Log in again") {
			t.Errorf("%s: %d %q", path, w.Code, w.Body.String())
		}
	}
}
