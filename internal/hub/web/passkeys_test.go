package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"fleetwatch/internal/hub/live"
)

func (h *harness) postJSON(path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	return w
}

// fakeCredential is a stored record in the library's JSON shape; it is enough
// for listing and for login options, never for a real signature check.
const fakeCredential = `{"id":"Y3JlZC0x","publicKey":"cGs=","attestationType":"none","flags":{},"authenticator":{"AAGUID":"","signCount":3}}`

func TestPasskeysOffWithoutHTTPSAndHostName(t *testing.T) {
	for _, publicURL := range []string{"http://192.168.1.5:8080", "https://10.0.0.1", "http://hub.example.com"} {
		h := newHarness(t, publicURL, false)
		c := h.login()
		if body := h.do("GET", "/settings", c, nil, false).Body.String(); !strings.Contains(body, "Passkeys are off") || strings.Contains(body, `id="passkey-add"`) {
			t.Errorf("%s: settings must explain that passkeys are off", publicURL)
		}
		if w := h.postJSON("/passkeys/register/begin", []*http.Cookie{c}, `{"name":"x"}`); w.Code != http.StatusConflict {
			t.Errorf("%s: register begin: %d, want 409", publicURL, w.Code)
		}
		h.st.AddPasskey(context.Background(), "MacBook", []byte("cred-1"), []byte(fakeCredential), h.clock)
		if body := h.do("GET", "/login", nil, nil, false).Body.String(); strings.Contains(body, `id="passkey-login"`) {
			t.Errorf("%s: the login page must not offer a passkey", publicURL)
		}
		if w := h.postJSON("/login/passkey/begin", nil, ""); w.Code != http.StatusConflict {
			t.Errorf("%s: login begin: %d, want 409", publicURL, w.Code)
		}
	}
	// localhost over plain HTTP is allowed by browsers, so the Hub allows it too.
	h := newHarness(t, "http://localhost:8080", false)
	if body := h.do("GET", "/settings", h.login(), nil, false).Body.String(); !strings.Contains(body, `id="passkey-add"`) {
		t.Error("localhost: passkeys must be on")
	}
}

func TestPasskeyRegistration(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	if w := h.postJSON("/passkeys/register/begin", nil, `{"name":"x"}`); w.Code != http.StatusSeeOther {
		t.Errorf("without a session: %d", w.Code)
	}
	c := h.login()
	w := h.postJSON("/passkeys/register/begin", []*http.Cookie{c}, `{"name":"MacBook"}`)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("begin: %d %s", w.Code, w.Body)
	}
	var opts struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			RP        struct {
				ID, Name string
			} `json:"rp"`
			User struct {
				Name string `json:"name"`
			} `json:"user"`
			AuthenticatorSelection struct {
				ResidentKey string `json:"residentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(w.Body.Bytes(), &opts) != nil || len(opts.PublicKey.Challenge) < 20 || opts.PublicKey.RP.ID != "hub.example.com" || opts.PublicKey.RP.Name != "FleetWatch" ||
		opts.PublicKey.User.Name != "admin" || opts.PublicKey.AuthenticatorSelection.ResidentKey != "required" {
		t.Errorf("options = %s", w.Body)
	}
	var ceremony *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "fw_ceremony" && ck.HttpOnly && ck.SameSite == http.SameSiteStrictMode {
			ceremony = ck
		}
	}
	if ceremony == nil {
		t.Fatal("begin must set the ceremony cookie")
	}
	if w := h.postJSON("/passkeys/register/finish", []*http.Cookie{c}, `{}`); w.Code != http.StatusBadRequest {
		t.Errorf("finish without a ceremony: %d, want 400", w.Code)
	}
	if w := h.postJSON("/passkeys/register/finish", []*http.Cookie{c, ceremony}, `{"id":"x","rawId":"eA","type":"public-key","response":{}}`); w.Code != http.StatusBadRequest {
		t.Errorf("finish with a broken response: %d, want 400", w.Code)
	}
	if w := h.postJSON("/passkeys/register/begin", []*http.Cookie{c}, `{"name":""}`); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("a passkey needs a name: %d", w.Code)
	}
	if list, _ := h.st.Passkeys(context.Background()); len(list) != 0 {
		t.Error("nothing may be stored before a valid response")
	}
}

func TestPasskeyLoginOptionsAndLimit(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	if body := h.do("GET", "/login", nil, nil, false).Body.String(); strings.Contains(body, `id="passkey-login"`) {
		t.Error("without a registered passkey the login page offers none")
	}
	h.st.AddPasskey(context.Background(), "MacBook", []byte("cred-1"), []byte(fakeCredential), h.clock)
	body := h.do("GET", "/login", nil, nil, false).Body.String()
	if !strings.Contains(body, `id="passkey-login"`) || !strings.Contains(body, "/static/passkey.js") {
		t.Error("with a passkey the login page offers it")
	}
	w := h.postJSON("/login/passkey/begin", nil, "")
	var opts struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			RPID             string `json:"rpId"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &opts) != nil || len(opts.PublicKey.Challenge) < 20 || opts.PublicKey.RPID != "hub.example.com" || opts.PublicKey.UserVerification != "preferred" {
		t.Fatalf("login begin: %d %s", w.Code, w.Body)
	}
	var ceremony *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "fw_ceremony" {
			ceremony = ck
		}
	}
	for i := 0; i < 5; i++ {
		if w := h.postJSON("/login/passkey/finish", []*http.Cookie{ceremony}, `{"id":"x","rawId":"eA","type":"public-key","response":{}}`); w.Code != http.StatusBadRequest {
			t.Fatalf("bad assertion %d: %d, want 400", i, w.Code)
		}
	}
	if w := h.postJSON("/login/passkey/begin", nil, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("after 5 failures: %d, want 429", w.Code)
	}
	if w := h.do("POST", "/login", nil, url.Values{"password": {"pw"}}, false); w.Code != http.StatusTooManyRequests {
		t.Errorf("passkey failures and password failures share one limit: %d", w.Code)
	}
}

func TestSettingsListsAndRemovesPasskeys(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	id, _ := h.st.AddPasskey(context.Background(), "Mac<Book>", []byte("cred-1"), []byte(fakeCredential), h.clock)
	body := h.do("GET", "/settings", c, nil, false).Body.String()
	for _, want := range []string{"Mac&lt;Book&gt;", `action="/passkeys/1/delete"`, `id="passkey-add"`, "/static/passkey.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings is missing %q", want)
		}
	}
	if w := h.do("POST", "/passkeys/1/delete", nil, nil, false); w.Header().Get("Location") != "/login" {
		t.Error("removing needs a session")
	}
	if w := h.do("POST", "/passkeys/1/delete", c, nil, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/settings" {
		t.Errorf("delete: %d %q", w.Code, w.Header().Get("Location"))
	}
	if _, err := h.st.PasskeyByCredentialID(context.Background(), []byte("cred-1")); err == nil {
		t.Errorf("passkey %d must be gone", id)
	}
	if w := h.do("POST", "/passkeys/1/delete", c, nil, false); w.Code != http.StatusNotFound {
		t.Errorf("deleting twice: %d", w.Code)
	}
}

func TestRemoveHost(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web-01")
	h.addHost("web-02")
	c := h.login()
	page := "/hosts/" + strconv.FormatInt(id, 10)
	body := h.do("GET", page, c, nil, false).Body.String()
	if !strings.Contains(body, `action="`+page+`/delete"`) || !strings.Contains(body, "Remove server") || !strings.Contains(body, "confirm(") {
		t.Error("the host page must offer removal, with a confirmation")
	}
	if w := h.do("POST", page+"/delete", nil, nil, false); w.Header().Get("Location") != "/login" {
		t.Error("removal needs a session")
	}
	events, cancel := h.bus.Subscribe()
	defer cancel()
	if w := h.do("POST", page+"/delete", c, nil, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("delete: %d %q", w.Code, w.Header().Get("Location"))
	}
	if ev := <-events; ev.Kind != live.HostRemoved || ev.HostID != id {
		t.Errorf("removal must publish HostRemoved: %+v", ev)
	}
	if hosts, _ := h.st.Hosts(context.Background()); len(hosts) != 1 || hosts[0].Name != "web-02" {
		t.Errorf("hosts after delete = %+v", hosts)
	}
	if w := h.do("POST", page+"/delete", c, nil, false); w.Code != http.StatusNotFound {
		t.Errorf("deleting twice: %d", w.Code)
	}
	if w := h.do("GET", page, c, nil, false); w.Code != http.StatusNotFound {
		t.Errorf("the page of a removed host: %d", w.Code)
	}
}
