package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/store"
)

const (
	ceremonyCookie = "fw_ceremony"
	ceremonyTTL    = 5 * time.Minute
	maxPasskeyName = 64
)

var adminHandle = []byte("admin")

// adminUser is the one account, as the WebAuthn library sees it.
type adminUser struct{ creds []webauthn.Credential }

func (adminUser) WebAuthnID() []byte                           { return adminHandle }
func (adminUser) WebAuthnName() string                         { return "admin" }
func (adminUser) WebAuthnDisplayName() string                  { return "FleetWatch admin" }
func (u adminUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ceremony is one registration or login in progress: the challenge waits
// here until the browser answers.
type ceremony struct {
	kind    string // "register" or "login"
	name    string // register: the passkey's name
	data    webauthn.SessionData
	expires time.Time
}

// passkeyRelyingParty returns the WebAuthn configuration for the public URL,
// or nil when browsers would refuse passkeys for it: plain HTTP (except
// localhost) or an IP address instead of a host name.
func passkeyRelyingParty(publicURL string) *webauthn.WebAuthn {
	u, err := url.Parse(publicURL)
	if err != nil {
		return nil
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && host == "localhost") {
		return nil
	}
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "FleetWatch", RPID: host, RPOrigins: []string{u.Scheme + "://" + u.Host}})
	if err != nil {
		return nil
	}
	return wa
}

func (w *Web) passkeyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /passkeys/register/begin", w.requireSession(w.passkeyRegisterBegin))
	mux.HandleFunc("POST /passkeys/register/finish", w.requireSession(w.passkeyRegisterFinish))
	mux.HandleFunc("POST /passkeys/{id}/delete", w.requireSession(w.passkeyDelete))
	mux.HandleFunc("POST /login/passkey/begin", w.passkeyLoginBegin)
	mux.HandleFunc("POST /login/passkey/finish", w.passkeyLoginFinish)
}

func (w *Web) passkeysOn() bool { return w.wa != nil }

func (w *Web) putCeremony(rw http.ResponseWriter, c ceremony) error {
	key, err := store.NewToken()
	if err != nil {
		return err
	}
	c.expires = w.now().Add(ceremonyTTL)
	w.cerMu.Lock()
	for k, old := range w.ceremonies {
		if !old.expires.After(w.now()) {
			delete(w.ceremonies, k)
		}
	}
	w.ceremonies[key] = c
	w.cerMu.Unlock()
	http.SetCookie(rw, &http.Cookie{Name: ceremonyCookie, Value: key, Path: "/", MaxAge: int(ceremonyTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: w.secure})
	return nil
}

// takeCeremony returns the ceremony of the request's cookie once.
func (w *Web) takeCeremony(r *http.Request, kind string) (ceremony, bool) {
	ck, err := r.Cookie(ceremonyCookie)
	if err != nil {
		return ceremony{}, false
	}
	w.cerMu.Lock()
	defer w.cerMu.Unlock()
	c, ok := w.ceremonies[ck.Value]
	delete(w.ceremonies, ck.Value)
	if !ok || c.kind != kind || !c.expires.After(w.now()) {
		return ceremony{}, false
	}
	return c, true
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(rw).Encode(v)
}

// admin loads the stored passkeys as the library's credentials.
func (w *Web) admin(r *http.Request) (adminUser, []store.Passkey, error) {
	keys, err := w.st.Passkeys(r.Context())
	if err != nil {
		return adminUser{}, nil, err
	}
	u := adminUser{}
	for _, p := range keys {
		var c webauthn.Credential
		if json.Unmarshal(p.Credential, &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, keys, nil
}

func (w *Web) passkeyRegisterBegin(rw http.ResponseWriter, r *http.Request) {
	if !w.passkeysOn() {
		http.Error(rw, "Passkeys are off for this Hub address. They need HTTPS and a host name.", http.StatusConflict)
		return
	}
	var req struct{ Name string }
	if err := json.NewDecoder(http.MaxBytesReader(rw, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(rw, "malformed request", http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > maxPasskeyName {
		http.Error(rw, "Give the passkey a name of 1 to 64 characters.", http.StatusUnprocessableEntity)
		return
	}
	user, _, err := w.admin(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	var exclude []protocol.CredentialDescriptor
	for i := range user.creds {
		exclude = append(exclude, user.creds[i].Descriptor())
	}
	opts, sess, err := w.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclude))
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.putCeremony(rw, ceremony{kind: "register", name: req.Name, data: *sess}); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(rw, opts)
}

func (w *Web) passkeyRegisterFinish(rw http.ResponseWriter, r *http.Request) {
	c, ok := w.takeCeremony(r, "register")
	if !ok || !w.passkeysOn() {
		http.Error(rw, "The registration took too long or was not started. Try again.", http.StatusBadRequest)
		return
	}
	user, _, err := w.admin(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 64<<10)
	cred, err := w.wa.FinishRegistration(user, c.data, r)
	if err != nil {
		http.Error(rw, "The browser's answer was not accepted: "+err.Error(), http.StatusBadRequest)
		return
	}
	b, err := json.Marshal(cred)
	if err == nil {
		_, err = w.st.AddPasskey(r.Context(), c.name, cred.ID, b, w.now())
	}
	if err != nil {
		http.Error(rw, "The passkey could not be stored.", http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (w *Web) passkeyDelete(rw http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		err = w.st.DeletePasskey(r.Context(), id)
	}
	if errors.Is(err, store.ErrNotFound) || id == 0 {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, r, "/settings", http.StatusSeeOther)
}

func (w *Web) passkeyLoginBegin(rw http.ResponseWriter, r *http.Request) {
	if !w.loginLimit.Allow(limit.RemoteIP(r)) {
		http.Error(rw, "Too many failed attempts. Wait one minute.", http.StatusTooManyRequests)
		return
	}
	keys, err := w.st.Passkeys(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if !w.passkeysOn() || len(keys) == 0 {
		http.Error(rw, "No passkey can be used on this Hub.", http.StatusConflict)
		return
	}
	opts, sess, err := w.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.putCeremony(rw, ceremony{kind: "login", data: *sess}); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(rw, opts)
}

func (w *Web) passkeyLoginFinish(rw http.ResponseWriter, r *http.Request) {
	ip := limit.RemoteIP(r)
	if !w.loginLimit.Allow(ip) {
		http.Error(rw, "Too many failed attempts. Wait one minute.", http.StatusTooManyRequests)
		return
	}
	c, ok := w.takeCeremony(r, "login")
	if !ok || !w.passkeysOn() {
		w.loginLimit.Fail(ip)
		http.Error(rw, "The login took too long or was not started. Try again.", http.StatusBadRequest)
		return
	}
	var used store.Passkey
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if !bytes.Equal(userHandle, adminHandle) {
			return nil, errors.New("unknown user")
		}
		p, err := w.st.PasskeyByCredentialID(r.Context(), rawID)
		if err != nil {
			return nil, errors.New("unknown passkey")
		}
		var cred webauthn.Credential
		if err := json.Unmarshal(p.Credential, &cred); err != nil {
			return nil, err
		}
		used = p
		return adminUser{creds: []webauthn.Credential{cred}}, nil
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 64<<10)
	_, cred, err := w.wa.FinishPasskeyLogin(handler, c.data, r)
	if err == nil && cred.Authenticator.CloneWarning {
		err = errors.New("the sign counter went backwards; the passkey may have been copied")
	}
	if err != nil {
		w.loginLimit.Fail(ip)
		http.Error(rw, "The passkey was not accepted: "+err.Error(), http.StatusBadRequest)
		return
	}
	if b, err := json.Marshal(cred); err == nil {
		w.st.UpdatePasskey(r.Context(), used.ID, b, w.now())
	}
	if err := w.startSession(rw, r); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// PasskeyRow is one passkey as Settings lists it.
type PasskeyRow struct {
	ID            int64
	Name          string
	Created, Used int64
	CreatedText   string
	UsedText      string
}

func passkeyRows(keys []store.Passkey) []PasskeyRow {
	rows := make([]PasskeyRow, len(keys))
	for i, p := range keys {
		rows[i] = PasskeyRow{ID: p.ID, Name: p.Name, Created: p.CreatedAt.Unix(), CreatedText: timeText(p.CreatedAt)}
		if !p.LastUsedAt.IsZero() {
			rows[i].Used, rows[i].UsedText = p.LastUsedAt.Unix(), timeText(p.LastUsedAt)
		}
	}
	return rows
}
