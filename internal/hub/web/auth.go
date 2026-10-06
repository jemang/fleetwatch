package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/store"
)

const (
	cookieName = "fw_session"
	sessionTTL = 7 * 24 * time.Hour
	// bcrypt reads only the first 72 bytes, so a longer password would be
	// cut without notice.
	minPassword = 12
	maxPassword = 72
)

// passwordProblem says what is wrong with a new admin password, or "".
func passwordProblem(p string) string {
	switch {
	case utf8.RuneCountInString(p) < minPassword:
		return fmt.Sprintf("The password must have at least %d characters.", minPassword)
	case len(p) > maxPassword:
		return fmt.Sprintf("The password can have at most %d bytes.", maxPassword)
	}
	return ""
}

// EnsureAdmin creates the admin account on first start. Once an admin exists
// the password argument is ignored.
func EnsureAdmin(ctx context.Context, st *store.Store, password string) error {
	exists, err := st.AdminExists(ctx)
	if err != nil || exists {
		return err
	}
	if password == "" {
		return errors.New("no admin account exists yet: set FLEETWATCH_ADMIN_PASSWORD for the first start")
	}
	if p := passwordProblem(password); p != "" {
		return fmt.Errorf("FLEETWATCH_ADMIN_PASSWORD: %s", p)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("FLEETWATCH_ADMIN_PASSWORD: %w", err)
	}
	return st.CreateAdmin(ctx, string(hash))
}

type loginData struct {
	Error   string
	Passkey bool // offer the passkey button: passkeys are on and one is registered
}

func (w *Web) loginView(r *http.Request, errText string) loginData {
	d := loginData{Error: errText}
	if w.passkeysOn() {
		keys, _ := w.st.Passkeys(r.Context())
		d.Passkey = len(keys) > 0
	}
	return d
}

func (w *Web) loginPage(rw http.ResponseWriter, r *http.Request) {
	w.render(rw, http.StatusOK, "login", w.loginView(r, ""))
}

// startSession issues the session cookie after a successful login of any kind.
func (w *Web) startSession(rw http.ResponseWriter, r *http.Request) error {
	token, err := store.NewToken()
	if err != nil {
		return err
	}
	now := w.now()
	if err := w.st.CreateSession(r.Context(), store.HashToken(token), now, now.Add(sessionTTL)); err != nil {
		return err
	}
	http.SetCookie(rw, &http.Cookie{
		Name: cookieName, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: w.secure,
	})
	return nil
}

func (w *Web) loginSubmit(rw http.ResponseWriter, r *http.Request) {
	ip := limit.RemoteIP(r)
	if !w.loginLimit.Allow(ip) {
		w.render(rw, http.StatusTooManyRequests, "login", w.loginView(r, "Too many failed attempts. Wait one minute."))
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4<<10)
	hash, err := w.st.AdminPasswordHash(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.PostFormValue("password"))) != nil {
		w.loginLimit.Fail(ip)
		log.Printf("login failed from %s (wrong password)", ip)
		w.render(rw, http.StatusUnauthorized, "login", w.loginView(r, "Wrong password."))
		return
	}
	if err := w.startSession(rw, r); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("login from %s", ip)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *Web) logout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		w.st.DeleteSession(r.Context(), store.HashToken(c.Value))
	}
	log.Printf("logout from %s", limit.RemoteIP(r))
	http.SetCookie(rw, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: w.secure})
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (w *Web) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieName); err == nil {
			if ok, _ := w.st.SessionValid(r.Context(), store.HashToken(c.Value), w.now()); ok {
				next(rw, r)
				return
			}
		}
		switch {
		case r.URL.Path == "/events":
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
		case strings.HasPrefix(r.URL.Path, "/push/") && r.Header.Get("Content-Type") == "application/json":
			// The page script shows this text; a followed redirect would hand it the login page.
			http.Error(rw, "Your login has expired. Log in again.", http.StatusUnauthorized)
		case r.Header.Get("HX-Request") != "":
			rw.Header().Set("HX-Redirect", "/login")
		default:
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
		}
	}
}

// changePassword replaces the admin password. The current one is checked
// under the login limit, and every other session ends, so a leaked password
// or a forgotten device loses access.
func (w *Web) changePassword(rw http.ResponseWriter, r *http.Request) {
	ip := limit.RemoteIP(r)
	if !w.loginLimit.Allow(ip) {
		w.passwordError(rw, r, http.StatusTooManyRequests, "Too many failed attempts. Wait one minute.")
		return
	}
	r.Body = http.MaxBytesReader(rw, r.Body, 4<<10)
	hash, err := w.st.AdminPasswordHash(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.PostFormValue("current"))) != nil {
		w.loginLimit.Fail(ip)
		log.Printf("password change refused from %s (wrong current password)", ip)
		w.passwordError(rw, r, http.StatusUnauthorized, "Current password is wrong.")
		return
	}
	next := r.PostFormValue("new")
	if p := passwordProblem(next); p != "" {
		w.passwordError(rw, r, http.StatusBadRequest, p)
		return
	}
	if next != r.PostFormValue("repeat") {
		w.passwordError(rw, r, http.StatusBadRequest, "The new passwords do not match.")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	c, cerr := r.Cookie(cookieName)
	if err != nil || cerr != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.st.SetAdminPassword(r.Context(), string(newHash), store.HashToken(c.Value)); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("admin password changed from %s; other sessions logged out", ip)
	http.Redirect(rw, r, "/settings?password=1", http.StatusSeeOther)
}

func (w *Web) passwordError(rw http.ResponseWriter, r *http.Request, status int, msg string) {
	s, err := w.st.Settings(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.renderSettings(rw, r, status, formFromSettings(s), []string{msg}, false)
}
