package web

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/store"
)

const (
	cookieName = "fw_session"
	sessionTTL = 7 * 24 * time.Hour
)

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
		case r.Header.Get("HX-Request") != "":
			rw.Header().Set("HX-Redirect", "/login")
		default:
			http.Redirect(rw, r, "/login", http.StatusSeeOther)
		}
	}
}
