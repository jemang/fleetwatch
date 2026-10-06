package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"fleetwatch/internal/hub/alert"
	"fleetwatch/internal/hub/push"
	"fleetwatch/internal/hub/store"
)

func (w *Web) pushRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /sw.js", w.serviceWorker)
	mux.HandleFunc("POST /push/subscribe", w.requireSession(w.pushSubscribe))
	mux.HandleFunc("POST /push/unsubscribe", w.requireSession(w.pushUnsubscribe))
	mux.HandleFunc("POST /push/state", w.requireSession(w.pushState))
	mux.HandleFunc("POST /push/test", w.requireSession(w.pushTest))
	mux.HandleFunc("POST /push/{id}/delete", w.requireSession(w.pushDelete))
}

// serviceWorker is served from the root so its scope is the whole Hub. It is
// static and holds no data, so it needs no login.
func (w *Web) serviceWorker(rw http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(staticFS, "static/sw.js")
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Write(b)
}

// pushKeys is the Hub's VAPID key pair, made the first time it is needed.
func (w *Web) pushKeys(ctx context.Context) (*push.Keys, error) {
	s, err := w.st.PushKey(ctx, push.NewKey)
	if err != nil {
		return nil, err
	}
	return push.ParseKey(s)
}

type pushSubBody struct {
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
	Label string `json:"label"`
}

func readPushBody(rw http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(rw, r.Body, 4<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}

func (w *Web) pushSubscribe(rw http.ResponseWriter, r *http.Request) {
	var b pushSubBody
	if !readPushBody(rw, r, &b) {
		return
	}
	u, err := url.Parse(b.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || len(b.Endpoint) > 1024 || !push.ValidSubscription(b.Keys.P256dh, b.Keys.Auth) {
		http.Error(rw, "This browser sent a subscription FleetWatch cannot use.", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(b.Label)
	for utf8.RuneCountInString(label) > 64 {
		label = string([]rune(label)[:64])
	}
	if label == "" {
		label = "Browser"
	}
	if err := w.st.SavePushSubscription(r.Context(), store.PushSubscription{Endpoint: b.Endpoint, P256dh: b.Keys.P256dh, Auth: b.Keys.Auth, Label: label}, w.now()); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("push: notifications on for %s", label)
	rw.WriteHeader(http.StatusNoContent)
}

func (w *Web) pushUnsubscribe(rw http.ResponseWriter, r *http.Request) {
	var b pushSubBody
	if !readPushBody(rw, r, &b) {
		return
	}
	if err := w.st.DeletePushSubscriptionByEndpoint(r.Context(), b.Endpoint); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("push: notifications off for a device")
	rw.WriteHeader(http.StatusNoContent)
}

// pushState tells the page whether its browser is still stored: a device
// removed on another device must show as off.
func (w *Web) pushState(rw http.ResponseWriter, r *http.Request) {
	var b pushSubBody
	if !readPushBody(rw, r, &b) {
		return
	}
	_, err := w.st.PushSubscriptionByEndpoint(r.Context(), b.Endpoint)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]bool{"stored": err == nil})
}

// pushTest sends a test message to the browser that asks.
func (w *Web) pushTest(rw http.ResponseWriter, r *http.Request) {
	var b pushSubBody
	if !readPushBody(rw, r, &b) {
		return
	}
	sub, err := w.st.PushSubscriptionByEndpoint(r.Context(), b.Endpoint)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(rw, "This device is not stored. Turn notifications on again.", http.StatusNotFound)
		return
	}
	k, kerr := w.pushKeys(r.Context())
	if err != nil || kerr != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	now := w.now()
	res := testResult{Name: sub.Label}
	if err := alert.SendPush(ctx, w.st, k, push.Subject(w.publicURL), sub, alert.Message{Event: "test", Hub: w.promptHost, Since: now, At: now}, now, log.Printf); err != nil {
		res.Error = err.Error()
		log.Printf("test message to %s failed: %v", sub.Label, err)
	} else {
		log.Printf("test message to %s delivered", sub.Label)
	}
	w.render(rw, http.StatusOK, "testresult", []testResult{res})
}

func (w *Web) pushDelete(rw http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		err = w.st.DeletePushSubscription(r.Context(), id)
	}
	if errors.Is(err, store.ErrNotFound) || id == 0 {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("push: device %d removed", id)
	http.Redirect(rw, r, "/settings", http.StatusSeeOther)
}

// PushRow is one device as Settings lists it.
type PushRow struct {
	ID          int64
	Label       string
	Created, OK int64
	CreatedText string
	OKText      string
}

func pushRows(subs []store.PushSubscription) []PushRow {
	rows := make([]PushRow, len(subs))
	for i, s := range subs {
		rows[i] = PushRow{ID: s.ID, Label: s.Label, Created: s.CreatedAt.Unix(), CreatedText: timeText(s.CreatedAt)}
		if !s.LastOKAt.IsZero() {
			rows[i].OK, rows[i].OKText = s.LastOKAt.Unix(), timeText(s.LastOKAt)
		}
	}
	return rows
}
