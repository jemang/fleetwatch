package web

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/version"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const enrollTTL = 15 * time.Minute

type Web struct {
	st         *store.Store
	bus        *live.Bus
	now        func() time.Time
	publicURL  string
	promptHost string
	secure     bool
	loginLimit *limit.Limiter
	tmpl       *template.Template
	// telegramBase replaces the Telegram API address in tests.
	telegramBase string

	// wa is nil when browsers would refuse passkeys for the public URL.
	wa         *webauthn.WebAuthn
	cerMu      sync.Mutex
	ceremonies map[string]ceremony

	sparkMu sync.Mutex
	sparkAt time.Time
	spark   sparkSet
}

// sparkTTL bounds how often the tile trend lines are recomputed.
const sparkTTL = 15 * time.Second

type sparkSet struct{ CPU, RAM, Disk string }

// tilesData is what the tiles and the footer status line render.
type tilesData struct {
	Summary
	Sparks sparkSet
}

func (w *Web) version() string { return version.Version }

func (w *Web) tiles(r *http.Request, rows []HostRow) tilesData {
	return tilesData{Summary: Summarize(rows), Sparks: w.sparks(r)}
}

// sparks returns the fleet averages of the last hour as trend lines.
func (w *Web) sparks(r *http.Request) sparkSet {
	now := w.now()
	w.sparkMu.Lock()
	defer w.sparkMu.Unlock()
	if age := now.Sub(w.sparkAt); !w.sparkAt.IsZero() && age >= 0 && age < sparkTTL {
		return w.spark
	}
	pts, err := w.st.FleetHistory(r.Context(), now.Add(-time.Hour), now, time.Minute)
	if err != nil {
		return w.spark
	}
	w.sparkAt = now
	w.spark = sparkSet{
		CPU:  SparkPath(pts, func(p store.MetricPoint) *float64 { return p.CPU }),
		RAM:  SparkPath(pts, func(p store.MetricPoint) *float64 { return p.Mem }),
		Disk: SparkPath(pts, func(p store.MetricPoint) *float64 { return p.Disk }),
	}
	return w.spark
}

func New(st *store.Store, bus *live.Bus, now func() time.Time, publicURL string, secure bool) (*Web, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Web{st: st, bus: bus, now: now, publicURL: strings.TrimRight(publicURL, "/"), promptHost: HubName(publicURL), secure: secure,
		loginLimit: limit.New(5, time.Minute, now), tmpl: tmpl, wa: passkeyRelyingParty(publicURL), ceremonies: map[string]ceremony{}}, nil
}

// HubName is how this Hub names itself in the prompt line and in messages.
func HubName(publicURL string) string {
	if u, err := url.Parse(publicURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "hub"
}

func (w *Web) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", w.loginPage)
	mux.HandleFunc("POST /login", w.loginSubmit)
	mux.HandleFunc("POST /logout", w.requireSession(w.logout))
	mux.HandleFunc("GET /{$}", w.requireSession(w.hostsPage))
	mux.HandleFunc("GET /hosts/{id}", w.requireSession(w.hostPage))
	mux.HandleFunc("GET /hosts/{id}/charts", w.requireSession(w.hostCharts))
	mux.HandleFunc("POST /hosts/{id}/credential", w.requireSession(w.replaceCredential))
	mux.HandleFunc("POST /hosts/{id}/agent", w.requireSession(w.setAgentDisabled))
	mux.HandleFunc("POST /hosts/{id}/delete", w.requireSession(w.deleteHost))
	mux.HandleFunc("POST /servers/enroll-token", w.requireSession(w.enrollToken))
	mux.HandleFunc("GET /alerts", w.requireSession(w.alertsPage))
	mux.HandleFunc("POST /alerts/{id}/dismiss", w.requireSession(w.dismissAlert))
	mux.HandleFunc("GET /settings", w.requireSession(w.settingsPage))
	mux.HandleFunc("POST /settings", w.requireSession(w.settingsSave))
	mux.HandleFunc("POST /settings/test", w.requireSession(w.settingsTest))
	mux.HandleFunc("GET /events", w.requireSession(w.events))
	w.passkeyRoutes(mux)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
}

func (w *Web) renderString(name string, data any) (string, error) {
	var buf bytes.Buffer
	err := w.tmpl.ExecuteTemplate(&buf, name, data)
	return buf.String(), err
}

func (w *Web) render(rw http.ResponseWriter, status int, name string, data any) {
	body, err := w.renderString(name, data)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(status)
	io.WriteString(rw, body)
}

func (w *Web) rows(r *http.Request) ([]HostRow, error) {
	hosts, err := w.st.Hosts(r.Context())
	if err != nil {
		return nil, err
	}
	now := w.now()
	rows := make([]HostRow, len(hosts))
	for i, h := range hosts {
		rows[i] = BuildRow(h, now)
	}
	return rows, nil
}

type sortHead struct {
	Label, Type string
	Active      bool
}

// Column order matches the cells template. The server sends rows by host name.
var sortHeads = []sortHead{
	{"Host", "text", true}, {"IP", "num", false}, {"CPU", "num", false}, {"RAM", "num", false},
	{"Disk", "num", false}, {"Guests", "num", false}, {"Uptime", "num", false}, {"Status", "num", false}, {"Last report", "num", false},
}

type navData struct{ Hosts, Firing int }

// chrome is what every signed-in page needs around its content: the menu,
// the footer and the Hub clock.
type chrome struct {
	Page       string
	Nav        navData
	Summary    tilesData
	NowUnix    int64
	Version    string
	PromptHost string
}

func (w *Web) nav(r *http.Request, hosts int) navData {
	firing, _ := w.st.FiringCount(r.Context())
	return navData{Hosts: hosts, Firing: firing}
}

func (w *Web) chrome(r *http.Request, page string, rows []HostRow) chrome {
	return chrome{Page: page, Nav: w.nav(r, len(rows)), Summary: w.tiles(r, rows), NowUnix: w.now().Unix(),
		Version: w.version(), PromptHost: w.promptHost}
}

type pageData struct {
	chrome
	Heads []sortHead
	Rows  []HostRow
}

func (w *Web) hostsPage(rw http.ResponseWriter, r *http.Request) {
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "hosts", pageData{chrome: w.chrome(r, "hosts", rows), Heads: sortHeads, Rows: rows})
}

type enrollData struct {
	Command  string   // the line to copy
	Manual   []string // the same install, with the script saved and read first
	Install  string   // credential dialog: the install line for a server set up again
	Host     string
	Minutes  int
	Insecure bool // the Hub is reached over plain HTTP
}

func (w *Web) insecure() bool { return strings.HasPrefix(w.publicURL, "http://") }

func (w *Web) installLine(token string) string {
	return "curl -fsSL " + w.publicURL + "/install/" + token + " | sudo bash"
}

func (w *Web) enrollToken(rw http.ResponseWriter, r *http.Request) {
	token, err := store.NewToken()
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	now := w.now()
	if err := w.st.CreateEnrollmentToken(r.Context(), store.HashToken(token), now, now.Add(enrollTTL)); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "enroll", enrollData{Command: w.installLine(token), Minutes: int(enrollTTL.Minutes()), Insecure: w.insecure(),
		Manual: []string{"curl -fsSL " + w.publicURL + "/install/" + token + " -o fleetwatch-install.sh", "less fleetwatch-install.sh", "sudo bash fleetwatch-install.sh"}})
}

// replaceCredential makes a token bound to the host. An agent that enrolls
// with it gets a new credential; the old one stops working at that moment.
func (w *Web) replaceCredential(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.hostFromPath(rw, r)
	if !ok {
		return
	}
	token, err := store.NewToken()
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	now := w.now()
	if err := w.st.CreateHostEnrollmentToken(r.Context(), store.HashToken(token), h.ID, now, now.Add(enrollTTL)); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	cmd := "sudo fleetwatch-agent enroll --hub " + w.publicURL + " --token " + token
	if w.insecure() {
		cmd += " --allow-insecure-http"
	}
	w.render(rw, http.StatusOK, "credential", enrollData{Command: cmd, Install: w.installLine(token), Host: h.Name,
		Minutes: int(enrollTTL.Minutes()), Insecure: w.insecure()})
}

func (w *Web) setAgentDisabled(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.hostFromPath(rw, r)
	if !ok {
		return
	}
	if err := w.st.SetAgentDisabled(r.Context(), h.ID, r.PostFormValue("disabled") == "1"); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: h.ID})
	http.Redirect(rw, r, "/hosts/"+strconv.FormatInt(h.ID, 10), http.StatusSeeOther)
}

// deleteHost removes a server and everything stored about it.
func (w *Web) deleteHost(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.hostFromPath(rw, r)
	if !ok {
		return
	}
	if err := w.st.DeleteHost(r.Context(), h.ID); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.bus.Publish(live.Event{Kind: live.HostRemoved, HostID: h.ID})
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

// writeSSE writes one event. Every line of data needs its own "data:" prefix.
func writeSSE(w io.Writer, event, data string) {
	fmt.Fprintf(w, "event: %s\n", event)
	for _, line := range strings.Split(strings.TrimRight(data, "\n"), "\n") {
		fmt.Fprintf(w, "data: %s\n", line)
	}
	fmt.Fprint(w, "\n")
}

func (w *Web) events(rw http.ResponseWriter, r *http.Request) {
	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// A detail page names the host it shows and gets that host's live block too.
	watch, _ := strconv.ParseInt(r.URL.Query().Get("host"), 10, 64)
	ch, cancel := w.bus.Subscribe()
	defer cancel()
	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("X-Accel-Buffering", "no")
	fmt.Fprint(rw, ": connected\n\n")
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(rw, ": keepalive\n\n")
		case ev := <-ch:
			w.writeHostEvent(rw, r, ev, watch)
		}
		flusher.Flush()
	}
}

// writeNav sends the menu. Its counts change only when a host is added or an
// alert changes.
func (w *Web) writeNav(rw io.Writer, r *http.Request) {
	hosts, err := w.st.Hosts(r.Context())
	if err != nil {
		return
	}
	if html, err := w.renderString("nav", w.nav(r, len(hosts))); err == nil {
		writeSSE(rw, "nav", html)
	}
}

// writeFleet sends the parts every page shows about the whole fleet.
func (w *Web) writeFleet(rw io.Writer, r *http.Request) {
	rows, err := w.rows(r)
	if err != nil {
		return
	}
	sum := w.tiles(r, rows)
	for _, name := range []string{"summary", "statusline"} {
		if html, err := w.renderString(name, sum); err == nil {
			writeSSE(rw, name, html)
		}
	}
	if html, err := w.renderString("nav", w.nav(r, len(rows))); err == nil {
		writeSSE(rw, "nav", html)
	}
}

func (w *Web) writeHostEvent(rw io.Writer, r *http.Request, ev live.Event, watch int64) {
	switch ev.Kind {
	case live.AlertsChanged:
		w.writeNav(rw, r)
		return
	case live.HostRemoved:
		// The page script drops the row; the counts follow.
		writeSSE(rw, "host-removed", strconv.FormatInt(ev.HostID, 10))
		w.writeFleet(rw, r)
		return
	}
	host, err := w.st.Host(r.Context(), ev.HostID)
	if err != nil {
		return
	}
	row := BuildRow(host, w.now())
	name, tmpl := fmt.Sprintf("host-%d", row.ID), "cells"
	if ev.Kind == live.HostAdded {
		name, tmpl = "host-new", "row"
	}
	if html, err := w.renderString(tmpl, row); err == nil {
		writeSSE(rw, name, html)
	}
	if rows, err := w.rows(r); err == nil {
		sum := w.tiles(r, rows)
		for _, name := range []string{"summary", "statusline"} {
			if html, err := w.renderString(name, sum); err == nil {
				writeSSE(rw, name, html)
			}
		}
		if ev.Kind == live.HostAdded {
			if html, err := w.renderString("nav", w.nav(r, len(rows))); err == nil {
				writeSSE(rw, "nav", html)
			}
		}
	}
	if ev.HostID == watch {
		if html, err := w.renderString("now", BuildDetail(host, w.now())); err == nil {
			writeSSE(rw, "detail", html)
		}
	}
}
