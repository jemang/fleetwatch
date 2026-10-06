package web

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/hub/svcicon"
)

// uptimeSpan is the uptime a card shows.
const uptimeSpan = 30 * 24 * time.Hour

type servicesData struct {
	chrome
	Groups []ServiceGroup
}

func (w *Web) serviceGroups(r *http.Request) ([]ServiceGroup, error) {
	list, err := w.st.Services(r.Context())
	if err != nil {
		return nil, err
	}
	stats, err := w.st.CheckStatsAll(r.Context(), store.HourStart(w.now().Add(-uptimeSpan)))
	if err != nil {
		return nil, err
	}
	return BuildServiceGroups(list, stats), nil
}

func (w *Web) servicesPage(rw http.ResponseWriter, r *http.Request) {
	groups, err := w.serviceGroups(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "services", servicesData{chrome: w.chrome(r, "services", rows), Groups: groups})
}

// serviceList is the card list alone; the open page redraws it on changes.
func (w *Web) serviceList(rw http.ResponseWriter, r *http.Request) {
	groups, err := w.serviceGroups(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "servicelist", servicesData{Groups: groups})
}

type intervalChoice struct {
	Seconds int
	Label   string
}

var intervals = []intervalChoice{{30, "30 s"}, {60, "60 s"}, {120, "2 min"}, {300, "5 min"}, {600, "10 min"}}

// durationLabel names an interval as the choices do: "45 s", "15 min".
func durationLabel(secs int) string {
	if secs%60 == 0 && secs >= 120 {
		return strconv.Itoa(secs/60) + " min"
	}
	return strconv.Itoa(secs) + " s"
}

type serviceForm struct {
	ID        int64 // 0 when adding
	S         store.Service
	Hosts     []store.Host
	Groups    []string
	Intervals []intervalChoice
	Error     string
}

func (w *Web) renderServiceForm(rw http.ResponseWriter, r *http.Request, status int, f serviceForm) {
	f.Hosts, _ = w.st.Hosts(r.Context())
	f.Groups, _ = w.st.ServiceGroups(r.Context())
	f.Intervals = intervals
	// An interval set outside the choices (a direct POST) stays selected, so
	// Save keeps it.
	if !slices.ContainsFunc(intervals, func(c intervalChoice) bool { return c.Seconds == f.S.IntervalS }) {
		f.Intervals = append(slices.Clone(intervals), intervalChoice{f.S.IntervalS, durationLabel(f.S.IntervalS)})
	}
	w.render(rw, status, "serviceform", f)
}

func (w *Web) serviceNew(rw http.ResponseWriter, r *http.Request) {
	w.renderServiceForm(rw, r, http.StatusOK, serviceForm{S: store.Service{IntervalS: 60, TimeoutS: 10, Enabled: true}})
}

func (w *Web) serviceFromPath(rw http.ResponseWriter, r *http.Request) (store.Service, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(rw, r)
		return store.Service{}, false
	}
	sv, err := w.st.Service(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return store.Service{}, false
	}
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return store.Service{}, false
	}
	return sv, true
}

func (w *Web) serviceEdit(rw http.ResponseWriter, r *http.Request) {
	sv, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	w.renderServiceForm(rw, r, http.StatusOK, serviceForm{ID: sv.ID, S: sv})
}

// urlHost is what log lines say about a URL: its host, never its path or
// query, which can hold a token.
func urlHost(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "?"
}

// parseService reads and checks the form; the message is "" when it is valid.
// The service always carries what was typed, so the dialog can show it again.
func parseService(r *http.Request, hostIDs map[int64]bool) (store.Service, string) {
	num := func(key string) (int, bool) {
		n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(key)))
		return n, err == nil
	}
	sv := store.Service{
		Name:             strings.TrimSpace(r.PostFormValue("name")),
		URL:              strings.TrimSpace(r.PostFormValue("url")),
		Group:            strings.TrimSpace(r.PostFormValue("group")),
		Description:      strings.TrimSpace(r.PostFormValue("description")),
		AcceptSelfSigned: r.PostFormValue("selfsigned") == "1",
		Enabled:          true,
	}
	interval, okI := num("interval")
	timeout, okT := num("timeout")
	sv.IntervalS, sv.TimeoutS = interval, timeout
	status := strings.TrimSpace(r.PostFormValue("status"))
	if status != "" {
		sv.ExpectedStatus, _ = strconv.Atoi(status)
	}
	host := strings.TrimSpace(r.PostFormValue("host"))
	if host != "" {
		sv.HostID, _ = strconv.ParseInt(host, 10, 64)
	}
	u, uerr := url.Parse(sv.URL)
	switch n := utf8.RuneCountInString(sv.Name); {
	case n == 0 || n > 64:
		return sv, "Give the service a name of 1 to 64 characters."
	case uerr != nil || len(sv.URL) > 2048 || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
		return sv, "Enter a full address that starts with http:// or https://, at most 2048 characters."
	case utf8.RuneCountInString(sv.Group) > 64:
		return sv, "Use a group name of at most 64 characters."
	case utf8.RuneCountInString(sv.Description) > 200:
		return sv, "Use a description of at most 200 characters."
	case !okI || interval < 10 || interval > 3600:
		return sv, "Check every 10 to 3600 seconds."
	case !okT || timeout < 1 || timeout > 60:
		return sv, "Use a timeout of 1 to 60 seconds."
	case timeout >= interval:
		return sv, "The timeout must be shorter than the check interval."
	}
	if status != "" {
		if n, err := strconv.Atoi(status); err != nil || n < 100 || n > 599 {
			return sv, "Leave the expected status empty, or use a number from 100 to 599."
		}
	}
	if host != "" && !hostIDs[sv.HostID] {
		return sv, "Choose a server from the list."
	}
	return sv, ""
}

func (w *Web) hostIDs(r *http.Request) map[int64]bool {
	hosts, _ := w.st.Hosts(r.Context())
	ids := make(map[int64]bool, len(hosts))
	for _, h := range hosts {
		ids[h.ID] = true
	}
	return ids
}

// saved closes the dialog: an empty body, and an event that redraws the list
// even when the live stream is down.
func (w *Web) saved(rw http.ResponseWriter) {
	w.bus.Publish(live.Event{Kind: live.ServicesChanged})
	rw.Header().Set("HX-Trigger", "services-saved")
	rw.WriteHeader(http.StatusOK)
}

func (w *Web) serviceCreate(rw http.ResponseWriter, r *http.Request) {
	sv, msg := parseService(r, w.hostIDs(r))
	if msg != "" {
		w.renderServiceForm(rw, r, http.StatusUnprocessableEntity, serviceForm{S: sv, Error: msg})
		return
	}
	id, err := w.st.CreateService(r.Context(), sv, w.now())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	sv.ID = id
	log.Printf("service %s (%s) added", sv.Name, urlHost(sv.URL))
	w.fetchIcon(sv)
	w.saved(rw)
}

func (w *Web) serviceUpdate(rw http.ResponseWriter, r *http.Request) {
	old, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	sv, msg := parseService(r, w.hostIDs(r))
	sv.ID, sv.Enabled = old.ID, old.Enabled
	if msg != "" {
		w.renderServiceForm(rw, r, http.StatusUnprocessableEntity, serviceForm{ID: old.ID, S: sv, Error: msg})
		return
	}
	if err := w.st.UpdateService(r.Context(), sv); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("service %s (%s) edited", sv.Name, urlHost(sv.URL))
	if sv.URL != old.URL || old.IconAt == 0 {
		w.fetchIcon(sv)
	}
	w.saved(rw)
}

// fetchIcon loads the icon in the background; the page never waits for it.
func (w *Web) fetchIcon(sv store.Service) {
	w.bg.Add(1)
	go func() {
		defer w.bg.Done()
		o := svcicon.Options{Timeout: time.Duration(sv.TimeoutS) * time.Second, AcceptSelfSigned: sv.AcceptSelfSigned}
		ctx, cancel := context.WithTimeout(context.Background(), 3*o.Timeout)
		defer cancel()
		data, typ, err := w.iconFetch(ctx, sv.URL, o)
		if err != nil {
			log.Printf("icon for %s not fetched: %s", sv.Name, svcicon.Reason(err))
			return
		}
		if err := w.st.SetServiceIcon(ctx, sv.ID, sv.URL, data, typ, w.now()); err != nil {
			return // removed meanwhile
		}
		w.bus.Publish(live.Event{Kind: live.ServicesChanged})
	}()
}

func (w *Web) serviceEnabled(rw http.ResponseWriter, r *http.Request) {
	sv, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	enabled := r.PostFormValue("enabled") == "1"
	if err := w.st.SetServiceEnabled(r.Context(), sv.ID, enabled); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	what := "paused"
	if enabled {
		what = "resumed"
	}
	log.Printf("service %s (%s) %s", sv.Name, urlHost(sv.URL), what)
	w.bus.Publish(live.Event{Kind: live.ServicesChanged})
	back := "/services"
	if r.PostFormValue("back") == "detail" {
		back = "/services/" + strconv.FormatInt(sv.ID, 10)
	}
	http.Redirect(rw, r, back, http.StatusSeeOther)
}

func (w *Web) serviceDelete(rw http.ResponseWriter, r *http.Request) {
	sv, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	if err := w.st.DeleteService(r.Context(), sv.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	log.Printf("service %s (%s) removed", sv.Name, urlHost(sv.URL))
	w.bus.Publish(live.Event{Kind: live.ServicesChanged})
	http.Redirect(rw, r, "/services", http.StatusSeeOther)
}

func (w *Web) serviceIconRefresh(rw http.ResponseWriter, r *http.Request) {
	sv, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	w.fetchIcon(sv)
	rw.WriteHeader(http.StatusNoContent)
}

// serviceIcon serves a stored icon. SVG can carry scripts: they never run in
// an <img>, and the sandbox stops them when the URL is opened directly.
func (w *Web) serviceIcon(rw http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	data, typ, err := w.st.ServiceIcon(r.Context(), id)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	h := rw.Header()
	h.Set("Content-Type", typ)
	h.Set("Cache-Control", "private, max-age=86400")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'")
	rw.Write(data)
}
