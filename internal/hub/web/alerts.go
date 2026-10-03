package web

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"fleetwatch/internal/hub/alert"
	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
)

// resolvedShown is how many ended alerts the Alerts page lists.
const resolvedShown = 100

type AlertRow struct {
	ID, HostID                 int64
	Host, Title, Detail, State string
	Since, Ended               int64
	SinceText, EndedText       string
}

var stateRank = map[string]int{"firing": 0, "pending": 1, "dismissed": 2, "resolved": 3}

// timeText is what a time shows before the page script prints it in the
// viewer's time zone.
func timeText(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" }

func BuildAlertRows(alerts []store.Alert) []AlertRow {
	rows := make([]AlertRow, len(alerts))
	for i, a := range alerts {
		title := alert.Title[a.Kind]
		if title == "" {
			title = a.Kind
		}
		rows[i] = AlertRow{ID: a.ID, HostID: a.HostID, Host: a.Host, Title: title, Detail: a.Detail, State: a.State(),
			Since: a.PendingSince.Unix(), SinceText: timeText(a.PendingSince)}
		if !a.ResolvedAt.IsZero() {
			rows[i].Ended, rows[i].EndedText = a.ResolvedAt.Unix(), timeText(a.ResolvedAt)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return stateRank[rows[i].State] < stateRank[rows[j].State] })
	return rows
}

type alertsData struct {
	chrome
	Alerts []AlertRow
}

func (w *Web) alertsPage(rw http.ResponseWriter, r *http.Request) {
	alerts, err := w.st.Alerts(r.Context(), resolvedShown)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	data := alertsData{Alerts: BuildAlertRows(alerts)}
	// The open page asks for the list alone whenever the menu changes.
	if r.Header.Get("HX-Request") != "" {
		w.render(rw, http.StatusOK, "alertlist", data)
		return
	}
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	data.chrome = w.chrome(r, "alerts", rows)
	w.render(rw, http.StatusOK, "alerts", data)
}

func (w *Web) dismissAlert(rw http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(rw, r)
		return
	}
	if err := w.st.DismissAlert(r.Context(), id, w.now()); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.bus.Publish(live.Event{Kind: live.AlertsChanged})
	http.Redirect(rw, r, "/alerts", http.StatusSeeOther)
}

// settingsForm is the settings as the form shows them. The Telegram token and
// the webhook URL are never part of it: a webhook URL often carries a secret in
// its path, so the page only says that one is stored, and its host.
type settingsForm struct {
	ChatID                                string
	OfflineAfter, CPUFor, RAMFor, DiskFor string
	TokenStored                           bool
	WebhookHost                           string // empty when no webhook is stored
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "set"
}

type settingsData struct {
	chrome
	Form       settingsForm
	Errors     []string
	Saved      bool
	PasskeysOn bool
	Passkeys   []PasskeyRow
	PublicURL  string
}

func formFromSettings(s map[string]string) settingsForm {
	or := func(key, def string) string {
		if v, ok := s[key]; ok {
			return v
		}
		return def
	}
	f := settingsForm{ChatID: s["telegram_chat_id"], TokenStored: s["telegram_token"] != "",
		OfflineAfter: or("offline_after_s", "60"), CPUFor: or("cpu_for_min", "5"), RAMFor: or("ram_for_min", "5"), DiskFor: or("disk_for_min", "2")}
	if s["webhook_url"] != "" {
		f.WebhookHost = hostOf(s["webhook_url"])
	}
	return f
}

func (w *Web) renderSettings(rw http.ResponseWriter, r *http.Request, status int, form settingsForm, errs []string, saved bool) {
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	keys, err := w.st.Passkeys(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, status, "settings", settingsData{chrome: w.chrome(r, "settings", rows), Form: form, Errors: errs, Saved: saved,
		PasskeysOn: w.passkeysOn(), Passkeys: passkeyRows(keys), PublicURL: w.publicURL})
}

func (w *Web) settingsPage(rw http.ResponseWriter, r *http.Request) {
	s, err := w.st.Settings(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.renderSettings(rw, r, http.StatusOK, formFromSettings(s), nil, r.URL.Query().Get("saved") != "")
}

var (
	// The token becomes part of the Telegram address, so its shape is checked.
	telegramToken = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
	telegramChat  = regexp.MustCompile(`^(-?[0-9]+|@[A-Za-z0-9_]+)$`)
)

func wholeNumber(value string, lo, hi int) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= lo && n <= hi
}

func (w *Web) settingsSave(rw http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(rw, r.Body, 16<<10)
	s, err := w.st.Settings(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	form := settingsForm{ChatID: r.PostFormValue("telegram_chat_id"),
		OfflineAfter: r.PostFormValue("offline_after_s"), CPUFor: r.PostFormValue("cpu_for_min"), RAMFor: r.PostFormValue("ram_for_min"),
		DiskFor: r.PostFormValue("disk_for_min"), TokenStored: s["telegram_token"] != ""}
	if s["webhook_url"] != "" {
		form.WebhookHost = hostOf(s["webhook_url"])
	}
	token := r.PostFormValue("telegram_token")
	webhook := strings.TrimSpace(r.PostFormValue("webhook_url"))

	var errs []string
	if webhook != "" {
		if u, err := url.Parse(webhook); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			errs = append(errs, "Webhook URL must start with http:// or https://.")
		}
	}
	if token != "" && !telegramToken.MatchString(token) {
		errs = append(errs, "The Telegram bot token does not look right. It has the form 123456:ABC-DEF.")
	}
	if form.ChatID != "" && !telegramChat.MatchString(form.ChatID) {
		errs = append(errs, "Telegram chat ID must be a number or a channel name that starts with @.")
	}
	// A host counts as offline 45 seconds after its last report.
	if !wholeNumber(form.OfflineAfter, int(OfflineAfter.Seconds()), 3600) {
		errs = append(errs, "Host offline: enter a whole number of seconds from 45 to 3600.")
	}
	for _, f := range []struct{ label, value string }{{"CPU high", form.CPUFor}, {"Memory high", form.RAMFor}, {"Disk full", form.DiskFor}} {
		if !wholeNumber(f.value, 0, 1440) {
			errs = append(errs, f.label+": enter a whole number of minutes from 0 to 1440.")
		}
	}
	if len(errs) > 0 {
		w.renderSettings(rw, r, http.StatusUnprocessableEntity, form, errs, false)
		return
	}

	values := map[string]string{"telegram_chat_id": form.ChatID, "offline_after_s": form.OfflineAfter,
		"cpu_for_min": form.CPUFor, "ram_for_min": form.RAMFor, "disk_for_min": form.DiskFor}
	// An empty secret field keeps what is stored; the clear box removes it.
	switch {
	case r.PostFormValue("clear_webhook_url") != "":
		values["webhook_url"] = ""
	case webhook != "":
		values["webhook_url"] = webhook
	}
	switch {
	case r.PostFormValue("clear_telegram_token") != "":
		values["telegram_token"] = ""
	case token != "":
		values["telegram_token"] = token
	}
	if err := w.st.SetSettings(r.Context(), values); err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, r, "/settings?saved=1", http.StatusSeeOther)
}

type testResult struct {
	Name, Error string
}

// settingsTest sends a test message to every stored target and reports each
// result.
func (w *Web) settingsTest(rw http.ResponseWriter, r *http.Request) {
	s, err := w.st.Settings(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	now := w.now()
	var results []testResult
	for _, t := range alert.Targets(s, w.telegramBase) {
		res := testResult{Name: t.Name}
		if err := t.Send(ctx, alert.Message{Event: "test", Hub: w.promptHost, Since: now, At: now}); err != nil {
			res.Error = err.Error()
		}
		results = append(results, res)
	}
	w.render(rw, http.StatusOK, "testresult", results)
}
