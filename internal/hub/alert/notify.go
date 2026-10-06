package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fleetwatch/internal/hub/push"
	"fleetwatch/internal/hub/store"
)

// Message is one notification. Event is "firing", "resolved" or "test".
// Zone is the time zone of the times in Text; nil is the Hub's local zone.
// Service and ServiceHost (the URL's domain only) are set for a service
// alert; Host is then the service's related host, or "".
type Message struct {
	Event, Host, Kind, Subject, Detail string
	Service, ServiceHost               string
	ServiceID                          int64
	AlertID                            int64    // the alert's page and the push tag; 0 for a test
	HostServices                       []string // host offline: the host's services, by name
	Since, At                          time.Time
	Hub                                string
	Zone                               *time.Location
}

// Text is the message as people read it: the same fields as a row of the
// Alerts page, one per line. Times are in the Hub's time zone (TZ).
func (m Message) Text() string {
	if m.Event == "test" {
		return "[FleetWatch] Test message from " + m.Hub + ". Notifications work."
	}
	title := Title[m.Kind]
	if title == "" {
		title = m.Kind
	}
	if m.Detail != "" {
		title += " (" + m.Detail + ")"
	}
	state := "Firing"
	if m.Event == "resolved" {
		state = "Resolved"
		if rt := ResolvedTitle[m.Kind]; rt != "" {
			title = rt
		}
	}
	lines := []string{"[FleetWatch] " + state}
	if m.Service != "" {
		lines = append(lines, "Service: "+m.Service+" ("+m.ServiceHost+")")
	}
	if m.Service == "" || m.Host != "" {
		lines = append(lines, "Host: "+m.Host)
	}
	if len(m.HostServices) > 0 {
		lines = append(lines, "Services on this host: "+strings.Join(m.HostServices, ", "))
	}
	lines = append(lines, "Alert: "+title, "Since: "+m.stamp(m.Since))
	if m.Event == "resolved" {
		lines = append(lines, "Ended: "+m.stamp(m.At)+" (after "+Lasted(m.At.Sub(m.Since))+")")
	}
	return strings.Join(append(lines, "Hub: "+m.Hub), "\n")
}

func (m Message) stamp(t time.Time) string {
	zone := m.Zone
	if zone == nil {
		zone = time.Local
	}
	return t.In(zone).Format("2006-01-02 15:04 MST")
}

// Lasted prints a duration in whole minutes, with days and hours when it has them.
func Lasted(d time.Duration) string {
	d = d.Round(time.Minute)
	days, hours, mins := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

// Target is one place messages go.
type Target struct {
	Name string
	Send func(ctx context.Context, m Message) error
}

const telegramAPI = "https://api.telegram.org"

var httpClient = &http.Client{
	Timeout:       8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func postJSON(ctx context.Context, url string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// Targets builds the configured targets. telegramBase replaces the Telegram
// API address in tests; "" means the real one.
func Targets(settings map[string]string, telegramBase string) []Target {
	var out []Target
	if url := settings["webhook_url"]; url != "" {
		out = append(out, Target{"Webhook", func(ctx context.Context, m Message) error {
			return postJSON(ctx, url, map[string]any{
				"event": m.Event, "host": m.Host, "kind": m.Kind, "subject": m.Subject, "detail": m.Detail,
				"since": m.Since.Unix(), "at": m.At.Unix(), "hub": m.Hub, "text": m.Text(),
				"service": m.Service, "service_id": m.ServiceID, "service_host": m.ServiceHost, "host_services": append([]string{}, m.HostServices...),
			})
		}})
	}
	if token, chat := settings["telegram_token"], settings["telegram_chat_id"]; token != "" && chat != "" {
		if telegramBase == "" {
			telegramBase = telegramAPI
		}
		out = append(out, Target{"Telegram", func(ctx context.Context, m Message) error {
			return postJSON(ctx, telegramBase+"/bot"+token+"/sendMessage", map[string]any{"chat_id": chat, "text": m.Text()})
		}})
	}
	return out
}

// ErrGone is a device the push service no longer knows: it was removed.
var ErrGone = errors.New("the device is gone")

// pushPayload is what the service worker shows for m. It fits one
// 4,096-byte record: the body is cut when needed.
func pushPayload(m Message) []byte {
	p := map[string]string{"title": "FleetWatch test", "body": "Notifications work on this device.", "url": "/settings", "tag": "test"}
	if m.Event != "test" {
		name := m.Service
		if name == "" {
			name = m.Host
		}
		title := Title[m.Kind]
		if title == "" {
			title = m.Kind
		}
		body := m.Detail
		if len(m.HostServices) > 0 {
			body = strings.TrimSpace(body + "\nServices on this host: " + strings.Join(m.HostServices, ", "))
		}
		if m.Event == "resolved" {
			if rt := ResolvedTitle[m.Kind]; rt != "" {
				title = rt
			}
			body = "After " + Lasted(m.At.Sub(m.Since))
		}
		p["title"], p["body"] = cut(title+" · "+name, 200), cut(body, 2000)
		p["url"], p["tag"] = fmt.Sprintf("/alerts/%d", m.AlertID), fmt.Sprintf("alert-%d", m.AlertID)
	}
	return fitRecord(p)
}

// fitRecord encodes p without HTML escaping. JSON still escapes control
// characters (up to six bytes each), so the body is cut again until the
// payload fits one record.
func fitRecord(p map[string]string) []byte {
	for {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.Encode(p)
		b := bytes.TrimRight(buf.Bytes(), "\n")
		if len(b)+17 <= 4096 || p["body"] == "" {
			return b
		}
		if len(p["body"]) <= 8 {
			p["body"] = ""
		} else {
			p["body"] = cut(p["body"], len(p["body"])/2)
		}
	}
}

// cut shortens s to at most n bytes on a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// SendPush sends m to one device. A device its push service no longer knows
// is removed and ErrGone returned.
func SendPush(ctx context.Context, st *store.Store, k *push.Keys, subject string, s store.PushSubscription, m Message, now time.Time, logf func(string, ...any)) error {
	urgency := "normal"
	if m.Event == "firing" {
		urgency = "high"
	}
	status, err := push.Send(ctx, httpClient, k, subject, push.Subscription{Endpoint: s.Endpoint, P256dh: s.P256dh, Auth: s.Auth}, pushPayload(m), urgency, now)
	switch {
	case status == http.StatusNotFound || status == http.StatusGone:
		if err := st.DeletePushSubscription(ctx, s.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if logf != nil {
			logf("push: removed a device that is gone (%s)", s.Label)
		}
		return ErrGone
	case err != nil:
		return err
	}
	return st.MarkPushOK(ctx, s.ID, now)
}

// PushTarget sends to every device with notifications on; it is nil without
// a device. It fails only when no device took the message and one failed for
// a reason other than being gone: one dead phone must not make the message
// owed again, and so repeated, on every target.
func PushTarget(ctx context.Context, st *store.Store, settings map[string]string, subject string, now time.Time, logf func(string, ...any)) (*Target, error) {
	if settings["push_vapid_key"] == "" {
		return nil, nil
	}
	subs, err := st.PushSubscriptions(ctx)
	if err != nil || len(subs) == 0 {
		return nil, err
	}
	k, err := push.ParseKey(settings["push_vapid_key"])
	if err != nil {
		return nil, err
	}
	return &Target{"Push", func(ctx context.Context, m Message) error {
		// All devices at once: slow push services must not add up and stall
		// the alert tick.
		results := make([]error, len(subs))
		var wg sync.WaitGroup
		var logMu sync.Mutex
		safeLog := func(format string, args ...any) {
			if logf != nil {
				logMu.Lock()
				defer logMu.Unlock()
				logf(format, args...)
			}
		}
		for i, s := range subs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = SendPush(ctx, st, k, subject, s, m, now, safeLog)
			}()
		}
		wg.Wait()
		delivered := 0
		var errs []error
		for i, err := range results {
			switch {
			case err == nil:
				delivered++
			case !errors.Is(err, ErrGone):
				errs = append(errs, fmt.Errorf("%s: %w", subs[i].Label, err))
			}
		}
		if delivered > 0 {
			return nil
		}
		return errors.Join(errs...)
	}}, nil
}
