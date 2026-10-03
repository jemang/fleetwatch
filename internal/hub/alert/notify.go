package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Message is one notification. Event is "firing", "resolved" or "test".
// Zone is the time zone of the times in Text; nil is the Hub's local zone.
type Message struct {
	Event, Host, Kind, Subject, Detail string
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
		if m.Kind == KindOffline {
			title = "Agent connected"
		}
	}
	lines := []string{"[FleetWatch] " + state, "Host: " + m.Host, "Alert: " + title, "Since: " + m.stamp(m.Since)}
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
