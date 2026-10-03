package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Message is one notification. Event is "firing", "resolved" or "test".
type Message struct {
	Event, Host, Kind, Subject, Detail string
	Since, At                          time.Time
	Hub                                string
}

func (m Message) Text() string {
	title := Title[m.Kind]
	if title == "" {
		title = m.Kind
	}
	if m.Event == "test" {
		return "[FleetWatch] Test message from " + m.Hub + ". Notifications work."
	}
	word := "ALERT"
	if m.Event == "resolved" {
		word = "RESOLVED"
		if m.Kind == KindOffline {
			title = "Agent connected"
		}
	}
	if m.Detail == "" {
		return fmt.Sprintf("[FleetWatch] %s %s: %s", word, m.Host, title)
	}
	return fmt.Sprintf("[FleetWatch] %s %s: %s (%s)", word, m.Host, title, m.Detail)
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
