package web

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLogsPage(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	h.logs.Write([]byte("fleetwatch-hub listening on :8080\n"))
	h.clock = h.clock.Add(time.Second)
	h.logs.Write([]byte("POST /x 500 3ms <b>\n"))
	h.logs.Write([]byte("report from web-01: agent 0.1.0, cpu 3%, ram 41%, disk 62%\n"))

	w := h.do("GET", "/logs", c, nil, false)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, want := range []string{`<body data-page="logs"`, `sse-connect="/events?log=1"`,
		`<div id="console" class="console" data-keep="100" sse-swap="log" hx-swap="beforeend">`,
		`<div class="line" data-seq="2"><time data-time="` + fmt.Sprint(h.clock.Unix()-1) + `"`,
		`<div class="line problem" data-seq="3"><time data-time="` + fmt.Sprint(h.clock.Unix()) + `"`,
		`<span>POST /x 500 3ms &lt;b&gt;</span>`, `Keeps the last 100`, `docker logs`,
		`<div class="line report" data-seq="4">`,
		`id="logfilter"`, `id="problems"`, `id="showreports"`, `id="follow"`, `action="/logs.txt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	// Lines written after the page loaded, for a stream that reconnected.
	w = h.do("GET", "/logs?after=2", c, nil, true)
	body = w.Body.String()
	if strings.Contains(body, "<html") || strings.Contains(body, `data-seq="2"`) || !strings.Contains(body, `data-seq="3"`) {
		t.Errorf("after=2 must return the later lines only:\n%s", body)
	}
}

func TestLogsText(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	h.logs.Write([]byte("one\ntwo\n"))
	w := h.do("GET", "/logs.txt", c, nil, false)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") ||
		w.Header().Get("Content-Disposition") != `attachment; filename="fleetwatch-hub.log"` {
		t.Fatalf("status %d, headers %v", w.Code, w.Header())
	}
	if got := w.Body.String(); !strings.HasSuffix(got, " one\n2026-10-03 06:00:00 two\n") && !strings.Contains(got, " one\n") {
		t.Errorf("body = %q", got)
	}
}

func TestLogsStream(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	srv := httptest.NewServer(h.mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events?log=1", nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	if !sc.Scan() || sc.Text() != ": connected" {
		t.Fatalf("first line = %q", sc.Text())
	}
	h.logs.Write([]byte("agent on web-01 upgraded to 0.1.2\n"))
	var event, data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = line[7:]
		case strings.HasPrefix(line, "data: "):
			data += line[6:]
		case line == "" && event != "":
			if event != "log" || !strings.Contains(data, `<div class="line" data-seq="`) || !strings.Contains(data, "<span>agent on web-01 upgraded to 0.1.2</span>") {
				t.Errorf("event %q data %q", event, data)
			}
			return
		}
	}
	t.Fatalf("stream ended: %v", sc.Err())
}

// A page without log=1 never receives log lines.
func TestEventsWithoutLogFlagSkipLogLines(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	srv := httptest.NewServer(h.mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events", nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Scan()
	h.logs.Write([]byte("quiet\n"))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: log") {
			t.Fatal("a dashboard stream received a log line")
		}
	}
}

func TestHandlersWriteLogLines(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addHost("web-01")
	if w := h.do("POST", "/login", nil, url.Values{"password": {"nope"}}, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", w.Code)
	}
	c := h.login()
	h.do("POST", "/servers/enroll-token", c, url.Values{}, true)
	h.do("POST", fmt.Sprintf("/hosts/%d/agent", id), c, url.Values{"disabled": {"1"}}, false)
	h.do("POST", fmt.Sprintf("/hosts/%d/credential", id), c, url.Values{}, true)
	h.do("POST", "/settings", c, url.Values{"webhook_url": {"https://hooks.example.com/x"}, "offline_after_s": {"120"}, "cpu_for_min": {"10"}, "ram_for_min": {"0"}, "disk_for_min": {"3"}}, false)
	h.do("POST", fmt.Sprintf("/hosts/%d/delete", id), c, url.Values{}, false)
	h.do("POST", "/logout", c, nil, false)

	var got []string
	for _, ln := range h.logs.Lines() {
		got = append(got, ln.Text)
	}
	text := strings.Join(got, "\n")
	for _, want := range []string{
		"login failed from 192.0.2.1 (wrong password)",
		"login from 192.0.2.1",
		"enrollment token created, valid 15 minutes",
		"agent on web-01 disabled",
		"credential replacement token created for web-01",
		"settings saved",
		"server web-01 removed",
		"logout from 192.0.2.1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	if strings.Contains(text, "hooks.example.com") || strings.Contains(text, "nope") {
		t.Errorf("a secret or a password reached the log:\n%s", text)
	}
	for _, ln := range h.logs.Lines() {
		if ln.Problem != strings.HasPrefix(ln.Text, "login failed") {
			t.Errorf("problem flag wrong on %+v", ln)
		}
	}
}
