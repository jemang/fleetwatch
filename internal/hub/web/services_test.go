package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/hub/svcicon"
)

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (h *harness) addService(name, url, group string) int64 {
	h.t.Helper()
	id, err := h.st.CreateService(context.Background(), store.Service{Name: name, URL: url, Group: group, IntervalS: 60, TimeoutS: 10, Enabled: true}, h.clock)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

func TestServicesPageEmpty(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	body := h.do("GET", "/services", h.login(), nil, false).Body.String()
	for _, want := range []string{`data-page="services"`, `No services yet.`, `id="search"`, `+ Add Service`,
		`hx-get="/services/list"`, `hx-trigger="sse:services, services-saved from:body"`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty page is missing %q", want)
		}
	}
}

func TestServicesPageGroupsAndCards(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	h.addService("Zeta", "https://z.example.com/path?q=1", "")
	h.addService(`<img src=x onerror=alert(1)>`, "https://x.example.com", "Production")
	id := h.addService("Grafana", "https://grafana.lan", "Infrastructure")
	h.st.SetServiceEnabled(ctx, id, false)
	h.st.SetServiceIcon(ctx, id, "https://grafana.lan", []byte{1}, "image/png", h.clock)
	c := h.login()
	body := h.do("GET", "/services", c, nil, false).Body.String()
	if strings.Contains(body, "<img src=x") {
		t.Error("service name must be HTML-escaped")
	}
	last := -1
	for _, s := range []string{`<h2>Infrastructure</h2>`, `<h2>Production</h2>`, `<h2>Ungrouped</h2>`} {
		i := strings.Index(body, s)
		if i <= last {
			t.Fatalf("group headings out of order or missing: %q at %d", s, i)
		}
		last = i
	}
	for _, want := range []string{
		`<a class="open" href="https://grafana.lan" target="_blank" rel="noopener noreferrer">`,
		`<img src="/services/` + itoa(id) + `/icon?v=1790000000" alt="" width="28" height="28">`,
		`<div class="svc-card" id="svc-` + itoa(id) + `"`, `data-state="paused"`, `>paused<`,
		`<span class="letter" aria-hidden="true">Z</span>`, `not checked yet`,
		`data-search="zeta z.example.com"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	list := h.do("GET", "/services/list", c, nil, true).Body.String()
	if strings.Contains(list, "<html") || !strings.Contains(list, `<h2>Infrastructure</h2>`) {
		t.Error("/services/list must return the list alone")
	}
}

func TestServicesStreamEvent(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	srv := httptest.NewServer(h.mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	h.addService("a", "http://a", "")
	h.bus.Publish(live.Event{Kind: live.ServicesChanged})
	seen := map[string]bool{}
	for !(seen["services"] && seen["nav"]) && sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: ") {
			seen[sc.Text()[7:]] = true
		}
	}
	if !seen["services"] || !seen["nav"] {
		t.Errorf("events seen: %v, want services and nav", seen)
	}
}

func TestServicesNeedSession(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	for _, path := range []string{"/services", "/services/list"} {
		if w := h.do("GET", path, nil, nil, false); w.Code != http.StatusSeeOther {
			t.Errorf("%s without session: %d", path, w.Code)
		}
	}
}

func form(kv ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func validForm() url.Values {
	return form("name", "Grafana", "url", "https://grafana.lan/?token=s3cret", "group", "Infra", "host", "",
		"interval", "60", "timeout", "10", "status", "", "description", "")
}

func TestAddServiceForm(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	hostID := h.addHost("pve-2")
	h.addService("Old", "http://old", "Infra")
	body := h.do("GET", "/services/new", h.login(), nil, true).Body.String()
	for _, want := range []string{`<h2>Add Service</h2>`, `hx-post="/services"`, `hx-target="#service-body"`, `hx-swap="innerHTML"`,
		`name="name"`, `name="url"`, `list="groups"`, `<option value="Infra">`, `<option value="` + itoa(hostID) + `">pve-2</option>`,
		`<option value="60" selected>60 s</option>`, `<details class="advanced">`, `name="timeout" type="number" value="10"`,
		`name="selfsigned"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form is missing %q", want)
		}
	}
}

func TestCreateService(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	h.web.iconFetch = func(ctx context.Context, u string, o svcicon.Options) ([]byte, string, error) {
		if o.Timeout != 10*time.Second || o.AcceptSelfSigned {
			t.Errorf("icon options = %+v", o)
		}
		return []byte{1}, "image/png", nil
	}
	events, cancel := h.bus.Subscribe()
	defer cancel()
	w := h.do("POST", "/services", h.login(), validForm(), true)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("HX-Trigger") != "services-saved" {
		t.Fatalf("create: %d %q %q", w.Code, w.Header().Get("HX-Trigger"), w.Body.String())
	}
	h.web.bg.Wait()
	list, _ := h.st.Services(context.Background())
	if len(list) != 1 || list[0].Name != "Grafana" || list[0].Group != "Infra" || list[0].IntervalS != 60 || !list[0].Enabled || list[0].IconAt == 0 {
		t.Fatalf("stored: %+v", list)
	}
	if ev := <-events; ev.Kind != live.ServicesChanged {
		t.Errorf("event = %+v", ev)
	}
	logs := h.logs.Text()
	if !strings.Contains(logs, "service Grafana (grafana.lan) added") || strings.Contains(logs, "s3cret") {
		t.Errorf("log = %q", logs)
	}
}

// A failed icon fetch logs the reason without the URL, which may hold a token.
func TestIconFailureIsLoggedWithoutURL(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	f := validForm()
	f.Set("url", "http://127.0.0.1:1/?token=s3cret")
	h.do("POST", "/services", h.login(), f, true)
	h.web.bg.Wait()
	logs := h.logs.Text()
	if !strings.Contains(logs, "icon for Grafana not fetched:") || strings.Contains(logs, "s3cret") {
		t.Errorf("log = %q", logs)
	}
}

func TestServiceValidation(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	h.web.iconFetch = func(context.Context, string, svcicon.Options) ([]byte, string, error) {
		return nil, "", context.Canceled
	}
	c := h.login()
	cases := map[string][2]string{
		"empty name":         {"name", "  "},
		"long name":          {"name", strings.Repeat("n", 65)},
		"javascript url":     {"url", "javascript:alert(1)"},
		"data url":           {"url", "data:text/html,hi"},
		"relative url":       {"url", "/admin"},
		"no host":            {"url", "https://"},
		"long url":           {"url", "https://a.b/" + strings.Repeat("x", 2048)},
		"long group":         {"group", strings.Repeat("g", 65)},
		"long description":   {"description", strings.Repeat("d", 201)},
		"interval too short": {"interval", "5"},
		"interval too long":  {"interval", "3601"},
		"timeout zero":       {"timeout", "0"},
		"timeout too long":   {"timeout", "61"},
		"status too low":     {"status", "99"},
		"status text":        {"status", "ok"},
		"unknown host":       {"host", "42"},
	}
	for name, kv := range cases {
		f := validForm()
		f.Set(kv[0], kv[1])
		w := h.do("POST", "/services", c, f, true)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `class="error"`) {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	f := validForm()
	f.Set("interval", "30")
	f.Set("timeout", "30")
	if w := h.do("POST", "/services", c, f, true); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "shorter than") {
		t.Errorf("timeout equal to interval: %d", w.Code)
	}
	f = validForm()
	f.Set("name", "")
	f.Set("group", "Kept group")
	if body := h.do("POST", "/services", c, f, true).Body.String(); !strings.Contains(body, `value="Kept group"`) || !strings.Contains(body, `value="https://grafana.lan/?token=s3cret"`) {
		t.Error("the dialog must keep every value after an error")
	}
	if n, _ := h.st.ServiceCount(context.Background()); n != 0 {
		t.Errorf("%d services stored from invalid forms", n)
	}
}

func TestEditService(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	hostID := h.addHost("pve-2")
	var fetches atomic.Int32
	h.web.iconFetch = func(context.Context, string, svcicon.Options) ([]byte, string, error) {
		fetches.Add(1)
		return []byte{1}, "image/png", nil
	}
	id := h.addService("Grafana", "https://grafana.lan", "Infra")
	h.st.SetServiceIcon(context.Background(), id, "https://grafana.lan", []byte{1}, "image/png", h.clock)
	c := h.login()
	body := h.do("GET", "/services/"+itoa(id)+"/edit", c, nil, true).Body.String()
	for _, want := range []string{`<h2>Edit Service</h2>`, `hx-post="/services/` + itoa(id) + `"`, `value="Grafana"`, "Refresh icon"} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form is missing %q", want)
		}
	}
	f := validForm()
	f.Set("url", "https://grafana.lan")
	f.Set("name", "Grafana 2")
	f.Set("host", itoa(hostID))
	f.Set("selfsigned", "1")
	if w := h.do("POST", "/services/"+itoa(id), c, f, true); w.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	h.web.bg.Wait()
	got, _ := h.st.Service(context.Background(), id)
	if got.Name != "Grafana 2" || got.HostID != hostID || !got.AcceptSelfSigned || fetches.Load() != 0 {
		t.Errorf("after edit: %+v, fetches %d (same URL must not fetch)", got, fetches.Load())
	}
	f.Set("url", "https://grafana2.lan")
	h.do("POST", "/services/"+itoa(id), c, f, true)
	h.web.bg.Wait()
	if fetches.Load() != 1 {
		t.Errorf("a new URL must fetch the icon once, fetched %d", fetches.Load())
	}
	if !strings.Contains(h.logs.Text(), "service Grafana 2 (grafana2.lan) edited") {
		t.Errorf("log = %q", h.logs.Text())
	}
	if w := h.do("GET", "/services/999/edit", c, nil, true); w.Code != http.StatusNotFound {
		t.Errorf("edit of a missing service: %d", w.Code)
	}
	if w := h.do("POST", "/services/999", c, f, true); w.Code != http.StatusNotFound {
		t.Errorf("save of a missing service: %d", w.Code)
	}
}

func TestPauseResumeDelete(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addService("Grafana", "https://grafana.lan/x?token=s3cret", "")
	c := h.login()
	w := h.do("POST", "/services/"+itoa(id)+"/enabled", c, form("enabled", "0"), false)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/services" {
		t.Fatalf("pause: %d %q", w.Code, w.Header().Get("Location"))
	}
	if got, _ := h.st.Service(context.Background(), id); got.Enabled {
		t.Error("must be paused")
	}
	h.do("POST", "/services/"+itoa(id)+"/enabled", c, form("enabled", "1"), false)
	if got, _ := h.st.Service(context.Background(), id); !got.Enabled {
		t.Error("must be resumed")
	}
	if w := h.do("POST", "/services/"+itoa(id)+"/delete", c, nil, false); w.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", w.Code)
	}
	if n, _ := h.st.ServiceCount(context.Background()); n != 0 {
		t.Error("must be deleted")
	}
	logs := h.logs.Text()
	for _, want := range []string{"service Grafana (grafana.lan) paused", "service Grafana (grafana.lan) resumed", "service Grafana (grafana.lan) removed"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log is missing %q", want)
		}
	}
	if strings.Contains(logs, "s3cret") {
		t.Error("log carries the URL query")
	}
	for _, path := range []string{"/enabled", "/delete", "/icon"} {
		if w := h.do("POST", "/services/999"+path, c, nil, false); w.Code != http.StatusNotFound {
			t.Errorf("%s of a missing service: %d", path, w.Code)
		}
	}
}

func TestIconRoute(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addService("a", "http://a", "")
	c := h.login()
	if w := h.do("GET", "/services/"+itoa(id)+"/icon", c, nil, false); w.Code != http.StatusNotFound {
		t.Errorf("no icon yet: %d", w.Code)
	}
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	h.st.SetServiceIcon(context.Background(), id, "http://a", svg, "image/svg+xml", h.clock)
	w := h.do("GET", "/services/"+itoa(id)+"/icon", c, nil, false)
	for k, v := range map[string]string{
		"Content-Type":            "image/svg+xml",
		"Cache-Control":           "private, max-age=86400",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if w.Body.String() != string(svg) {
		t.Error("body must be the stored icon")
	}
	if w := h.do("GET", "/services/"+itoa(id)+"/icon", nil, nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("icon without session: %d", w.Code)
	}
}

func TestRefreshIcon(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addService("a", "http://a", "")
	h.web.iconFetch = func(context.Context, string, svcicon.Options) ([]byte, string, error) {
		return []byte{7}, "image/png", nil
	}
	w := h.do("POST", "/services/"+itoa(id)+"/icon", h.login(), nil, true)
	if w.Code != http.StatusNoContent {
		t.Fatalf("refresh: %d", w.Code)
	}
	h.web.bg.Wait()
	if data, _, err := h.st.ServiceIcon(context.Background(), id); err != nil || data[0] != 7 {
		t.Errorf("icon = %v %v", data, err)
	}
}

// A service removed while its icon loads stays removed.
func TestDeleteDuringIconFetch(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	started, release := make(chan struct{}), make(chan struct{})
	h.web.iconFetch = func(context.Context, string, svcicon.Options) ([]byte, string, error) {
		close(started)
		<-release
		return []byte{1}, "image/png", nil
	}
	c := h.login()
	h.do("POST", "/services", c, validForm(), true)
	<-started
	list, _ := h.st.Services(context.Background())
	h.do("POST", "/services/"+itoa(list[0].ID)+"/delete", c, nil, false)
	close(release)
	h.web.bg.Wait()
	if n, _ := h.st.ServiceCount(context.Background()); n != 0 {
		t.Errorf("service came back: %d", n)
	}
}

func TestServiceRoutesNeedSession(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := itoa(h.addService("a", "http://a", ""))
	for _, rt := range [][2]string{{"GET", "/services/new"}, {"GET", "/services/" + id + "/edit"}, {"POST", "/services"},
		{"POST", "/services/" + id}, {"POST", "/services/" + id + "/enabled"}, {"POST", "/services/" + id + "/delete"},
		{"POST", "/services/" + id + "/icon"}} {
		if w := h.do(rt[0], rt[1], nil, validForm(), false); w.Code != http.StatusSeeOther {
			t.Errorf("%s %s without session: %d", rt[0], rt[1], w.Code)
		}
	}
	if n, _ := h.st.ServiceCount(context.Background()); n != 1 {
		t.Error("a request without session changed the services")
	}
}

func TestCardLiveLine(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	on := h.addService("On", "http://on", "")
	slow := h.addService("Slow", "http://slow", "")
	down := h.addService("Down", "http://down", "")
	busy := h.addService("Busy", "http://busy", "")
	h.addService("New", "http://new", "")
	h.st.SaveCheck(ctx, on, "http://on", store.CheckState{State: "online", CheckedAt: 1790000000, Ms: 84, Code: 200})
	h.st.SaveCheck(ctx, slow, "http://slow", store.CheckState{State: "degraded", CheckedAt: 1790000000, Ms: 1842, Code: 200})
	h.st.SaveCheck(ctx, down, "http://down", store.CheckState{State: "down", Since: 1789999520, CheckedAt: 1790000000, Error: "timeout", FailStreak: 3})
	h.st.SaveCheck(ctx, busy, "http://busy", store.CheckState{State: "unknown", CheckedAt: 1790000000, Error: "timeout", FailStreak: 1})
	body := h.do("GET", "/services", h.login(), nil, false).Body.String()
	for _, want := range []string{
		`sse-swap="svc-` + itoa(on) + `" hx-swap="innerHTML"`,
		`<span class="st" data-state="online"><span class="dot"></span>84 ms · checked <span data-ts="1790000000"></span> · 100%</span>`,
		`<span class="st" data-state="degraded"><span class="dot"></span>1,842 ms · slow · checked <span data-ts="1790000000"></span> · 100%</span>`,
		`<span class="st" data-state="down" title="timeout"><span class="dot"></span><b>DOWN</b> · <span data-for="1789999520"></span> · 0%</span>`,
		`<span class="st" data-state="unknown" title="timeout"><span class="dot"></span>checking…</span>`,
		`<span class="st" data-state="unknown"><span class="dot"></span>not checked yet</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	if !strings.Contains(body, `<a href="/services" data-nav="services">Services<span class="count bad">5</span></a>`) {
		t.Error("the Services count must be red while a service is down")
	}
}

func TestServiceCheckedStreamEvent(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addService("a", "http://a", "")
	c := h.login()
	srv := httptest.NewServer(h.mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
	h.st.SaveCheck(context.Background(), id, "http://a", store.CheckState{State: "online", CheckedAt: 1790000000, Ms: 12})
	h.bus.Publish(live.Event{Kind: live.ServiceChecked, HostID: id})
	var event, data string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = line[7:]
		case strings.HasPrefix(line, "data: "):
			data += line[6:]
		case line == "" && event != "":
			if event != "svc-"+itoa(id) || !strings.Contains(data, `data-state="online"`) || !strings.Contains(data, "12 ms") {
				t.Errorf("event %q data %q", event, data)
			}
			return
		}
	}
	t.Fatalf("stream ended: %v", sc.Err())
}

func TestSettingsServiceRules(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	body := h.do("GET", "/settings", c, nil, false).Body.String()
	for _, want := range []string{`<legend>Service checks</legend>`, `name="svc_fail_n" value="3"`, `name="svc_ok_n" value="2"`, `name="svc_slow_ms" value="1000"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	f := form("offline_after_s", "60", "cpu_for_min", "5", "ram_for_min", "5", "disk_for_min", "2", "svc_fail_n", "5", "svc_ok_n", "1", "svc_slow_ms", "250")
	if w := h.do("POST", "/settings", c, f, false); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	s, _ := h.st.Settings(context.Background())
	if s["svc_fail_n"] != "5" || s["svc_ok_n"] != "1" || s["svc_slow_ms"] != "250" {
		t.Errorf("stored: %v", s)
	}
	for key, bad := range map[string]string{"svc_fail_n": "0", "svc_ok_n": "11", "svc_slow_ms": "50"} {
		f := form("offline_after_s", "60", "cpu_for_min", "5", "ram_for_min", "5", "disk_for_min", "2", key, bad)
		if w := h.do("POST", "/settings", c, f, false); w.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s=%s: %d", key, bad, w.Code)
		}
	}
}

// An old form without the new fields keeps what is stored.
func TestSettingsKeepServiceRulesWhenMissing(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	h.st.SetSettings(context.Background(), map[string]string{"svc_fail_n": "4"})
	c := h.login()
	f := form("offline_after_s", "60", "cpu_for_min", "5", "ram_for_min", "5", "disk_for_min", "2")
	if w := h.do("POST", "/settings", c, f, false); w.Code != http.StatusSeeOther {
		t.Fatalf("save without the new fields: %d %s", w.Code, w.Body.String())
	}
	s, _ := h.st.Settings(context.Background())
	if s["svc_fail_n"] != "4" || s["svc_ok_n"] != "2" || s["svc_slow_ms"] != "1000" {
		t.Errorf("stored: %v", s)
	}
}

func TestServiceCardShowsUptimeAndDetails(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	id := h.addService("Grafana", "https://grafana.lan", "")
	fresh := h.addService("New", "https://new.lan", "")
	at := h.clock.Unix()
	h.st.SaveCheck(ctx, id, "https://grafana.lan", store.CheckState{State: "online", OK: true, CheckedAt: at - 60, Ms: 40, Code: 200})
	h.st.SaveCheck(ctx, id, "https://grafana.lan", store.CheckState{State: "down", Since: at, CheckedAt: at, Error: "timeout", FailStreak: 3})
	body := h.do("GET", "/services", h.login(), nil, false).Body.String()
	for _, want := range []string{`href="/services/` + itoa(id) + `"`, `>Details<`, `· 50%`} {
		if !strings.Contains(body, want) {
			t.Errorf("services page is missing %q", want)
		}
	}
	card := body[strings.Index(body, `id="svc-`+itoa(fresh)+`"`):]
	card = card[:strings.Index(card, `</span></span>`)]
	if strings.Contains(card, "%") {
		t.Errorf("a never-checked card shows an uptime: %s", card)
	}
}

func stripTags(s string) string { return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(s, " ") }

func TestServiceDetailPage(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	host := h.addHost("pve-2")
	u := "https://portal.lan/login?token=SECRET"
	id, _ := h.st.CreateService(ctx, store.Service{Name: "Portal", URL: u, Description: "customer portal",
		HostID: host, IntervalS: 60, TimeoutS: 10, Enabled: true}, h.clock)
	at := h.clock.Unix()
	h.st.SaveCheck(ctx, id, u, store.CheckState{State: "down", Since: at - 600, CheckedAt: at - 600, Error: "timeout", FailStreak: 3})
	h.st.SaveCheck(ctx, id, u, store.CheckState{State: "online", OK: true, Since: at - 60, CheckedAt: at - 60, Ms: 68, Code: 200,
		OkStreak: 2, CertExpiresAt: at + 73*86400 + 60})
	body := h.do("GET", "/services/"+itoa(id), h.login(), nil, false).Body.String()
	for _, want := range []string{
		`<span class="crumb">Portal</span>`, `data-service="` + itoa(id) + `"`, `customer portal`,
		`68 ms`, `every 60 s`, `expires in 73 days`, `href="/hosts/` + itoa(host) + `"`, `pve-2`,
		`hx-get="/services/` + itoa(id) + `/panel"`, `sse:svc-` + itoa(id), `class="avail"`,
		`9 min`, `timeout`, `https://portal.lan`, // incident: 540 s, its reason; the shown address
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page is missing %q", want)
		}
	}
	if n := strings.Count(body, `class="blk"`); n != 48 {
		t.Errorf("availability bar has %d blocks; want 48", n)
	}
	if strings.Contains(stripTags(body), "SECRET") {
		t.Error("the page text shows the URL query")
	}
}

func TestServiceDetailPageEmptyService(t *testing.T) {
	h := newHarness(t, "http://hub.example.com", false)
	id := h.addService("Plain", "http://plain.lan", "")
	rec := h.do("GET", "/services/"+itoa(id), h.login(), nil, false)
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	for _, unwanted := range []string{"Certificate", "Hosted on", "Description"} {
		if strings.Contains(body, "<dt>"+unwanted+"</dt>") {
			t.Errorf("empty service shows a %q row", unwanted)
		}
	}
	for _, want := range []string{"not checked yet", "No incidents in the last 90 days.", `data-state="none"`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty service page is missing %q", want)
		}
	}
}

func TestServiceDetailUnknownAndPanelAndPauseBack(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	if rec := h.do("GET", "/services/999", c, nil, false); rec.Code != 404 {
		t.Fatalf("unknown service = %d; want 404", rec.Code)
	}
	id := h.addService("A", "https://a.lan", "")
	panel := h.do("GET", "/services/"+itoa(id)+"/panel", c, nil, true).Body.String()
	if strings.Contains(panel, "<html") || !strings.Contains(panel, `class="avail"`) {
		t.Fatalf("panel must be the fragment with the bar: %.200s", panel)
	}
	rec := h.do("POST", "/services/"+itoa(id)+"/enabled", c, url.Values{"enabled": {"0"}, "back": {"detail"}}, false)
	if loc := rec.Header().Get("Location"); loc != "/services/"+itoa(id) {
		t.Fatalf("pause from the detail page goes to %q", loc)
	}
	rec = h.do("POST", "/services/"+itoa(id)+"/enabled", c, url.Values{"enabled": {"1"}}, false)
	if loc := rec.Header().Get("Location"); loc != "/services" {
		t.Fatalf("resume from the list goes to %q", loc)
	}
}

func TestServiceDetailWhileDown(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	id := h.addService("Local", "http://127.0.0.1:8095", "")
	at := h.clock.Unix()
	h.st.SaveCheck(ctx, id, "http://127.0.0.1:8095", store.CheckState{State: "down", Since: at, CheckedAt: at, Ms: 0, Error: "connection refused", FailStreak: 3})
	body := h.do("GET", "/services/"+itoa(id), h.login(), nil, false).Body.String()
	if !strings.Contains(body, "<dt>Response</dt><dd>– · avg 24 h –</dd>") {
		t.Error("a down service must not show the time it took to fail as its response time")
	}
	status := body[strings.Index(body, "<dt>Status</dt>"):]
	status = status[:strings.Index(status, "</dd>")]
	if strings.Contains(status, "%") {
		t.Errorf("the status line repeats the uptime shown in its own row: %s", status)
	}
}

func TestAlertsPageShowsServiceAlerts(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	id := h.addService("Grafana", "https://grafana.lan/?token=SECRET", "")
	aid, _ := h.st.CreateServiceAlert(ctx, id, "svc_down", "", "timeout", h.clock, true)
	c := h.login()
	body := h.do("GET", "/alerts", c, nil, false).Body.String()
	for _, want := range []string{`<th>Host / service</th>`, `href="/services/` + itoa(id) + `"`, `>Grafana<`, `Service DOWN`, `timeout`} {
		if !strings.Contains(body, want) {
			t.Errorf("alerts page is missing %q", want)
		}
	}
	page := h.do("GET", "/alerts/"+itoa(aid), c, nil, false).Body.String()
	if !strings.Contains(page, "<dt>Service</dt>") || strings.Contains(page, "<dt>Host</dt>") || strings.Contains(stripTags(page), "SECRET") {
		t.Errorf("alert page for a service without host: %s", stripTags(page))
	}
}

func TestSettingsServiceAlerts(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	body := h.do("GET", "/settings", c, nil, false).Body.String()
	for _, want := range []string{`name="svc_cert_days" value="30, 14, 7, 1"`, `type="hidden" name="svc_slow_alert" value="0"`, `type="checkbox" name="svc_slow_alert" value="1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	base := func() url.Values {
		return form("offline_after_s", "60", "cpu_for_min", "5", "ram_for_min", "5", "disk_for_min", "2", "svc_fail_n", "3", "svc_ok_n", "2", "svc_slow_ms", "1000")
	}
	f := base()
	f.Set("svc_cert_days", "60, 7")
	f["svc_slow_alert"] = []string{"0", "1"}
	if rec := h.do("POST", "/settings", c, f, false); rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d", rec.Code)
	}
	s, _ := h.st.Settings(context.Background())
	if s["svc_cert_days"] != "60, 7" || s["svc_slow_alert"] != "1" {
		t.Fatalf("saved %q %q", s["svc_cert_days"], s["svc_slow_alert"])
	}
	f["svc_slow_alert"] = []string{"0"}
	h.do("POST", "/settings", c, f, false)
	if s, _ = h.st.Settings(context.Background()); s["svc_slow_alert"] != "0" {
		t.Fatalf("unchecked box saved %q; want 0", s["svc_slow_alert"])
	}
	h.st.SetSettings(context.Background(), map[string]string{"svc_slow_alert": "1"})
	h.do("POST", "/settings", c, base(), false) // a form from before these fields
	if s, _ = h.st.Settings(context.Background()); s["svc_slow_alert"] != "1" || s["svc_cert_days"] != "60, 7" {
		t.Fatalf("missing fields must keep what is stored: %q %q", s["svc_slow_alert"], s["svc_cert_days"])
	}
	f = base()
	f.Set("svc_cert_days", "7, 30")
	rec := h.do("POST", "/settings", c, f, false)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "List certificate warning days from large to small") {
		t.Fatalf("bad days: %d", rec.Code)
	}
}

func TestQuietlyEndedAlertSaysNoMessage(t *testing.T) {
	a := store.Alert{Kind: "svc_down", ServiceID: 3, Service: "A", PendingSince: time.Unix(100, 0), FiredAt: time.Unix(100, 0),
		ResolvedAt: time.Unix(200, 0), NotifiedFire: true, EndedQuietly: true}
	v := BuildAlertView(a, time.Unix(300, 0))
	if v.FireMsg != "sent" || !strings.HasPrefix(v.ResolveMsg, "none: it ended without a message") {
		t.Fatalf("messages = %q / %q", v.FireMsg, v.ResolveMsg)
	}
}
