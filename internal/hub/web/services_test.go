package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
