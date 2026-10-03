package web

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/logbuf"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

type harness struct {
	t     *testing.T
	web   *Web
	st    *store.Store
	bus   *live.Bus
	logs  *logbuf.Buffer
	mux   *http.ServeMux
	clock time.Time
}

func newHarness(t *testing.T, publicURL string, secure bool) *harness {
	t.Helper()
	h := &harness{t: t, bus: live.New(), mux: http.NewServeMux(), clock: now}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h.st = st
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	st.CreateAdmin(context.Background(), string(hash))
	h.logs = logbuf.New(100, func() time.Time { return h.clock })
	w, err := New(st, h.bus, h.logs, func() time.Time { return h.clock }, publicURL, secure)
	if err != nil {
		t.Fatal(err)
	}
	// Handlers log through the standard logger, as the Hub does.
	log.SetOutput(h.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	w.Routes(h.mux)
	h.web = w
	return h
}

func (h *harness) do(method, path string, cookie *http.Cookie, form url.Values, htmx bool) *httptest.ResponseRecorder {
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if htmx {
		r.Header.Set("HX-Request", "true")
	}
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	return w
}

func (h *harness) login() *http.Cookie {
	h.t.Helper()
	w := h.do("POST", "/login", nil, url.Values{"password": {"pw"}}, false)
	if w.Code != http.StatusSeeOther || len(w.Result().Cookies()) != 1 {
		h.t.Fatalf("login: status %d, cookies %d", w.Code, len(w.Result().Cookies()))
	}
	return w.Result().Cookies()[0]
}

// addHost enrolls a host and stores one report with inventory.
func (h *harness) addHost(name string) int64 {
	h.t.Helper()
	ctx := context.Background()
	eh, ah := "e-"+name, "a-"+name
	h.st.CreateEnrollmentToken(ctx, eh, h.clock, h.clock.Add(time.Minute))
	agentID, hostID, err := h.st.Enroll(ctx, store.EnrollParams{EnrollTokenHash: eh, Hostname: name, AgentTokenHash: ah, ProtocolVersion: 1, Now: h.clock})
	if err != nil {
		h.t.Fatal(err)
	}
	cpu := 12.0
	rep := protocol.Report{ProtocolVersion: 1, TS: 1, Metrics: protocol.Metrics{CPUPct: &cpu, UptimeS: 600},
		Inventory: &protocol.Inventory{Hostname: name, Interfaces: []protocol.Interface{{Name: "eth0", DefaultRoute: true, IPv4: []string{"10.0.0.5"}, IPv6: []string{}}}}}
	if err := h.st.AcceptReport(ctx, agentID, rep, h.clock); err != nil {
		h.t.Fatal(err)
	}
	return hostID
}

func TestEnsureAdmin(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(filepath.Join(t.TempDir(), "t.db"))
	defer st.Close()
	if err := EnsureAdmin(ctx, st, ""); err == nil || !strings.Contains(err.Error(), "FLEETWATCH_ADMIN_PASSWORD") {
		t.Errorf("first start without a password: err = %v, want it to name the variable", err)
	}
	if err := EnsureAdmin(ctx, st, "s3cret"); err != nil {
		t.Fatal(err)
	}
	hash, _ := st.AdminPasswordHash(ctx)
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("s3cret")) != nil {
		t.Error("stored hash must verify the password")
	}
	if err := EnsureAdmin(ctx, st, ""); err != nil {
		t.Errorf("an existing admin must make the variable optional: %v", err)
	}
	EnsureAdmin(ctx, st, "other")
	if again, _ := st.AdminPasswordHash(ctx); again != hash {
		t.Error("the variable must be ignored once an admin exists")
	}
}

func TestLoginSetsHardenedCookie(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", true)
	w := h.do("POST", "/login", nil, url.Values{"password": {"wrong"}}, false)
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), "Wrong password") {
		t.Errorf("wrong password: status %d, cookies %d", w.Code, len(w.Result().Cookies()))
	}
	c := h.login()
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || !c.Secure || c.Path != "/" || len(c.Value) != 43 {
		t.Errorf("cookie = %+v", c)
	}
	if plain := newHarness(t, "http://hub:8080", false).login(); plain.Secure {
		t.Error("without TLS the cookie must not be Secure, or the browser would never send it")
	}
}

func TestLoginRateLimit(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	for i := 0; i < 5; i++ {
		h.do("POST", "/login", nil, url.Values{"password": {"wrong"}}, false)
	}
	if w := h.do("POST", "/login", nil, url.Values{"password": {"pw"}}, false); w.Code != http.StatusTooManyRequests {
		t.Errorf("sixth attempt within a minute: %d, want 429", w.Code)
	}
	h.clock = h.clock.Add(61 * time.Second)
	h.login()
}

func TestSessionIsRequired(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	if w := h.do("GET", "/", nil, nil, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("page without session: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := h.do("GET", "/events", nil, nil, false); w.Code != http.StatusUnauthorized {
		t.Errorf("/events without session: %d, want 401", w.Code)
	}
	if w := h.do("POST", "/servers/enroll-token", nil, nil, true); w.Header().Get("HX-Redirect") != "/login" || strings.Contains(w.Body.String(), "--token") {
		t.Errorf("htmx request without session must redirect and reveal nothing: %q", w.Header().Get("HX-Redirect"))
	}
	c := h.login()
	if w := h.do("GET", "/", c, nil, false); w.Code != http.StatusOK {
		t.Fatalf("page with session: %d", w.Code)
	}
	if w := h.do("POST", "/logout", c, nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("logout: %d", w.Code)
	}
	if w := h.do("GET", "/", c, nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("the old cookie must stop working after logout: %d", w.Code)
	}
	h.clock = h.clock.Add(8 * 24 * time.Hour)
	if w := h.do("GET", "/", h.login(), nil, false); w.Code != http.StatusOK {
		t.Errorf("fresh login: %d", w.Code)
	}
}

func TestHostsPage(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	body := h.do("GET", "/", c, nil, false).Body.String()
	if !strings.Contains(body, `id="empty"`) || strings.Contains(body, `<tr id="host-`) {
		t.Error("with no hosts the page shows the empty state and no rows")
	}
	id := h.addHost(`<img src=x onerror=alert(1)>`)
	body = h.do("GET", "/", c, nil, false).Body.String()
	if strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;img src=x") {
		t.Error("agent-supplied host name must be HTML-escaped")
	}
	for _, want := range []string{
		`<tr id="host-1" sse-swap="host-1" hx-swap="innerHTML">`, `<a href="/hosts/1">`,
		`data-status="online"`, `10.0.0.5`, `<span class="pct">12%</span>`, `10m`,
		`sse-connect="/events"`, `sse-swap="host-new"`, `data-now="1790000000"`,
		`id="search"`, `class="sort"`, `data-v="600"`, `data-v="167772165"`,
		`CPU (avg)`, `<span class="ok">1 online</span>`, `max <span>12%</span>`,
		`sse-swap="statusline"`, `<span>1 host</span>`, `v0.1.0`, `fleetwatch@hub.example.com:~$`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page for host %d is missing %q", id, want)
		}
	}
}

func TestEnrollTokenFragment(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	body := h.do("POST", "/servers/enroll-token", c, nil, true).Body.String()
	m := regexp.MustCompile(`<code id="enroll-command">curl -fsSL https://hub\.example\.com/install/([A-Za-z0-9_-]{43}) \| sudo bash</code>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("fragment does not hold the install line: %s", body)
	}
	if !strings.Contains(body, "15 minutes") || !strings.Contains(body, `data-copy="#enroll-command"`) {
		t.Error("fragment must state the expiry and offer the copy button")
	}
	for _, want := range []string{"curl -fsSL https://hub.example.com/install/" + m[1] + " -o fleetwatch-install.sh", "less fleetwatch-install.sh", "sudo bash fleetwatch-install.sh"} {
		if !strings.Contains(body, want) {
			t.Errorf("the manual path is missing %q", want)
		}
	}
	if strings.Contains(body, "not encrypted") {
		t.Error("an https:// Hub needs no warning")
	}
	_, _, err := h.st.Enroll(context.Background(), store.EnrollParams{EnrollTokenHash: store.HashToken(m[1]), Hostname: "x", AgentTokenHash: "a", ProtocolVersion: 1, Now: h.clock.Add(14 * time.Minute)})
	if err != nil {
		t.Errorf("the token shown must enroll within 15 minutes: %v", err)
	}

	plain := newHarness(t, "http://192.168.1.5:8080", false)
	body = plain.do("POST", "/servers/enroll-token", plain.login(), nil, true).Body.String()
	if !strings.Contains(body, "curl -fsSL http://192.168.1.5:8080/install/") || !strings.Contains(body, "not encrypted") {
		t.Error("for an http:// Hub the fragment must warn that the connection is not encrypted")
	}
}

func TestReplaceCredentialFragment(t *testing.T) {
	h := newHarness(t, "http://192.168.1.5:8080", false)
	id := h.addHost("web-01")
	c := h.login()
	path := "/hosts/" + strconv.FormatInt(id, 10) + "/credential"
	if w := h.do("POST", path, nil, nil, true); w.Header().Get("HX-Redirect") != "/login" {
		t.Error("replacing a credential needs a session")
	}
	body := h.do("POST", path, c, nil, true).Body.String()
	m := regexp.MustCompile(`<code id="enroll-command">sudo fleetwatch-agent enroll --hub http://192\.168\.1\.5:8080 --token ([A-Za-z0-9_-]{43}) --allow-insecure-http</code>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("fragment does not hold the enroll command: %s", body)
	}
	if !strings.Contains(body, "curl -fsSL http://192.168.1.5:8080/install/"+m[1]+" | sudo bash") || !strings.Contains(body, "web-01") {
		t.Error("fragment must also offer the install line for a reinstalled server, and name the host")
	}
	bound, usable, _ := h.st.EnrollmentTokenHost(context.Background(), store.HashToken(m[1]), h.clock)
	if !usable || bound != id {
		t.Errorf("the token must be bound to host %d: bound %d usable %v", id, bound, usable)
	}
	if w := h.do("POST", "/hosts/999/credential", c, nil, true); w.Code != http.StatusNotFound {
		t.Errorf("unknown host: %d", w.Code)
	}
}

func TestDisableAndEnableAgent(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web-01")
	h.addHost("web-02")
	c := h.login()
	page := "/hosts/" + strconv.FormatInt(id, 10)
	body := h.do("GET", page, c, nil, false).Body.String()
	for _, want := range []string{`hx-post="` + page + `/credential"`, `action="` + page + `/agent"`, `name="disabled" value="1"`, "Disable agent", `<dialog id="enroll-dialog">`} {
		if !strings.Contains(body, want) {
			t.Errorf("host page is missing %q", want)
		}
	}
	if w := h.do("POST", page+"/agent", nil, url.Values{"disabled": {"1"}}, false); w.Header().Get("Location") != "/login" {
		t.Error("disabling needs a session")
	}
	events, cancel := h.bus.Subscribe()
	defer cancel()
	if w := h.do("POST", page+"/agent", c, url.Values{"disabled": {"1"}}, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != page {
		t.Fatalf("disable: %d %q", w.Code, w.Header().Get("Location"))
	}
	if ev := <-events; ev.Kind != live.HostUpdated || ev.HostID != id {
		t.Errorf("disable must publish an update of the host: %+v", ev)
	}
	body = h.do("GET", page, c, nil, false).Body.String()
	for _, want := range []string{`data-status="disabled"`, "Disabled", `name="disabled" value="0"`, "Enable agent", "The Hub refuses reports from this agent"} {
		if !strings.Contains(body, want) {
			t.Errorf("page of a disabled host is missing %q", want)
		}
	}
	if strings.Contains(body, `<span class="pct">12%</span>`) {
		t.Error("a disabled host shows no current usage")
	}
	list := h.do("GET", "/", c, nil, false).Body.String()
	if !strings.Contains(list, `data-status="disabled"`) || !strings.Contains(list, "1 disabled") || !strings.Contains(list, `<span>0 offline</span>`) {
		t.Error("the list must show the host as disabled and not count it as offline")
	}
	h.do("POST", page+"/agent", c, url.Values{"disabled": {"0"}}, false)
	if host, _ := h.st.Host(context.Background(), id); host.Disabled {
		t.Error("the agent must be enabled again")
	}
}

func TestBackgroundImageIsServedAndUsed(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	w := h.do("GET", "/static/bg.webp", nil, nil, false)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/webp" || w.Body.Len() < 10_000 {
		t.Fatalf("background image: status %d, type %q, %d bytes", w.Code, w.Header().Get("Content-Type"), w.Body.Len())
	}
	css := h.do("GET", "/static/app.css", nil, nil, false).Body.String()
	if !strings.Contains(css, `url("bg.webp")`) {
		t.Error("app.css must load the background relative to itself, so the login page and the mocks get it too")
	}
}

// addRichHost enrolls a host and stores a report with every field filled.
func (h *harness) addRichHost(name string) int64 {
	h.t.Helper()
	ctx := context.Background()
	eh, ah := "e-"+name, "a-"+name
	h.st.CreateEnrollmentToken(ctx, eh, h.clock, h.clock.Add(time.Minute))
	agentID, hostID, err := h.st.Enroll(ctx, store.EnrollParams{EnrollTokenHash: eh, Hostname: name, AgentTokenHash: ah, ProtocolVersion: 1, Now: h.clock})
	if err != nil {
		h.t.Fatal(err)
	}
	const gib = 1 << 30
	cpu := 42.0
	rep := protocol.Report{ProtocolVersion: 1, AgentVersion: "0.1.0", TS: 1, Metrics: protocol.Metrics{
		CPUPct: &cpu, Load: []float64{0.42, 0.31, 0.2}, UptimeS: 93784,
		Mem:      &protocol.Mem{Total: 8 * gib, Used: 2 * gib},
		Swap:     &protocol.Swap{Total: 4 * gib, Used: 1 * gib},
		Disks:    []protocol.Disk{{Mount: "/", FS: "ext4", Total: 100 * gib, Used: 40 * gib}, {Mount: "/data<b>", FS: "xfs", Total: 200 * gib, Used: 170 * gib}},
		Net:      []protocol.NetIf{{Name: "eth0", State: "up", RxBytes: 1536, TxBytes: 3 * gib}},
		Services: []protocol.Service{{Name: "nginx.service", Status: "running"}, {Name: "db<i>.service", Status: "failed"}},
		Proxmox: &protocol.Proxmox{Detected: true, Configured: true, Version: "8.2.4", Node: "pve-01",
			Guests:  []protocol.Guest{{ID: 101, Type: "lxc", Name: "nginx<u>", Status: "running", CPUs: 2, MemMax: 512 << 20, IPs: []string{"192.168.10.21"}}, {ID: 115, Type: "qemu", Name: "db", Status: "stopped"}},
			Storage: []protocol.Storage{{Name: "local", Type: "dir", Active: true, Total: 100 * gib, Used: 40 * gib}}},
	}, Inventory: &protocol.Inventory{Hostname: name, OS: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-18-amd64", CPUModel: "Test CPU", Cores: 8,
		Interfaces: []protocol.Interface{{Name: "eth0", DefaultRoute: true, IPv4: []string{"10.0.0.5"}, IPv6: []string{"2001:db8::5"}}}}}
	if err := h.st.AcceptReport(ctx, agentID, rep, h.clock); err != nil {
		h.t.Fatal(err)
	}
	return hostID
}

func TestHostDetailPage(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	h.addRichHost("web-01")
	if w := h.do("GET", "/hosts/1", nil, nil, false); w.Code != http.StatusSeeOther {
		t.Fatalf("detail page without session: %d, want a redirect to login", w.Code)
	}
	c := h.login()
	w := h.do("GET", "/hosts/1", c, nil, false)
	if w.Code != http.StatusOK {
		t.Fatalf("detail page: %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"web-01", `data-status="online"`, "1d 2h", "v0.1.0",
		"Debian GNU/Linux 12 (bookworm)", "6.1.0-18-amd64", "Test CPU", "8 cores", "8.0 GiB",
		"42%", "2.0 GiB / 8.0 GiB", "1.0 GiB / 4.0 GiB", "0.42 0.31 0.20",
		"ext4", "40.0 GiB / 100.0 GiB", "170.0 GiB / 200.0 GiB", "85%",
		"eth0", "10.0.0.5", "2001:db8::5", "1.5 KiB", "3.0 GiB",
		`sse-connect="/events?host=1"`, `hx-get="/hosts/1/charts?range=1h"`, `href="/"`,
		"Services", "nginx.service", `data-s="running"`, "db&lt;i&gt;.service", `data-s="failed"`,
		"Proxmox VE 8.2.4", "Guests", "nginx&lt;u&gt;", "LXC", "192.168.10.21", "Storage", "40.0 GiB / 100.0 GiB",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page is missing %q", want)
		}
	}
	if strings.Contains(body, "/data<b>") || !strings.Contains(body, "/data&lt;b&gt;") {
		t.Error("agent-supplied mount point must be HTML-escaped")
	}
	for _, path := range []string{"/hosts/999", "/hosts/abc"} {
		if w := h.do("GET", path, c, nil, false); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, w.Code)
		}
	}
}

func TestGuestsColumnOnTheList(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	h.addRichHost("pve-01")
	h.addHost("plain")
	body := h.do("GET", "/", h.login(), nil, false).Body.String()
	for _, want := range []string{`>Guests<`, `<td class="guests" data-v="2">1 / 2</td>`, `<td class="guests" data-v="">–</td>`} {
		if !strings.Contains(body, want) {
			t.Errorf("host list is missing %q", want)
		}
	}
}

func TestChartsFragment(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web-01")
	c := h.login()
	body := h.do("GET", "/hosts/1/charts?range=1h", c, nil, true).Body.String()
	if strings.Count(body, "No data in this period") != 3 {
		t.Errorf("without history every chart says so: %s", body)
	}
	for i := int64(0); i < 20; i++ {
		v := float64(10 + i)
		h.st.QueueMetric(store.MetricPoint{HostID: id, TS: h.clock.Unix() - 1800 + i*15, CPU: &v, Mem: &v, Disk: &v})
	}
	h.st.FlushMetrics(context.Background())
	body = h.do("GET", "/hosts/1/charts?range=1h", c, nil, true).Body.String()
	if strings.Count(body, `<svg class="chart"`) != 3 || strings.Contains(body, "No data in this period") {
		t.Fatalf("three charts with data expected: %s", body)
	}
	for _, want := range []string{">CPU<", ">Memory<", ">Disk<", "max 29%", `data-points="[[`, "limit 90%", "limit 85%",
		`<button type="button" aria-pressed="true" hx-get="/hosts/1/charts?range=1h"`} {
		if !strings.Contains(body, want) {
			t.Errorf("charts fragment is missing %q", want)
		}
	}
	body = h.do("GET", "/hosts/1/charts?range=7d", c, nil, true).Body.String()
	if !strings.Contains(body, `aria-pressed="true" hx-get="/hosts/1/charts?range=7d"`) {
		t.Error("the chosen range must be marked")
	}
	body = h.do("GET", "/hosts/1/charts?range=bogus", c, nil, true).Body.String()
	if !strings.Contains(body, `aria-pressed="true" hx-get="/hosts/1/charts?range=1h"`) {
		t.Error("an unknown range falls back to 1 hour")
	}
	if w := h.do("GET", "/hosts/999/charts", c, nil, true); w.Code != http.StatusNotFound {
		t.Errorf("charts of an unknown host: %d, want 404", w.Code)
	}
}

func TestTilesShowTrendOnlyWithHistory(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web-01")
	c := h.login()
	if body := h.do("GET", "/", c, nil, false).Body.String(); strings.Contains(body, `class="spark"`) {
		t.Error("no trend line without history")
	}
	for i := int64(0); i < 10; i++ {
		v := float64(10 + i)
		h.st.QueueMetric(store.MetricPoint{HostID: id, TS: h.clock.Unix() - 1800 + i*60, CPU: &v, Mem: &v, Disk: &v})
	}
	h.st.FlushMetrics(context.Background())
	h.clock = h.clock.Add(16 * time.Second) // trend lines are cached for 15 seconds
	if body := h.do("GET", "/", c, nil, false).Body.String(); strings.Count(body, `class="spark"`) != 3 {
		t.Errorf("CPU, RAM and Disk tiles each get a trend line, found %d", strings.Count(body, `class="spark"`))
	}
}

func TestDetailEventOnlyForWatchedHost(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	watched := h.addRichHost("web-01")
	other := h.addHost("web-02")
	srv := httptest.NewServer(h.mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events?host=1", nil)
	req.AddCookie(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var names []string
	read := func(n int) {
		for len(names) < n && sc.Scan() {
			if name, ok := strings.CutPrefix(sc.Text(), "event: "); ok {
				names = append(names, name)
			}
		}
	}
	if !sc.Scan() || sc.Text() != ": connected" {
		t.Fatalf("first line = %q", sc.Text())
	}
	h.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: other})
	h.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: watched})
	read(7)
	want := "host-2 summary statusline host-1 summary statusline detail"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("events = %q, want %q (the detail block only for the watched host)", got, want)
	}
}

func TestMenuOnEveryPageWithCounts(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web-01")
	h.addHost("web-02")
	ctx := context.Background()
	h.st.CreateAlert(ctx, id, "cpu_high", "", "CPU 95%", h.clock, true)
	h.st.CreateAlert(ctx, id, "ram_high", "", "memory 95%", h.clock, false)
	c := h.login()
	for path, page := range map[string]string{"/": "hosts", "/hosts/1": "hosts", "/alerts": "alerts", "/logs": "logs", "/settings": "settings"} {
		w := h.do("GET", path, c, nil, false)
		body := w.Body.String()
		if w.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, w.Code)
			continue
		}
		for _, want := range []string{`data-page="` + page + `"`, `<nav id="nav" class="side"`, `sse-swap="nav"`,
			`<a href="/" data-nav="hosts">Hosts<span class="count">2</span></a>`,
			`<a href="/alerts" data-nav="alerts">Alerts<span class="count bad">1</span></a>`,
			`<a href="/logs" data-nav="logs">Logs</a>`,
			`<a href="/settings" data-nav="settings">Settings</a>`, `fleetwatch@hub.example.com:~$`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q", path, want)
			}
		}
	}
	for _, path := range []string{"/alerts", "/logs", "/logs.txt", "/settings"} {
		if w := h.do("GET", path, nil, nil, false); w.Code != http.StatusSeeOther {
			t.Errorf("%s without session: %d", path, w.Code)
		}
	}
}

func TestAlertsPageAndDismiss(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web<x>")
	ctx := context.Background()
	firing, _ := h.st.CreateAlert(ctx, id, "service_failed", "db.service", "db.service failed", h.clock.Add(-10*time.Minute), true)
	h.st.CreateAlert(ctx, id, "cpu_high", "", "CPU 95%", h.clock, false)
	old, _ := h.st.CreateAlert(ctx, id, "disk_full", "/data", "/data 91%", h.clock.Add(-time.Hour), true)
	h.st.ResolveAlert(ctx, old, h.clock.Add(-30*time.Minute))
	c := h.login()
	body := h.do("GET", "/alerts", c, nil, false).Body.String()
	for _, want := range []string{"Service failed", "db.service failed", `data-state="firing"`, "CPU high", `data-state="pending"`, "Disk full", `data-state="resolved"`,
		`<a href="/hosts/1">web&lt;x&gt;</a>`, `action="/alerts/` + strconv.FormatInt(firing, 10) + `/dismiss"`} {
		if !strings.Contains(body, want) {
			t.Errorf("alerts page is missing %q", want)
		}
	}
	if strings.Count(body, "/dismiss") != 1 {
		t.Error("only a firing alert can be dismissed")
	}
	if w := h.do("POST", "/alerts/"+strconv.FormatInt(firing, 10)+"/dismiss", nil, nil, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("dismiss without session: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := h.do("POST", "/alerts/"+strconv.FormatInt(firing, 10)+"/dismiss", c, nil, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/alerts" {
		t.Errorf("dismiss: %d %q", w.Code, w.Header().Get("Location"))
	}
	body = h.do("GET", "/alerts", c, nil, false).Body.String()
	if !strings.Contains(body, `data-state="dismissed"`) || strings.Contains(body, "/dismiss\"") {
		t.Error("after dismissing, the alert shows as dismissed and offers no button")
	}
	empty := newHarness(t, "https://hub.example.com", false)
	if body := empty.do("GET", "/alerts", empty.login(), nil, false).Body.String(); !strings.Contains(body, "No alerts") {
		t.Error("an empty alerts page must say so")
	}
}

func TestAlertDetailPage(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addRichHost("web<x>")
	ctx := context.Background()
	firing, _ := h.st.CreateAlert(ctx, id, "service_failed", "db.service", "db.service failed", h.clock.Add(-10*time.Minute), true)
	h.st.MarkNotified(ctx, firing, "firing")
	old, _ := h.st.CreateAlert(ctx, id, "disk_full", "/data", "/data 91%", h.clock.Add(-2*time.Hour), true)
	h.st.MarkNotified(ctx, old, "firing")
	h.st.ResolveAlert(ctx, old, h.clock.Add(-30*time.Minute))
	quiet, _ := h.st.CreateAlert(ctx, id, "cpu_high", "", "CPU 95%", h.clock.Add(-time.Hour), true)
	h.st.ResolveAlert(ctx, quiet, h.clock.Add(-50*time.Minute))
	c := h.login()
	if w := h.do("GET", "/alerts/"+strconv.FormatInt(firing, 10), nil, nil, false); w.Code != http.StatusSeeOther {
		t.Errorf("alert page without session: %d", w.Code)
	}
	list := h.do("GET", "/alerts", c, nil, false).Body.String()
	if !strings.Contains(list, `<tr data-href="/alerts/`+strconv.FormatInt(firing, 10)+`">`) || !strings.Contains(list, `<a href="/alerts/`+strconv.FormatInt(firing, 10)+`"><b>Service failed</b>`) {
		t.Error("each row of the list must open the alert's page")
	}
	body := h.do("GET", "/alerts/"+strconv.FormatInt(firing, 10), c, nil, false).Body.String()
	for _, want := range []string{`data-state="firing"`, `<a href="/hosts/1">web&lt;x&gt;</a>`, "Service failed", "db.service failed", "<dt>Lasting</dt><dd>10m</dd>",
		"<td>Firing</td><td>sent</td>", "<td>Resolved</td><td>not yet: the problem is still there</td>", `action="/alerts/` + strconv.FormatInt(firing, 10) + `/dismiss"`, `<title>web&lt;x&gt;: Service failed`} {
		if !strings.Contains(body, want) {
			t.Errorf("alert page is missing %q", want)
		}
	}
	body = h.do("GET", "/alerts/"+strconv.FormatInt(old, 10), c, nil, false).Body.String()
	for _, want := range []string{`data-state="resolved"`, "<dt>Lasted</dt><dd>1h 30m</dd>", "<dt>Ended</dt><dd data-time=", "<td>Resolved</td><td>being sent</td>"} {
		if !strings.Contains(body, want) {
			t.Errorf("resolved alert page is missing %q", want)
		}
	}
	if strings.Contains(body, "/dismiss") {
		t.Error("a resolved alert cannot be dismissed")
	}
	body = h.do("GET", "/alerts/"+strconv.FormatInt(quiet, 10), c, nil, false).Body.String()
	if !strings.Contains(body, "<td>Firing</td><td>none: it ended before the message went out</td>") || !strings.Contains(body, "<td>Resolved</td><td>none</td>") {
		t.Error("an alert that ended before its message went out says so")
	}
	if w := h.do("GET", "/alerts/999", c, nil, false); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "No such alert") {
		t.Errorf("unknown alert: %d %s", w.Code, w.Body)
	}
}

func TestSettingsPage(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	ctx := context.Background()
	body := h.do("GET", "/settings", c, nil, false).Body.String()
	for _, want := range []string{`name="offline_after_s" value="60"`, `name="cpu_for_min" value="5"`, `name="ram_for_min" value="5"`, `name="disk_for_min" value="2"`, `name="webhook_url" value=""`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page is missing %q", want)
		}
	}
	form := url.Values{"webhook_url": {"https://hooks.example.com/x"}, "telegram_token": {"123:secret"}, "telegram_chat_id": {"-100"},
		"offline_after_s": {"120"}, "cpu_for_min": {"10"}, "ram_for_min": {"0"}, "disk_for_min": {"3"}}
	if w := h.do("POST", "/settings", c, form, false); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	got, _ := h.st.Settings(ctx)
	if got["webhook_url"] != "https://hooks.example.com/x" || got["telegram_token"] != "123:secret" || got["offline_after_s"] != "120" || got["ram_for_min"] != "0" {
		t.Errorf("stored settings = %v", got)
	}
	body = h.do("GET", "/settings", c, nil, false).Body.String()
	if strings.Contains(body, "123:secret") || !strings.Contains(body, "A token is stored") {
		t.Error("the stored Telegram token must never be shown again, only that one exists")
	}
	// A webhook URL often carries a secret in its path, so only its host is shown.
	if strings.Contains(body, "hooks.example.com/x") || !strings.Contains(body, "Stored: hooks.example.com") || !strings.Contains(body, "hooks.example.com") || !strings.Contains(body, `name="webhook_url" value=""`) {
		t.Error("the stored webhook URL must not be shown again, only its host")
	}
	form.Set("webhook_url", "")
	h.do("POST", "/settings", c, form, false)
	if got, _ := h.st.Settings(ctx); got["webhook_url"] != "https://hooks.example.com/x" {
		t.Errorf("an empty webhook field must keep the stored URL, got %q", got["webhook_url"])
	}
	form.Set("clear_webhook_url", "1")
	h.do("POST", "/settings", c, form, false)
	if got, _ := h.st.Settings(ctx); got["webhook_url"] != "" {
		t.Errorf("the clear box must remove the webhook, got %q", got["webhook_url"])
	}
	form.Del("clear_webhook_url")
	// An empty token field keeps the stored token.
	form.Set("telegram_token", "")
	h.do("POST", "/settings", c, form, false)
	if got, _ := h.st.Settings(ctx); got["telegram_token"] != "123:secret" {
		t.Errorf("an empty token field must keep the stored token, got %q", got["telegram_token"])
	}
	form.Set("clear_telegram_token", "1")
	h.do("POST", "/settings", c, form, false)
	if got, _ := h.st.Settings(ctx); got["telegram_token"] != "" {
		t.Errorf("the clear box must remove the token, got %q", got["telegram_token"])
	}
	for field, bad := range map[string]string{"webhook_url": "ftp://x", "offline_after_s": "5", "cpu_for_min": "-1", "disk_for_min": "abc"} {
		f := url.Values{"webhook_url": {""}, "offline_after_s": {"60"}, "cpu_for_min": {"5"}, "ram_for_min": {"5"}, "disk_for_min": {"2"}}
		f.Set(field, bad)
		w := h.do("POST", "/settings", c, f, false)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `class="error"`) {
			t.Errorf("%s=%q: status %d, want 422 with an error message", field, bad, w.Code)
		}
	}
	if got, _ := h.st.Settings(ctx); got["offline_after_s"] != "120" {
		t.Errorf("a rejected form must not change stored settings: %v", got)
	}
}

func TestSettingsTestButton(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	if body := h.do("POST", "/settings/test", c, nil, true).Body.String(); !strings.Contains(body, "No notification target is configured") {
		t.Errorf("no targets: %s", body)
	}
	var got []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/bot") {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer target.Close()
	h.web.telegramBase = target.URL
	h.st.SetSettings(context.Background(), map[string]string{"webhook_url": target.URL + "/hook", "telegram_token": "1:a", "telegram_chat_id": "9"})
	body := h.do("POST", "/settings/test", c, nil, true).Body.String()
	if !strings.Contains(body, "Webhook: delivered") || !strings.Contains(body, "Telegram: failed") || !strings.Contains(body, "403") {
		t.Errorf("test result = %s", body)
	}
	if len(got) != 2 || got[0] != "/hook" || got[1] != "/bot1:a/sendMessage" {
		t.Errorf("requests = %v", got)
	}
}

func TestWriteSSEPrefixesEveryLine(t *testing.T) {
	var b strings.Builder
	writeSSE(&b, "host-1", "<td>a</td>\n<td>b</td>\n")
	if b.String() != "event: host-1\ndata: <td>a</td>\ndata: <td>b</td>\n\n" {
		t.Errorf("frame = %q", b.String())
	}
}

func TestEventsStreamOutlivesServerReadTimeout(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	id := h.addHost("web-01")
	srv := httptest.NewUnstartedServer(h.mux)
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
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
	if !sc.Scan() || sc.Text() != ": connected" {
		t.Fatalf("first line = %q", sc.Text())
	}
	time.Sleep(900 * time.Millisecond)
	h.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: id})
	for sc.Scan() {
		if sc.Text() == "event: host-1" {
			return
		}
	}
	t.Fatalf("the stream was closed by the server's read timeout before the event arrived: %v", sc.Err())
}

func TestEventsStream(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	id := h.addHost("web-01")
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
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	sc := bufio.NewScanner(resp.Body)
	next := func() (event, data string) {
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = line[7:]
			case strings.HasPrefix(line, "data: "):
				data += line[6:]
			case line == "" && event != "":
				return event, data
			}
		}
		t.Fatalf("stream ended before an event arrived: %v", sc.Err())
		return "", ""
	}
	// The handler subscribes before it writes the first comment line.
	if !sc.Scan() || sc.Text() != ": connected" {
		t.Fatalf("first line = %q", sc.Text())
	}

	h.bus.Publish(live.Event{Kind: live.HostAdded, HostID: id})
	if ev, data := next(); ev != "host-new" || !strings.Contains(data, `<tr id="host-1" sse-swap="host-1" hx-swap="innerHTML">`) {
		t.Errorf("event %q data %q", ev, data)
	}
	if ev, data := next(); ev != "summary" || !strings.Contains(data, `<span class="ok">1 online</span>`) || !strings.Contains(data, "CPU (avg)") {
		t.Errorf("event %q data %q", ev, data)
	}
	if ev, data := next(); ev != "statusline" || !strings.Contains(data, `<span>1 host</span><span>1 online</span><span>0 offline</span>`) {
		t.Errorf("event %q data %q", ev, data)
	}
	if ev, data := next(); ev != "nav" || !strings.Contains(data, `href="/alerts"`) {
		t.Errorf("event %q data %q", ev, data)
	}
	h.bus.Publish(live.Event{Kind: live.AlertsChanged})
	if ev, _ := next(); ev != "nav" {
		t.Errorf("a change of alerts refreshes the menu only, got %q", ev)
	}
	h.bus.Publish(live.Event{Kind: live.HostRemoved, HostID: 7})
	if ev, data := next(); ev != "host-removed" || data != "7" {
		t.Errorf("a removed host: event %q data %q", ev, data)
	}
	for _, want := range []string{"summary", "statusline", "nav"} {
		if ev, _ := next(); ev != want {
			t.Errorf("after a removal: event %q, want %q", ev, want)
		}
	}
	h.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: id})
	if ev, data := next(); ev != "host-1" || !strings.HasPrefix(data, `<td class="host" data-v="web-01"><a href="/hosts/1">web-01</a></td>`) || strings.Contains(data, "<tr") {
		t.Errorf("a row update carries the cells only: event %q data %q", ev, data)
	}
}

func TestLogoOnEveryPageAndAsIcon(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	for _, path := range []string{"/login", "/", "/alerts", "/settings"} {
		body := h.do("GET", path, c, nil, false).Body.String()
		for _, want := range []string{`<link rel="icon" href="/static/logo.svg" type="image/svg+xml">`, `<svg class="logo"`, `<span class="wm">Fleet<b>Watch</b></span>`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q", path, want)
			}
		}
	}
	w := h.do("GET", "/static/logo.svg", nil, nil, false)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "image/svg+xml") || !strings.Contains(w.Body.String(), "<svg") {
		t.Errorf("logo.svg: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestRenameHost(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	id := h.addHost("pve")
	c := h.login()
	page := "/hosts/" + strconv.FormatInt(id, 10)
	if body := h.do("GET", page, c, nil, false).Body.String(); !strings.Contains(body, `action="`+page+`/label"`) || !strings.Contains(body, `placeholder="pve"`) {
		t.Error("host page must offer a name form with the hostname as placeholder")
	}
	if w := h.do("POST", page+"/label", nil, url.Values{"label": {"x"}}, false); w.Header().Get("Location") != "/login" {
		t.Error("renaming needs a session")
	}
	if w := h.do("POST", page+"/label", c, url.Values{"label": {strings.Repeat("a", 65)}}, false); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("a 65-character name: status %d, want 422", w.Code)
	}
	events, cancel := h.bus.Subscribe()
	defer cancel()
	if w := h.do("POST", page+"/label", c, url.Values{"label": {"  pve-office  "}}, false); w.Code != http.StatusSeeOther || w.Header().Get("Location") != page {
		t.Fatalf("rename: %d %q", w.Code, w.Header().Get("Location"))
	}
	if ev := <-events; ev.Kind != live.HostUpdated || ev.HostID != id {
		t.Errorf("rename must publish an update of the host: %+v", ev)
	}
	if body := h.do("GET", page, c, nil, false).Body.String(); !strings.Contains(body, `<span class="crumb">pve-office</span>`) || !strings.Contains(body, `value="pve-office"`) {
		t.Error("host page must show the new name")
	}
	list := h.do("GET", "/", c, nil, false).Body.String()
	if !strings.Contains(list, `data-v="pve-office"><a href="`+page+`">pve-office</a><small class="hostname">pve</small>`) {
		t.Error("the list must show the name with the hostname under it")
	}
	if !strings.Contains(h.logs.Text(), "server pve renamed to pve-office") {
		t.Error("rename must be logged")
	}
	h.do("POST", page+"/label", c, url.Values{"label": {""}}, false)
	if list := h.do("GET", "/", c, nil, false).Body.String(); strings.Contains(list, `class="hostname"`) {
		t.Error("without a name the list shows only the hostname")
	}
}

func TestInstallableAsAnApp(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	c := h.login()
	for _, path := range []string{"/login", "/", "/alerts", "/logs", "/settings"} {
		body := h.do("GET", path, c, nil, false).Body.String()
		for _, want := range []string{`<link rel="manifest" href="/static/manifest.webmanifest">`, `<meta name="theme-color" content="#0b0e12">`, `<link rel="apple-touch-icon" href="/static/icon-180.png">`, `viewport-fit=cover`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s is missing %q", path, want)
			}
		}
	}
	w := h.do("GET", "/static/manifest.webmanifest", nil, nil, false)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/manifest+json" {
		t.Fatalf("manifest: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	var m struct {
		Name            string `json:"name"`
		StartURL        string `json:"start_url"`
		Display         string `json:"display"`
		ThemeColor      string `json:"theme_color"`
		BackgroundColor string `json:"background_color"`
		Icons           []struct{ Src, Sizes, Type, Purpose string }
	}
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != "FleetWatch" || m.StartURL != "/" || m.Display != "standalone" || m.ThemeColor != "#0b0e12" || m.BackgroundColor != "#0b0e12" {
		t.Errorf("manifest = %+v", m)
	}
	want := map[string]bool{"192x192 any": false, "512x512 any": false, "512x512 maskable": false}
	for _, i := range m.Icons {
		key := i.Sizes + " " + i.Purpose
		if _, ok := want[key]; ok && i.Type == "image/png" {
			want[key] = true
		}
		if r := h.do("GET", i.Src, nil, nil, false); r.Code != http.StatusOK || r.Header().Get("Content-Type") != "image/png" {
			t.Errorf("icon %s: %d %q", i.Src, r.Code, r.Header().Get("Content-Type"))
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("manifest has no %s PNG icon", k)
		}
	}
	if r := h.do("GET", "/static/icon-180.png", nil, nil, false); r.Code != http.StatusOK {
		t.Errorf("apple-touch-icon: %d", r.Code)
	}
}
