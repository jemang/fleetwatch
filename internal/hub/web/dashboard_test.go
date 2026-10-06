package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
)

func TestDashboardEmpty(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	rec := h.do("GET", "/", h.login(), nil, false)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	for _, want := range []string{`data-page="dashboard"`, `Nothing needs attention.`, `hx-get="/services/new"`, `hx-post="/servers/enroll-token"`,
		`id="search"`, `hx-get="/search"`, `hx-get="/dashboard/panel"`, `id="summary"`, `No incidents yet.`} {
		if !strings.Contains(body, want) {
			t.Errorf("empty dashboard is missing %q", want)
		}
	}
}

func TestDashboardCountsAndAttention(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	host := h.addRichHost("pve-2")
	save := func(id int64, url string, c store.CheckState) {
		t.Helper()
		c.CheckedAt = h.clock.Unix()
		if err := h.st.SaveCheck(ctx, id, url, c); err != nil {
			t.Fatal(err)
		}
	}
	on := h.addService("Grafana", "https://grafana.lan", "")
	save(on, "https://grafana.lan", store.CheckState{State: "online", OK: true, Ms: 40})
	slow := h.addService("HN", "https://hn.lan", "")
	save(slow, "https://hn.lan", store.CheckState{State: "degraded", OK: true, Ms: 1842})
	down := h.addService("Portal", "https://portal.lan/?token=SECRET", "")
	save(down, "https://portal.lan/?token=SECRET", store.CheckState{State: "down", Since: h.clock.Unix() - 480, Error: "timeout"})
	paused := h.addService("Old", "https://old.lan", "")
	h.st.SetServiceEnabled(ctx, paused, false)
	under, _ := h.st.CreateService(ctx, store.Service{Name: "Proxmox", URL: "https://pve.lan", HostID: host, IntervalS: 60, TimeoutS: 10, Enabled: true}, h.clock)
	save(under, "https://pve.lan", store.CheckState{State: "down", Since: h.clock.Unix(), Error: "timeout"})
	cert := h.addService("Wiki", "https://wiki.lan", "")
	h.st.CreateServiceAlert(ctx, cert, "svc_cert", "30@1", "28 days, 3 Nov 2026", h.clock, true)
	h.clock = h.clock.Add(2 * time.Minute) // pve-2 stops reporting

	body := h.do("GET", "/", h.login(), nil, false).Body.String()
	if strings.Contains(stripTags(body), "SECRET") {
		t.Error("the dashboard shows a URL query")
	}
	att := body[strings.Index(body, `class="attention"`):]
	order := []string{"[OFFLINE]", "1 service unavailable because host pve-2 is offline", ">Proxmox<", "[DOWN]", ">Portal<", "timeout", "[ALERT]", "Certificate expiring", "Wiki", "[SLOW]", ">HN<", "1,842 ms response time"}
	last := -1
	for _, s := range order {
		i := strings.Index(att, s)
		if i <= last {
			t.Fatalf("attention order: %q at %d (after %d)\n%s", s, i, last, stripTags(att))
		}
		last = i
	}
	if strings.Count(att, "[DOWN]") != 1 {
		t.Error("a service under an offline host is listed under the host, not again as DOWN")
	}
	for _, want := range []string{`data-tile="total"><div class="label">Services · 1 paused · 1 not checked</div><div class="value">6<`,
		`data-tile="online"><div class="label">Online</div><div class="value">2<`,
		`data-tile="down"><div class="label">Down</div><div class="value">2<`,
		`data-tile="slow"><div class="label">Slow</div><div class="value">1<`} {
		if !strings.Contains(body, want) {
			t.Errorf("tiles are missing %q", want)
		}
	}
}

func TestDashboardRecentIncidents(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	id := h.addService("Portal", "https://portal.lan", "")
	h.st.SaveCheck(ctx, id, "https://portal.lan", store.CheckState{State: "down", Since: h.clock.Unix() - 60, CheckedAt: h.clock.Unix(), Error: "timeout"})
	body := h.do("GET", "/dashboard/panel", h.login(), nil, true).Body.String()
	if strings.Contains(body, "<html") {
		t.Fatal("panel must be a fragment")
	}
	inc := body[strings.Index(body, "Recent incidents"):]
	for _, want := range []string{`href="/services/` + itoa(id) + `"`, ">Portal<", "ongoing", "timeout"} {
		if !strings.Contains(inc, want) {
			t.Errorf("recent incidents are missing %q", want)
		}
	}
}

func TestHostListMovedToHosts(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	h.addHost("web-01")
	c := h.login()
	list := h.do("GET", "/hosts", c, nil, false).Body.String()
	if !strings.Contains(list, `id="host-rows"`) || !strings.Contains(list, "web-01") || !strings.Contains(list, `data-page="hosts"`) {
		t.Fatal("/hosts must be the host list")
	}
	nav := list[strings.Index(list, `<nav id="nav"`):]
	last := -1
	for _, s := range []string{`href="/" data-nav="dashboard"`, `href="/services" data-nav="services"`, `href="/hosts" data-nav="hosts"`, `href="/alerts"`, `href="/logs"`, `href="/settings"`} {
		i := strings.Index(nav, s)
		if i <= last {
			t.Fatalf("menu order: %q at %d", s, i)
		}
		last = i
	}
	id := h.addHost("web-02")
	page := h.do("GET", "/hosts/"+itoa(id), c, nil, false).Body.String()
	if !strings.Contains(page, `<a class="button" href="/hosts">All hosts</a>`) {
		t.Error("the host page's All hosts button must go to /hosts")
	}
}

func TestSearchServicesAndHosts(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	host := h.addHost("proxy-01")
	id := h.addService("Grafana", "https://grafana.lan/x?token=SECRET", "Infrastructure")
	h.addService("<b>x</b>", "https://x.lan", "")
	c := h.login()
	body := h.do("GET", "/search?q=graf", c, nil, true).Body.String()
	if !strings.Contains(body, "<h3>Services</h3>") || !strings.Contains(body, `href="/services/`+itoa(id)+`"`) || !strings.Contains(body, "grafana.lan") || strings.Contains(body, "SECRET") || strings.Contains(body, "<h3>Hosts</h3>") {
		t.Errorf("search graf: %s", body)
	}
	if body := h.do("GET", "/search?q=10.0.0", c, nil, true).Body.String(); !strings.Contains(body, `href="/hosts/`+itoa(host)+`"`) || !strings.Contains(body, "proxy-01") {
		t.Errorf("search by IP: %s", body)
	}
	if body := h.do("GET", "/search?q=PROXY", c, nil, true).Body.String(); !strings.Contains(body, "proxy-01") {
		t.Errorf("search ignores case: %s", body)
	}
	if body := h.do("GET", "/search?q=x", c, nil, true).Body.String(); strings.Contains(body, "<b>x</b>") {
		t.Errorf("names must be escaped: %s", body)
	}
	if body := strings.TrimSpace(h.do("GET", "/search?q=", c, nil, true).Body.String()); body != "" {
		t.Errorf("empty query shows %q", body)
	}
	if body := h.do("GET", "/search?q=token", c, nil, true).Body.String(); strings.Contains(body, "Grafana") {
		t.Error("the URL query is not searched")
	}
}

func TestHostPageListsItsServices(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	host := h.addHost("pve-2")
	bare := h.addHost("bare")
	a, _ := h.st.CreateService(ctx, store.Service{Name: "Proxmox", URL: "https://pve.lan", HostID: host, IntervalS: 60, TimeoutS: 10, Enabled: true}, h.clock)
	h.st.SaveCheck(ctx, a, "https://pve.lan", store.CheckState{State: "online", OK: true, Ms: 68, CheckedAt: h.clock.Unix()})
	b, _ := h.st.CreateService(ctx, store.Service{Name: "Grafana", URL: "https://graf.lan", HostID: host, IntervalS: 60, TimeoutS: 10, Enabled: true}, h.clock)
	h.st.SaveCheck(ctx, b, "https://graf.lan", store.CheckState{State: "down", Since: h.clock.Unix(), CheckedAt: h.clock.Unix(), Error: "timeout"})
	c := h.login()
	page := h.do("GET", "/hosts/"+itoa(host), c, nil, false).Body.String()
	for _, want := range []string{"<h2>Services on this host</h2>", `href="/services/` + itoa(a) + `"`, "68 ms", `href="/services/` + itoa(b) + `"`, "<b>DOWN</b>",
		`hx-get="/hosts/` + itoa(host) + `/services"`} {
		if !strings.Contains(page, want) {
			t.Errorf("host page is missing %q", want)
		}
	}
	if strings.Index(page, ">Grafana<") > strings.Index(page, ">Proxmox<") {
		t.Error("services are listed by name")
	}
	if p := h.do("GET", "/hosts/"+itoa(bare), c, nil, false).Body.String(); strings.Contains(p, "Services on this host") {
		t.Error("a host without services shows no services heading")
	}
	frag := h.do("GET", "/hosts/"+itoa(host)+"/services", c, nil, true).Body.String()
	if strings.Contains(frag, "<html") || !strings.Contains(frag, ">Proxmox<") {
		t.Errorf("services fragment: %.200s", frag)
	}
	h.clock = h.clock.Add(2 * time.Minute)
	svc := h.do("GET", "/services/"+itoa(a), c, nil, false).Body.String()
	if !strings.Contains(svc, `pve-2</a> <span class="offline">· offline</span>`) {
		t.Error("the service page marks an offline host")
	}
}

func TestDashboardPanelRedrawIsBounded(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	body := h.do("GET", "/", h.login(), nil, false).Body.String()
	for _, want := range []string{`sse:summary throttle:10s`, `hx-sync="this:replace"`} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard is missing %q: host reports arrive every few seconds", want)
		}
	}
}

// A slow service whose host is offline is not listed as [SLOW]: its host's
// outage is the news. An incident ended by a pause says so.
func TestDashboardSlowUnderOfflineHostAndPausedIncident(t *testing.T) {
	h := newHarness(t, "https://hub.example.com", false)
	ctx := context.Background()
	host := h.addRichHost("pve-2")
	id, _ := h.st.CreateService(ctx, store.Service{Name: "Proxmox", URL: "https://pve.lan", HostID: host, IntervalS: 60, TimeoutS: 10, Enabled: true}, h.clock)
	h.st.SaveCheck(ctx, id, "https://pve.lan", store.CheckState{State: "degraded", OK: true, Ms: 1500, CheckedAt: h.clock.Unix()})
	p := h.addService("Portal", "https://portal.lan", "")
	h.st.SaveCheck(ctx, p, "https://portal.lan", store.CheckState{State: "down", Since: h.clock.Unix() - 60, CheckedAt: h.clock.Unix(), Error: "timeout"})
	h.st.SetServiceEnabled(ctx, p, false)
	h.clock = h.clock.Add(2 * time.Minute) // pve-2 stops reporting
	body := h.do("GET", "/dashboard/panel", h.login(), nil, true).Body.String()
	if strings.Contains(body, "[SLOW]") {
		t.Error("a slow service under an offline host is listed as [SLOW]")
	}
	if !strings.Contains(body, `timeout <span class="muted">· ended: paused</span>`) {
		t.Errorf("incident end reason missing: %s", body[strings.Index(body, "Recent incidents"):])
	}
}
