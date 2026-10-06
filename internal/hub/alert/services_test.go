package alert

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

func svcConds(conds []ServiceCondition) string {
	var out []string
	for _, c := range conds {
		out = append(out, strconv.FormatInt(c.ServiceID, 10)+":"+c.Kind+":"+c.Subject+":"+c.Detail)
	}
	return strings.Join(out, " | ")
}

func TestServiceRulesFrom(t *testing.T) {
	r := ServiceRulesFrom(nil)
	if !reflect.DeepEqual(r.CertDays, []int{30, 14, 7, 1}) || r.SlowAlert || r.SlowFor != 5*time.Minute {
		t.Fatalf("defaults = %+v", r)
	}
	r = ServiceRulesFrom(map[string]string{"svc_cert_days": "60, 7", "svc_slow_alert": "1"})
	if !reflect.DeepEqual(r.CertDays, []int{60, 7}) || !r.SlowAlert {
		t.Fatalf("from settings = %+v", r)
	}
	if r := ServiceRulesFrom(map[string]string{"svc_cert_days": "7, 14"}); !reflect.DeepEqual(r.CertDays, []int{30, 14, 7, 1}) {
		t.Fatalf("an unreadable list keeps the default: %+v", r.CertDays)
	}
	for in, ok := range map[string]bool{"30, 14, 7, 1": true, "30,14": true, "1": true, "": false, "0": false, "366": false, "14, 14": false, "7, 14": false, "a": false, "30,14,7,5,3,2,1": false} {
		if _, got := ParseCertDays(in); got != ok {
			t.Errorf("ParseCertDays(%q) ok = %v; want %v", in, got, ok)
		}
	}
}

func TestEvaluateServices(t *testing.T) {
	now := t0
	day := int64(86400)
	exp := func(days int64) int64 { return now.Unix() + days*day + 60 }
	list := []store.Service{
		{ID: 1, URL: "https://a", Enabled: true, State: "down", LastError: "timeout"},
		{ID: 2, URL: "https://b", Enabled: true, State: "degraded", LastMs: 1842},
		{ID: 3, URL: "https://c", Enabled: true, State: "online", CertExpiresAt: exp(20)},
		{ID: 4, URL: "https://d", Enabled: true, State: "online", CertExpiresAt: exp(31)},
		{ID: 5, URL: "https://e", Enabled: true, State: "online", CertExpiresAt: now.Unix() - 3600},
		{ID: 6, URL: "http://f", Enabled: true, State: "online", CertExpiresAt: exp(2)},
		{ID: 7, URL: "https://g", Enabled: false, State: "paused", CertExpiresAt: exp(2)},
		{ID: 8, URL: "https://h", Enabled: true, State: "online", CertExpiresAt: exp(0)},
		{ID: 9, URL: "https://i", Enabled: true, State: "online", CertExpiresAt: exp(1)},
	}
	r := ServiceRulesFrom(nil)
	date := func(ts int64) string { return time.Unix(ts, 0).Format("2 Jan 2006") }
	itoa := func(n int64) string { return strconv.FormatInt(n, 10) }
	want := "1:svc_down::timeout" +
		" | 3:svc_cert:30@" + itoa(exp(20)) + ":20 days, " + date(exp(20)) +
		" | 5:svc_cert:expired@" + itoa(now.Unix()-3600) + ":expired " + date(now.Unix()-3600) +
		" | 8:svc_cert:1@" + itoa(exp(0)) + ":less than a day, " + date(exp(0)) +
		" | 9:svc_cert:1@" + itoa(exp(1)) + ":1 day, " + date(exp(1))
	if got := svcConds(EvaluateServices(list, now, r, nil)); got != want {
		t.Fatalf("conditions =\n%s\nwant\n%s", got, want)
	}
	r.SlowAlert = true
	conds := EvaluateServices(list[1:2], now, r, nil)
	if len(conds) != 1 || conds[0].Kind != KindSvcSlow || conds[0].Detail != "1,842 ms" || conds[0].For != 5*time.Minute {
		t.Fatalf("slow condition = %+v", conds)
	}
	if certExpiry("14@1795000000") != 1795000000 || certExpiry("junk") != 0 {
		t.Error("certExpiry must read the expiry from the subject")
	}
}

func TestServiceMessage(t *testing.T) {
	m := Message{Event: "firing", Service: "Grafana", ServiceHost: "grafana.lan", Host: "pve-2", Kind: KindSvcDown, Detail: "timeout",
		Since: t0, At: t0, Hub: "hub.example.com", Zone: time.UTC}
	want := "[FleetWatch] Firing\nService: Grafana (grafana.lan)\nHost: pve-2\nAlert: Service DOWN (timeout)\nSince: 2026-09-21 14:13 UTC\nHub: hub.example.com"
	if m.Text() != want {
		t.Errorf("firing text = %q", m.Text())
	}
	m.Event, m.At, m.Host = "resolved", t0.Add(time.Minute), ""
	want = "[FleetWatch] Resolved\nService: Grafana (grafana.lan)\nAlert: Service recovered\nSince: 2026-09-21 14:13 UTC\nEnded: 2026-09-21 14:14 UTC (after 1m)\nHub: hub.example.com"
	if m.Text() != want {
		t.Errorf("resolved text = %q", m.Text())
	}
	c := Message{Event: "resolved", Service: "Proxmox", ServiceHost: "labs.example.com", Kind: KindSvcCert, Detail: "14 days, 22 Nov 2026", Since: t0, At: t0, Hub: "h", Zone: time.UTC}
	if !strings.Contains(c.Text(), "Alert: Certificate renewed\n") {
		t.Errorf("certificate resolved text = %q", c.Text())
	}
}

func (w *world) service(name, url string) int64 {
	w.t.Helper()
	id, err := w.st.CreateService(context.Background(), store.Service{Name: name, URL: url, IntervalS: 60, TimeoutS: 10, Enabled: true}, w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

func (w *world) check(id int64, url string, c store.CheckState) {
	w.t.Helper()
	c.CheckedAt = w.now.Unix()
	if err := w.st.SaveCheck(context.Background(), id, url, c); err != nil {
		w.t.Fatal(err)
	}
}

func TestEngineServiceDownAndRecovered(t *testing.T) {
	w := newWorld(t)
	id := w.service("Grafana", "https://grafana.lan/?token=x")
	w.check(id, "https://grafana.lan/?token=x", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(0)
	if w.states() != "svc_down=firing" || strings.Join(w.sent, ";") != "firing  svc_down  Grafana grafana.lan" {
		t.Fatalf("down: states %q sent %q", w.states(), w.sent)
	}
	w.check(id, "https://grafana.lan/?token=x", store.CheckState{State: "online", OK: true, Since: w.now.Unix()})
	w.tick(15 * time.Second)
	if w.states() != "svc_down=resolved" || len(w.sent) != 2 || !strings.HasPrefix(w.sent[1], "resolved") {
		t.Fatalf("recovered: states %q sent %q", w.states(), w.sent)
	}
	for _, l := range w.logged {
		if strings.Contains(l, "token") {
			t.Errorf("log line shows the URL query: %q", l)
		}
	}
}

func TestEngineServicePausedOrReaddressedEndsQuietly(t *testing.T) {
	w := newWorld(t)
	id := w.service("A", "https://a.lan")
	w.check(id, "https://a.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(0)
	w.st.SetServiceEnabled(context.Background(), id, false)
	w.tick(15 * time.Second)
	if w.states() != "svc_down=resolved" || len(w.sent) != 1 {
		t.Fatalf("pause: states %q sent %q (no recovered message)", w.states(), w.sent)
	}
	w.st.SetServiceEnabled(context.Background(), id, true)
	w.check(id, "https://a.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(15 * time.Second)
	sv, _ := w.st.Service(context.Background(), id)
	sv.URL = "https://b.lan"
	w.st.UpdateService(context.Background(), sv)
	w.tick(15 * time.Second)
	if len(w.sent) != 2 || strings.Contains(strings.Join(w.sent, ";"), "resolved") {
		t.Fatalf("new address: sent %q (one firing per outage, no recovered)", w.sent)
	}
}

func TestEngineHostPassLeavesServiceAlerts(t *testing.T) {
	w := newWorld(t)
	w.report("web-01", protocol.Metrics{CPUPct: f(10)})
	id := w.service("A", "https://a.lan")
	w.check(id, "https://a.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	for i := 0; i < 3; i++ {
		w.tick(15 * time.Second)
		w.report("web-01", protocol.Metrics{CPUPct: f(10)})
	}
	if w.states() != "svc_down=firing" || len(w.sent) != 1 {
		t.Fatalf("states %q sent %q", w.states(), w.sent)
	}
}

func TestEngineCertificateSteps(t *testing.T) {
	w := newWorld(t)
	id := w.service("Proxmox", "https://labs.lan")
	exp := w.now.Add(20*24*time.Hour + time.Minute).Unix()
	w.check(id, "https://labs.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), CertExpiresAt: exp})
	w.tick(0)
	w.now = w.now.Add(7 * 24 * time.Hour) // 13 days left: the 14-day warning
	w.check(id, "https://labs.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), CertExpiresAt: exp})
	w.tick(0)
	if len(w.sent) != 2 || !strings.HasPrefix(w.sent[0], "firing") || !strings.HasPrefix(w.sent[1], "firing") {
		t.Fatalf("step 30 -> 14: sent %q; want two firing messages, no resolved", w.sent)
	}
	renewed := w.now.Add(90 * 24 * time.Hour).Unix()
	w.check(id, "https://labs.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), CertExpiresAt: renewed})
	w.tick(15 * time.Second)
	if len(w.sent) != 3 || !strings.HasPrefix(w.sent[2], "resolved") {
		t.Fatalf("renewed: sent %q; want a resolved message", w.sent)
	}
}

func TestEngineSlowAlertOnlyWhenOn(t *testing.T) {
	w := newWorld(t)
	id := w.service("HN", "https://hn.lan")
	w.check(id, "https://hn.lan", store.CheckState{State: "degraded", OK: true, Since: w.now.Unix(), Ms: 1842})
	w.tick(10 * time.Minute)
	if w.states() != "" {
		t.Fatalf("slow alert while off: %q", w.states())
	}
	w.st.SetSettings(context.Background(), map[string]string{"svc_slow_alert": "1"})
	w.tick(0)
	w.tick(5 * time.Minute)
	if w.states() != "svc_slow=firing" {
		t.Fatalf("slow alert after 5 min: %q", w.states())
	}
	w.check(id, "https://hn.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), Ms: 80})
	w.tick(15 * time.Second)
	if w.states() != "svc_slow=resolved" || len(w.sent) != 2 {
		t.Fatalf("fast again: %q sent %q", w.states(), w.sent)
	}
}

// The checker runs every second and the engine every 15: a new address or a
// quick pause and resume is usually checked again before the engine looks.
func TestEngineNewAddressCheckedBeforeTheTickEndsQuietly(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	id := w.service("A", "https://a.lan")
	exp := w.now.Add(10*24*time.Hour + time.Minute).Unix()
	w.check(id, "https://a.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout", CertExpiresAt: exp})
	w.tick(0)
	sv, _ := w.st.Service(ctx, id)
	sv.URL = "https://b.lan"
	w.st.UpdateService(ctx, sv)
	w.check(id, "https://b.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), CertExpiresAt: w.now.Add(80 * 24 * time.Hour).Unix()})
	w.tick(15 * time.Second)
	if strings.Contains(strings.Join(w.sent, ";"), "resolved") {
		t.Fatalf("a new address is not a recovery or a renewal: sent %q", w.sent)
	}
	w.check(id, "https://b.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(15 * time.Second)
	w.st.SetServiceEnabled(ctx, id, false)
	w.st.SetServiceEnabled(ctx, id, true)
	w.check(id, "https://b.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix()})
	w.tick(15 * time.Second)
	if strings.Contains(strings.Join(w.sent, ";"), "resolved") {
		t.Fatalf("a pause is not a recovery: sent %q", w.sent)
	}
}

func TestEngineCertificateDetailFollowsTheDays(t *testing.T) {
	w := newWorld(t)
	id := w.service("P", "https://p.lan")
	exp := w.now.Add(13*24*time.Hour + time.Minute).Unix()
	w.check(id, "https://p.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), CertExpiresAt: exp})
	w.tick(0)
	w.now = w.now.Add(3 * 24 * time.Hour)
	w.tick(0)
	alerts, _ := w.st.OpenAlerts(context.Background())
	if len(alerts) != 1 || !strings.HasPrefix(alerts[0].Detail, "10 days") || len(w.sent) != 1 {
		t.Fatalf("detail after 3 days = %+v, sent %q", alerts, w.sent)
	}
}

func (w *world) hostID(name string) int64 {
	w.t.Helper()
	hosts, _ := w.st.Hosts(context.Background())
	for _, h := range hosts {
		if h.Name == name {
			return h.ID
		}
	}
	w.t.Fatalf("no host %s", name)
	return 0
}

func (w *world) hostedService(name, url, host string) int64 {
	w.t.Helper()
	id, err := w.st.CreateService(context.Background(), store.Service{Name: name, URL: url, HostID: w.hostID(host), IntervalS: 60, TimeoutS: 10, Enabled: true}, w.now)
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

func (w *world) serviceMessages() []string {
	var out []string
	for _, line := range w.sent {
		if strings.Contains(line, "svc_") {
			out = append(out, line)
		}
	}
	return out
}

func TestServiceDownUnderSilentHostIsHeldBack(t *testing.T) {
	w := newWorld(t)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	id := w.hostedService("Proxmox", "https://pve.lan", "pve-2")
	w.now = w.now.Add(50 * time.Second) // the host stopped reporting
	w.check(id, "https://pve.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(15 * time.Second)
	if got := w.serviceMessages(); len(got) != 0 || strings.Contains(w.states(), "svc_down") {
		t.Fatalf("held back: states %q service messages %q", w.states(), got)
	}
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	w.tick(0)
	if got := w.serviceMessages(); len(got) != 0 {
		t.Fatalf("no check since the host came back, nothing is known yet: %q", got)
	}
	w.now = w.now.Add(30 * time.Second)
	w.check(id, "https://pve.lan", store.CheckState{State: "down", Since: w.now.Add(-95 * time.Second).Unix(), Error: "timeout", FailStreak: 5})
	w.tick(0)
	if got := w.serviceMessages(); len(got) != 1 || !strings.HasPrefix(got[0], "firing") {
		t.Fatalf("a check after the host came back failed: %q", got)
	}
}

// A reboot: the host comes back and its services need two good checks
// before they read online. Nothing about them should be sent.
func TestHostRebootRecoveryIsQuiet(t *testing.T) {
	w := newWorld(t)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	id := w.hostedService("Proxmox", "https://pve.lan", "pve-2")
	down := w.now.Add(90 * time.Second).Unix()
	w.now = w.now.Add(90 * time.Second)
	w.check(id, "https://pve.lan", store.CheckState{State: "down", Since: down, Error: "timeout", FailStreak: 3})
	w.tick(0)
	w.tick(60 * time.Second)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)}) // back
	w.tick(5 * time.Second)
	w.check(id, "https://pve.lan", store.CheckState{State: "down", Since: down, Error: "timeout", OkStreak: 1}) // recovering
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	w.tick(15 * time.Second)
	w.check(id, "https://pve.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix(), OkStreak: 2})
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	w.tick(15 * time.Second)
	if got := w.serviceMessages(); len(got) != 0 {
		t.Fatalf("a reboot sent service messages: %q", got)
	}
}

// A dead agent does not mean a dead host: a service that fails long after
// its host went quiet is a failure of its own.
func TestAgentSilenceDoesNotHideLaterFailures(t *testing.T) {
	w := newWorld(t)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	id := w.hostedService("Nextcloud", "https://nc.lan", "pve-2")
	w.tick(2 * time.Hour)
	w.check(id, "https://nc.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "HTTP 502", FailStreak: 3})
	w.tick(15 * time.Second)
	if got := w.serviceMessages(); len(got) != 1 || !strings.HasPrefix(got[0], "firing") {
		t.Fatalf("service messages %q; want its DOWN", got)
	}
}

func TestNeverReportedHostHoldsNothing(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.st.CreateEnrollmentToken(ctx, "e-new", w.now, w.now.Add(time.Minute))
	_, hostID, err := w.st.Enroll(ctx, store.EnrollParams{EnrollTokenHash: "e-new", Hostname: "new", AgentTokenHash: "a-new", ProtocolVersion: 1, Now: w.now})
	if err != nil {
		t.Fatal(err)
	}
	id, _ := w.st.CreateService(ctx, store.Service{Name: "App", URL: "https://app.lan", HostID: hostID, IntervalS: 60, TimeoutS: 10, Enabled: true}, w.now)
	w.check(id, "https://app.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout", FailStreak: 3})
	w.tick(15 * time.Second)
	if got := w.serviceMessages(); len(got) != 1 {
		t.Fatalf("service messages %q; want its DOWN", got)
	}
}

func TestServiceRecoveredDuringHostOutageSendsNothing(t *testing.T) {
	w := newWorld(t)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	id := w.hostedService("Proxmox", "https://pve.lan", "pve-2")
	w.now = w.now.Add(50 * time.Second)
	w.check(id, "https://pve.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(15 * time.Second)
	w.check(id, "https://pve.lan", store.CheckState{State: "online", OK: true, Since: w.now.Unix()})
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	w.tick(15 * time.Second)
	if got := w.serviceMessages(); len(got) != 0 {
		t.Fatalf("service messages %q; want none", got)
	}
}

func TestOpenServiceAlertSurvivesHostSilence(t *testing.T) {
	w := newWorld(t)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	id := w.hostedService("Proxmox", "https://pve.lan", "pve-2")
	w.check(id, "https://pve.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(0)
	w.tick(50 * time.Second)
	w.tick(50 * time.Second)
	if !strings.Contains(w.states(), "svc_down=firing") || len(w.serviceMessages()) != 1 {
		t.Fatalf("states %q service messages %q", w.states(), w.serviceMessages())
	}
}

func TestOfflineMessageNamesTheHostServices(t *testing.T) {
	w := newWorld(t)
	w.report("pve-2", protocol.Metrics{CPUPct: f(10)})
	w.hostedService("b-app", "https://b.lan", "pve-2")
	w.hostedService("A-app", "https://a.lan", "pve-2")
	paused := w.hostedService("C-app", "https://c.lan", "pve-2")
	w.st.SetServiceEnabled(context.Background(), paused, false)
	w.tick(70 * time.Second)
	var off *Message
	for i := range w.msgs {
		if w.msgs[i].Kind == KindOffline {
			off = &w.msgs[i]
		}
	}
	if off == nil || strings.Join(off.HostServices, ",") != "A-app,b-app" {
		t.Fatalf("offline message = %+v", off)
	}
}

// The certificate date is in the Hub's zone, as Since and Ended are.
func TestCertDateInHubZone(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("+08", 8*3600)
	defer func() { time.Local = old }()
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	exp := time.Date(2026, 11, 10, 20, 0, 0, 0, time.UTC).Unix() // 11 Nov at +08
	c, ok := certCondition(store.Service{URL: "https://a", CertExpiresAt: exp}, now, []int{30})
	if !ok || c.Detail != "9 days, 11 Nov 2026" {
		t.Errorf("detail = %q", c.Detail)
	}
}

// An alert that ended before its firing message was delivered sends nothing
// and is recorded as skipped, not as sent.
func TestEndedBeforeDeliveryIsSkipped(t *testing.T) {
	w := newWorld(t)
	id := w.service("Grafana", "https://grafana.lan")
	w.check(id, "https://grafana.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.fail = true
	w.tick(15 * time.Second)
	w.st.SetServiceEnabled(context.Background(), id, false)
	w.fail = false
	w.tick(15 * time.Second)
	alerts, _ := w.st.Alerts(context.Background(), 100)
	if len(w.sent) != 0 || len(alerts) != 1 || !alerts[0].Skipped || alerts[0].NotifiedFire || alerts[0].NotifiedResolve {
		t.Errorf("sent %q, alert %+v", w.sent, alerts)
	}
	if owed, _ := w.st.UnnotifiedAlerts(context.Background()); len(owed) != 0 {
		t.Errorf("still owed: %+v", owed)
	}
}
