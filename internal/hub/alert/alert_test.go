package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

var t0 = time.Unix(1_790_000_000, 0)

func f(v float64) *float64 { return &v }

func onlineHost(id int64, name string) store.Host {
	return store.Host{ID: id, Name: name, LastSeen: t0, Metrics: &protocol.Metrics{CPUPct: f(10), Mem: &protocol.Mem{Total: 100, Used: 10}}}
}

func kinds(conds []Condition) string {
	var out []string
	for _, c := range conds {
		out = append(out, c.Kind+":"+c.Subject)
	}
	return strings.Join(out, " ")
}

func TestRulesFromSettings(t *testing.T) {
	r := RulesFrom(nil)
	if r != (Rules{OfflineAfter: 60 * time.Second, CPUFor: 5 * time.Minute, RAMFor: 5 * time.Minute, DiskFor: 2 * time.Minute, StorageFor: 2 * time.Minute}) {
		t.Errorf("defaults = %+v", r)
	}
	r = RulesFrom(map[string]string{"offline_after_s": "120", "cpu_for_min": "0", "ram_for_min": "junk", "disk_for_min": "10"})
	if r.OfflineAfter != 2*time.Minute || r.CPUFor != 0 || r.RAMFor != 5*time.Minute || r.DiskFor != 10*time.Minute {
		t.Errorf("from settings = %+v (an unreadable value keeps the default)", r)
	}
}

func TestEvaluateThresholds(t *testing.T) {
	h := onlineHost(1, "web-01")
	h.Metrics.CPUPct = f(93.4)
	h.Metrics.Mem = &protocol.Mem{Total: 1000, Used: 900}
	h.Metrics.Disks = []protocol.Disk{{Mount: "/", Total: 100, Used: 50}, {Mount: "/data", Total: 100, Used: 85}, {Mount: "/var", Total: 100, Used: 99}}
	h.Metrics.Services = []protocol.Service{{Name: "nginx.service", Status: "running"}, {Name: "db.service", Status: "failed"}}
	conds, unknown := Evaluate([]store.Host{h}, t0, RulesFrom(nil), map[GuestKey]bool{})
	if got := kinds(conds); got != "cpu_high: ram_high: disk_full:/data disk_full:/var service_failed:db.service" {
		t.Fatalf("conditions = %q", got)
	}
	if conds[0].For != 5*time.Minute || conds[0].Detail != "CPU 93%" || conds[2].For != 2*time.Minute || conds[2].Detail != "/data 85%" || conds[4].For != 0 {
		t.Errorf("waiting times and details: %+v", conds)
	}
	if len(unknown) != 0 {
		t.Errorf("an online host is not unknown: %v", unknown)
	}
	h.Metrics.CPUPct, h.Metrics.Mem = f(89.4), &protocol.Mem{Total: 1000, Used: 894}
	h.Metrics.Disks, h.Metrics.Services = nil, nil
	if conds, _ := Evaluate([]store.Host{h}, t0, RulesFrom(nil), map[GuestKey]bool{}); len(conds) != 0 {
		t.Errorf("just under every limit raises nothing: %q", kinds(conds))
	}
}

func TestEvaluateOfflineHidesOtherRules(t *testing.T) {
	h := onlineHost(1, "web-01")
	h.Metrics.CPUPct = f(99)
	h.LastSeen = t0.Add(-50 * time.Second)
	conds, unknown := Evaluate([]store.Host{h}, t0, RulesFrom(nil), map[GuestKey]bool{})
	if len(conds) != 0 || !unknown[1] {
		t.Errorf("50s without a report: no alert yet, but nothing is known either: %q %v", kinds(conds), unknown)
	}
	h.LastSeen = t0.Add(-60 * time.Second)
	conds, unknown = Evaluate([]store.Host{h}, t0, RulesFrom(nil), map[GuestKey]bool{})
	if kinds(conds) != "host_offline:" || conds[0].For != 0 || !unknown[1] {
		t.Errorf("60s without a report: only host_offline: %q", kinds(conds))
	}
	never := store.Host{ID: 2, Name: "new"}
	if conds, _ := Evaluate([]store.Host{never}, t0, RulesFrom(nil), map[GuestKey]bool{}); len(conds) != 0 {
		t.Errorf("a host that never reported raises nothing: %q", kinds(conds))
	}
}

func TestEvaluateProxmox(t *testing.T) {
	h := onlineHost(1, "pve-01")
	h.Metrics.Proxmox = &protocol.Proxmox{Detected: true, Configured: true,
		Guests:  []protocol.Guest{{ID: 101, Type: "lxc", Name: "nginx", Status: "running"}, {ID: 115, Type: "lxc", Name: "ocrmypdf", Status: "stopped"}},
		Storage: []protocol.Storage{{Name: "local", Active: true}, {Name: "nas", Active: false}}}
	seen := map[GuestKey]bool{}
	conds, _ := Evaluate([]store.Host{h}, t0, RulesFrom(nil), seen)
	if kinds(conds) != "storage_inactive:nas" || conds[0].For != 2*time.Minute {
		t.Fatalf("a guest never seen running is not 'stopped unexpectedly': %q", kinds(conds))
	}
	h.Metrics.Proxmox.Guests[0].Status = "stopped"
	conds, _ = Evaluate([]store.Host{h}, t0, RulesFrom(nil), seen)
	if kinds(conds) != "guest_stopped:101 storage_inactive:nas" || conds[0].Detail != "nginx (LXC 101) stopped" || conds[0].For != 0 {
		t.Errorf("a guest seen running and now stopped: %q %+v", kinds(conds), conds)
	}
	h.Metrics.Proxmox.Guests = h.Metrics.Proxmox.Guests[1:]
	conds, _ = Evaluate([]store.Host{h}, t0, RulesFrom(nil), seen)
	if kinds(conds) != "storage_inactive:nas" || seen[GuestKey{1, 101}] {
		t.Errorf("a removed guest ends its alert and is forgotten: %q %v", kinds(conds), seen)
	}
}

// ---- notifiers ----

func TestWebhookAndTelegram(t *testing.T) {
	var path, ctype string
	var body map[string]any
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ctype = r.URL.Path, r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		body = nil
		json.Unmarshal(b, &body)
		w.WriteHeader(code)
	}))
	defer srv.Close()
	msg := Message{Event: "firing", Host: "web-01", Kind: KindCPU, Detail: "CPU 93%", Since: t0, At: t0.Add(5 * time.Minute), Hub: "hub.example.com"}

	targets := Targets(map[string]string{"webhook_url": srv.URL + "/hook"}, "")
	if len(targets) != 1 || targets[0].Name != "Webhook" {
		t.Fatalf("targets = %+v", targets)
	}
	if err := targets[0].Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if path != "/hook" || ctype != "application/json" || body["event"] != "firing" || body["host"] != "web-01" || body["kind"] != "cpu_high" || body["detail"] != "CPU 93%" || body["hub"] != "hub.example.com" || body["at"] != float64(t0.Add(5*time.Minute).Unix()) {
		t.Errorf("webhook request: %s %s %v", path, ctype, body)
	}
	code = http.StatusBadGateway
	if err := targets[0].Send(context.Background(), msg); err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("a non-2xx answer is a failed delivery: %v", err)
	}

	code = http.StatusOK
	targets = Targets(map[string]string{"telegram_token": "123:abc", "telegram_chat_id": "-100200"}, srv.URL)
	if len(targets) != 1 || targets[0].Name != "Telegram" {
		t.Fatalf("targets = %+v", targets)
	}
	if err := targets[0].Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:abc/sendMessage" || body["chat_id"] != "-100200" || body["text"] != "[FleetWatch] ALERT web-01: CPU high (CPU 93%)" {
		t.Errorf("telegram request: %s %v", path, body)
	}
	if got := Targets(map[string]string{"telegram_token": "123:abc"}, ""); len(got) != 0 {
		t.Error("Telegram needs both the token and the chat ID")
	}
	resolved := msg
	resolved.Event = "resolved"
	if resolved.Text() != "[FleetWatch] RESOLVED web-01: CPU high" {
		t.Errorf("resolved text = %q", resolved.Text())
	}
}

// ---- engine ----

type world struct {
	t      *testing.T
	st     *store.Store
	eng    *Engine
	now    time.Time
	sent   []string
	fail   bool
	agents map[string]int64
	ts     int64
	events <-chan live.Event
	logged []string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	w := &world{t: t, st: st, now: t0, agents: map[string]int64{}}
	bus := live.New()
	events, cancel := bus.Subscribe()
	t.Cleanup(cancel)
	w.events = events
	w.eng = &Engine{St: st, Bus: bus, Now: func() time.Time { return w.now }, Hub: "hub",
		Log: func(format string, args ...any) { w.logged = append(w.logged, fmt.Sprintf(format, args...)) },
		Send: func(_ context.Context, _ map[string]string, m Message) error {
			if w.fail {
				return errors.New("target down")
			}
			w.sent = append(w.sent, m.Event+" "+m.Host+" "+m.Kind+" "+m.Subject)
			return nil
		}}
	return w
}

// report stores a report for the named host at the current time.
func (w *world) report(name string, m protocol.Metrics) {
	w.t.Helper()
	ctx := context.Background()
	id, ok := w.agents[name]
	if !ok {
		w.st.CreateEnrollmentToken(ctx, "e-"+name, w.now, w.now.Add(time.Minute))
		var err error
		if id, _, err = w.st.Enroll(ctx, store.EnrollParams{EnrollTokenHash: "e-" + name, Hostname: name, AgentTokenHash: "a-" + name, ProtocolVersion: 1, Now: w.now}); err != nil {
			w.t.Fatal(err)
		}
		w.agents[name] = id
	}
	w.ts++
	if err := w.st.AcceptReport(ctx, id, protocol.Report{ProtocolVersion: 1, TS: w.ts, Metrics: m}, w.now); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) tick(advance time.Duration) {
	w.t.Helper()
	w.now = w.now.Add(advance)
	if err := w.eng.Tick(context.Background()); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) states() string {
	alerts, _ := w.st.Alerts(context.Background(), 100)
	var out []string
	for _, a := range alerts {
		out = append(out, a.Kind+"="+a.State())
	}
	return strings.Join(out, " ")
}

func TestEngineFiresOnlyAfterTheWaitingTime(t *testing.T) {
	w := newWorld(t)
	hot := protocol.Metrics{CPUPct: f(95)}
	w.report("web-01", hot)
	w.tick(0)
	if w.states() != "cpu_high=pending" || len(w.sent) != 0 {
		t.Fatalf("first sighting: %q, sent %v", w.states(), w.sent)
	}
	w.now = w.now.Add(4 * time.Minute)
	w.report("web-01", hot)
	w.tick(0)
	if w.states() != "cpu_high=pending" || len(w.sent) != 0 {
		t.Fatalf("after 4 minutes: %q, sent %v", w.states(), w.sent)
	}
	w.now = w.now.Add(time.Minute)
	w.report("web-01", hot)
	w.tick(0)
	if w.states() != "cpu_high=firing" || len(w.sent) != 1 || w.sent[0] != "firing web-01 cpu_high " {
		t.Fatalf("after 5 minutes: %q, sent %v", w.states(), w.sent)
	}
	w.tick(0)
	if len(w.sent) != 1 {
		t.Errorf("a delivered message is not sent again: %v", w.sent)
	}
	w.report("web-01", protocol.Metrics{CPUPct: f(20)})
	w.tick(15 * time.Second)
	if w.states() != "cpu_high=resolved" || len(w.sent) != 2 || w.sent[1] != "resolved web-01 cpu_high " {
		t.Fatalf("after recovery: %q, sent %v", w.states(), w.sent)
	}
	select {
	case ev := <-w.events:
		if ev.Kind != live.AlertsChanged {
			t.Errorf("event = %+v", ev)
		}
	default:
		t.Error("a change of alert state must be published for the dashboard")
	}
}

func TestEngineLogsFiringResolvedAndDelivery(t *testing.T) {
	w := newWorld(t)
	w.report("web-01", protocol.Metrics{CPUPct: f(95)})
	w.tick(0)
	w.now = w.now.Add(5 * time.Minute)
	w.report("web-01", protocol.Metrics{CPUPct: f(95)})
	w.tick(0)
	w.report("web-01", protocol.Metrics{CPUPct: f(20)})
	w.tick(15 * time.Second)
	got := strings.Join(w.logged, "\n")
	for _, want := range []string{
		"alert fired: cpu_high on web-01 (CPU 95%)",
		"\"firing\" message for cpu_high on web-01 delivered",
		"alert resolved: cpu_high on web-01",
		"\"resolved\" message for cpu_high on web-01 delivered",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestEngineForgetsAConditionThatClearsEarly(t *testing.T) {
	w := newWorld(t)
	w.report("web-01", protocol.Metrics{CPUPct: f(95)})
	w.tick(0)
	w.now = w.now.Add(time.Minute)
	w.report("web-01", protocol.Metrics{CPUPct: f(20)})
	w.tick(0)
	if w.states() != "" || len(w.sent) != 0 {
		t.Errorf("a short spike leaves no alert and no message: %q %v", w.states(), w.sent)
	}
}

func TestEngineOfflineAndBack(t *testing.T) {
	w := newWorld(t)
	w.report("web-01", protocol.Metrics{CPUPct: f(95)})
	w.tick(0) // cpu pending
	w.tick(61 * time.Second)
	if w.states() != "cpu_high=pending host_offline=firing" || len(w.sent) != 1 || w.sent[0] != "firing web-01 host_offline " {
		t.Fatalf("offline: %q, sent %v (the pending CPU alert is left alone: nothing is known)", w.states(), w.sent)
	}
	w.now = w.now.Add(10 * time.Minute)
	w.report("web-01", protocol.Metrics{CPUPct: f(20)})
	w.tick(0)
	if w.states() != "host_offline=resolved" || len(w.sent) != 2 || w.sent[1] != "resolved web-01 host_offline " {
		t.Errorf("back online: %q, sent %v", w.states(), w.sent)
	}
}

func TestEngineRetriesFailedDeliveryForAnHour(t *testing.T) {
	w := newWorld(t)
	w.fail = true
	failed := protocol.Metrics{CPUPct: f(5), Services: []protocol.Service{{Name: "db.service", Status: "failed"}}}
	w.report("web-01", failed)
	w.tick(0)
	if w.states() != "service_failed=firing" || len(w.sent) != 0 {
		t.Fatalf("delivery failed: %q %v", w.states(), w.sent)
	}
	w.fail = false
	w.now = w.now.Add(15 * time.Second)
	w.report("web-01", failed)
	w.tick(0)
	w.tick(0)
	if len(w.sent) != 1 || w.sent[0] != "firing web-01 service_failed db.service" {
		t.Fatalf("the message is delivered once the target is back, and only once: %v", w.sent)
	}

	// A second alert whose delivery never succeeds is given up after an hour.
	w.fail = true
	hot := failed
	hot.Mem = &protocol.Mem{Total: 100, Used: 95}
	w.eng.Rules = &Rules{OfflineAfter: time.Minute}
	w.report("web-01", hot)
	w.tick(0)
	w.now = w.now.Add(61 * time.Minute)
	w.report("web-01", hot)
	w.fail = false
	w.tick(0)
	if len(w.sent) != 1 {
		t.Errorf("a message older than an hour is not sent late: %v", w.sent)
	}
}

func TestEngineDismiss(t *testing.T) {
	w := newWorld(t)
	failed := protocol.Metrics{CPUPct: f(5), Services: []protocol.Service{{Name: "db.service", Status: "failed"}}}
	w.report("web-01", failed)
	w.tick(0)
	alerts, _ := w.st.OpenAlerts(context.Background())
	w.st.DismissAlert(context.Background(), alerts[0].ID, w.now)
	w.now = w.now.Add(15 * time.Second)
	w.report("web-01", failed)
	w.tick(0)
	if w.states() != "service_failed=dismissed" {
		t.Fatalf("a dismissed alert is not raised again while the condition lasts: %q", w.states())
	}
	w.now = w.now.Add(15 * time.Second)
	w.report("web-01", protocol.Metrics{CPUPct: f(5)})
	w.tick(0)
	if w.states() != "service_failed=resolved" || len(w.sent) != 1 {
		t.Errorf("a dismissed alert ends without a 'resolved' message: %q %v", w.states(), w.sent)
	}
}

func TestDisabledHostRaisesNothingAndItsAlertsEnd(t *testing.T) {
	w := newWorld(t)
	w.report("web-01", protocol.Metrics{})
	w.tick(2 * time.Minute)
	if w.states() != "host_offline=firing" {
		t.Fatalf("after 2 silent minutes: %q", w.states())
	}
	hosts, _ := w.st.Hosts(context.Background())
	w.st.SetAgentDisabled(context.Background(), hosts[0].ID, true)
	w.tick(15 * time.Second)
	if w.states() != "host_offline=resolved" {
		t.Errorf("the alert of a disabled host must end: %q", w.states())
	}
	w.tick(time.Hour)
	if w.states() != "host_offline=resolved" {
		t.Errorf("a disabled host must raise nothing: %q", w.states())
	}
}
