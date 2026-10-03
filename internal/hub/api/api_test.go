package api

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

type env struct {
	t      *testing.T
	st     *store.Store
	bus    *live.Bus
	mux    *http.ServeMux
	now    time.Time
	dbPath string
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, bus: live.New(), mux: http.NewServeMux(), now: time.Unix(1_790_000_000, 0)}
	e.dbPath = filepath.Join(t.TempDir(), "t.db")
	st, err := store.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e.st = st
	New(st, e.bus, func() time.Time { return e.now }).Routes(e.mux)
	return e
}

func (e *env) post(path, token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

// enrollToken creates an enrollment token directly in the store.
func (e *env) enrollToken() string {
	plain, _ := store.NewToken()
	if err := e.st.CreateEnrollmentToken(e.t.Context(), store.HashToken(plain), e.now, e.now.Add(15*time.Minute)); err != nil {
		e.t.Fatal(err)
	}
	return plain
}

func (e *env) enroll(hostname string) protocol.EnrollResponse {
	e.t.Helper()
	body, _ := json.Marshal(protocol.EnrollRequest{Token: e.enrollToken(), Hostname: hostname, AgentVersion: "0.1.0", ProtocolVersion: 1})
	w := e.post("/api/v1/agent/enroll", "", body)
	if w.Code != http.StatusOK {
		e.t.Fatalf("enroll status = %d, body %s", w.Code, w.Body)
	}
	var resp protocol.EnrollResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp
}

func report(ts int64) []byte {
	cpu := 14.2
	b, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, AgentVersion: "0.1.0", TS: ts, Metrics: protocol.Metrics{CPUPct: &cpu, UptimeS: 60}})
	return b
}

func TestEnrollThenReport(t *testing.T) {
	e := setup(t)
	events, cancel := e.bus.Subscribe()
	defer cancel()
	resp := e.enroll("web-01")
	if resp.AgentID == "" || len(resp.AgentToken) != 43 {
		t.Fatalf("enroll response = %+v", resp)
	}
	if ev := <-events; ev.Kind != live.HostAdded || ev.HostID == 0 {
		t.Errorf("enroll must publish HostAdded, got %+v", ev)
	}
	if w := e.post("/api/v1/agent/report", resp.AgentToken, report(100)); w.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, body %s", w.Code, w.Body)
	}
	ev := <-events
	if ev.Kind != live.HostUpdated {
		t.Errorf("report must publish HostUpdated, got %+v", ev)
	}
	h, err := e.st.Host(t.Context(), ev.HostID)
	if err != nil || h.Name != "web-01" || h.Metrics == nil || h.Metrics.UptimeS != 60 || !h.LastSeen.Equal(e.now) {
		t.Errorf("stored host = %+v, %v", h, err)
	}
}

func TestReportChecksInSpecOrder(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	huge := bytes.Repeat([]byte("x"), MaxBody+1)

	if w := e.post("/api/v1/agent/report", "wrong", huge); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body with a bad token: %d, want 413 (size is checked first)", w.Code)
	}
	if w := e.post("/api/v1/agent/report", "wrong", []byte("{not json")); w.Code != http.StatusUnauthorized {
		t.Errorf("bad token with bad JSON: %d, want 401", w.Code)
	}
	if w := e.post("/api/v1/agent/report", "", report(1)); w.Code != http.StatusUnauthorized {
		t.Errorf("missing Authorization: %d, want 401", w.Code)
	}
	if w := e.post("/api/v1/agent/report", tok, report(100)); w.Code != http.StatusNoContent {
		t.Fatalf("first report: %d", w.Code)
	}
	e.now = e.now.Add(2 * time.Second)
	if w := e.post("/api/v1/agent/report", tok, []byte("{not json")); w.Code != http.StatusTooManyRequests {
		t.Errorf("2s after the last report, even with bad JSON: %d, want 429", w.Code)
	}
	e.now = e.now.Add(3 * time.Second)
	if w := e.post("/api/v1/agent/report", tok, []byte("{not json")); w.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: %d, want 400", w.Code)
	}
	wrongVersion, _ := json.Marshal(protocol.Report{ProtocolVersion: 2, TS: 50})
	if w := e.post("/api/v1/agent/report", tok, wrongVersion); w.Code != http.StatusBadRequest {
		t.Errorf("unsupported protocol_version with an old ts: %d, want 400 (version is checked before replay)", w.Code)
	}
	w := e.post("/api/v1/agent/report", tok, report(100))
	var rr protocol.ReplayResponse
	json.Unmarshal(w.Body.Bytes(), &rr)
	if w.Code != http.StatusConflict || rr.LastTS != 100 {
		t.Errorf("repeated ts: %d %s, want 409 with last_ts 100", w.Code, w.Body)
	}
	if w := e.post("/api/v1/agent/report", tok, report(101)); w.Code != http.StatusNoContent {
		t.Errorf("rejected reports must not count toward the 5s interval: %d", w.Code)
	}
}

func TestAcceptedReportQueuesOneHistoryRow(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	history := func() []store.MetricPoint {
		t.Helper()
		if err := e.st.FlushMetrics(t.Context()); err != nil {
			t.Fatal(err)
		}
		pts, _, err := e.st.History(t.Context(), 1, e.now.Add(-time.Hour), e.now.Add(time.Hour), 0)
		if err != nil {
			t.Fatal(err)
		}
		return pts
	}
	e.post("/api/v1/agent/report", tok, report(100))
	pts := history()
	if len(pts) != 1 || pts[0].CPU == nil || *pts[0].CPU != 14.2 {
		t.Fatalf("history after one report = %+v", pts)
	}
	e.now = e.now.Add(15 * time.Second)
	if w := e.post("/api/v1/agent/report", tok, report(100)); w.Code != http.StatusConflict {
		t.Fatalf("replayed report: %d", w.Code)
	}
	if pts := history(); len(pts) != 1 {
		t.Errorf("a rejected report must not leave a history row, rows = %d", len(pts))
	}
}

func TestDisabledAgentIsRejected(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	raw, err := sql.Open("sqlite", "file:"+e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("UPDATE agents SET disabled = 1"); err != nil {
		t.Fatal(err)
	}
	if w := e.post("/api/v1/agent/report", tok, report(100)); w.Code != http.StatusUnauthorized {
		t.Errorf("disabled agent: %d, want 401", w.Code)
	}
}

func TestTokensAreNotInterchangeable(t *testing.T) {
	e := setup(t)
	enrollTok := e.enrollToken()
	if w := e.post("/api/v1/agent/report", enrollTok, report(100)); w.Code != http.StatusUnauthorized {
		t.Errorf("enrollment token on the report endpoint: %d, want 401", w.Code)
	}
	agentTok := e.enroll("web-01").AgentToken
	body, _ := json.Marshal(protocol.EnrollRequest{Token: agentTok, Hostname: "x", ProtocolVersion: 1})
	if w := e.post("/api/v1/agent/enroll", "", body); w.Code != http.StatusUnauthorized {
		t.Errorf("agent token on the enroll endpoint: %d, want 401", w.Code)
	}
}

func TestEnrollRejections(t *testing.T) {
	e := setup(t)
	tok := e.enrollToken()
	body, _ := json.Marshal(protocol.EnrollRequest{Token: tok, Hostname: "web-01", ProtocolVersion: 1})
	if w := e.post("/api/v1/agent/enroll", "", body); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	if w := e.post("/api/v1/agent/enroll", "", body); w.Code != http.StatusUnauthorized {
		t.Errorf("second use of one token: %d, want 401", w.Code)
	}
	expired := e.enrollToken()
	e.now = e.now.Add(15 * time.Minute)
	body, _ = json.Marshal(protocol.EnrollRequest{Token: expired, Hostname: "x", ProtocolVersion: 1})
	if w := e.post("/api/v1/agent/enroll", "", body); w.Code != http.StatusUnauthorized {
		t.Errorf("expired token: %d, want 401", w.Code)
	}
	body, _ = json.Marshal(protocol.EnrollRequest{Token: e.enrollToken(), Hostname: "x", ProtocolVersion: 9})
	if w := e.post("/api/v1/agent/enroll", "", body); w.Code != http.StatusBadRequest {
		t.Errorf("unsupported protocol_version: %d, want 400", w.Code)
	}
}

func TestEnrollIsRateLimitedAfterFiveFailures(t *testing.T) {
	e := setup(t)
	bad, _ := json.Marshal(protocol.EnrollRequest{Token: "nope", Hostname: "x", ProtocolVersion: 1})
	for i := 0; i < 5; i++ {
		if w := e.post("/api/v1/agent/enroll", "", bad); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i+1, w.Code)
		}
	}
	good, _ := json.Marshal(protocol.EnrollRequest{Token: e.enrollToken(), Hostname: "x", ProtocolVersion: 1})
	if w := e.post("/api/v1/agent/enroll", "", good); w.Code != http.StatusTooManyRequests {
		t.Errorf("sixth attempt within a minute: %d, want 429", w.Code)
	}
}

func TestInvalidAddressesAreDropped(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	rep, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, TS: 100,
		Inventory: &protocol.Inventory{Hostname: "web-01", Interfaces: []protocol.Interface{{Name: "eth0",
			IPv4: []string{"192.168.10.10", "<b>not-an-ip</b>", strings.Repeat("9", 5000)},
			IPv6: []string{"2001:db8::10", "zzzz", "fe80::1%" + strings.Repeat("z", 5000)}}}}})
	if w := e.post("/api/v1/agent/report", tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	hosts, _ := e.st.Hosts(t.Context())
	ifc := hosts[0].Inventory.Interfaces[0]
	if len(ifc.IPv4) != 1 || ifc.IPv4[0] != "192.168.10.10" {
		t.Errorf("only strings that parse as addresses may be stored and shown: ipv4 = %d entries", len(ifc.IPv4))
	}
	if len(ifc.IPv6) != 2 || ifc.IPv6[0] != "2001:db8::10" || ifc.IPv6[1] != "fe80::1" {
		t.Errorf("ipv6 must keep valid addresses and drop the zone: %d entries, %.40q", len(ifc.IPv6), ifc.IPv6)
	}
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

func (e *env) postGzip(token string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/agent/report", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func TestGzipReports(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	if w := e.postGzip(tok, gz(report(100))); w.Code != http.StatusNoContent {
		t.Fatalf("gzip report: %d %s", w.Code, w.Body)
	}
	hosts, _ := e.st.Hosts(t.Context())
	if hosts[0].Metrics == nil || hosts[0].Metrics.UptimeS != 60 {
		t.Errorf("gzip report must be stored like a plain one: %+v", hosts[0].Metrics)
	}
	e.now = e.now.Add(15 * time.Second)
	if w := e.postGzip(tok, []byte("not gzip at all")); w.Code != http.StatusBadRequest {
		t.Errorf("a body that claims gzip but is not: %d, want 400", w.Code)
	}
	// 5 MB of zeros compress to a few KB: the limit must apply to the expanded size.
	bomb := gz(append([]byte(`{"protocol_version":1,"ts":200,"pad":"`), append(bytes.Repeat([]byte("0"), 5<<20), []byte(`"}`)...)...))
	if len(bomb) > MaxBody {
		t.Fatalf("test body is %d bytes compressed, must be under the wire limit", len(bomb))
	}
	if w := e.postGzip(tok, bomb); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("a report that expands past 4 MB: %d, want 413", w.Code)
	}
}

func TestProxmoxDataIsSanitized(t *testing.T) {
	e := setup(t)
	tok := e.enroll("pve-01").AgentToken
	long := strings.Repeat("x", 400)
	pve := &protocol.Proxmox{Detected: true, Configured: true, Version: long, Node: "pve-01", Error: long,
		Guests: []protocol.Guest{
			{ID: 101, Type: "lxc", Name: long, Status: "running", IPs: []string{"192.168.10.21", "<b>x</b>"}},
			{ID: 102, Type: "docker", Name: "wrong type", Status: "running"},
			{ID: 103, Type: "qemu", Name: "vm", Status: "exploded"},
		},
		Storage: []protocol.Storage{{Name: long, Type: long, Active: true, Total: 10, Used: 1}},
	}
	rep, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, TS: 100, Metrics: protocol.Metrics{Proxmox: pve}})
	if w := e.post("/api/v1/agent/report", tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	hosts, _ := e.st.Hosts(t.Context())
	got := hosts[0].Metrics.Proxmox
	if got == nil || len(got.Version) != 255 || len(got.Error) != 255 {
		t.Fatalf("proxmox = %+v", got)
	}
	if len(got.Guests) != 2 || len(got.Guests[0].Name) != 255 || len(got.Guests[0].IPs) != 1 || got.Guests[0].IPs[0] != "192.168.10.21" {
		t.Errorf("a guest of an unknown type is dropped, names are clipped, addresses validated: %d guests", len(got.Guests))
	}
	if got.Guests[1].ID != 103 || got.Guests[1].Status != "unknown" {
		t.Errorf("an unexpected status becomes unknown: %+v", got.Guests[1])
	}
	if len(got.Storage) != 1 || len(got.Storage[0].Name) != 255 || len(got.Storage[0].Type) != 255 {
		t.Errorf("storage strings must be clipped")
	}
}

func TestServicesAreSanitized(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	svcs := []protocol.Service{{Name: strings.Repeat("n", 400), Status: "running"}, {Name: "x.service", Status: "<b>on fire</b>"}}
	for i := 0; i < 150; i++ {
		svcs = append(svcs, protocol.Service{Name: "bulk.service", Status: "stopped"})
	}
	rep, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, TS: 100, Metrics: protocol.Metrics{Services: svcs}})
	if w := e.post("/api/v1/agent/report", tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	hosts, _ := e.st.Hosts(t.Context())
	got := hosts[0].Metrics.Services
	if len(got) != 100 {
		t.Fatalf("at most 100 services are kept, got %d", len(got))
	}
	if len(got[0].Name) != 255 || got[0].Status != "running" || got[1].Status != "unknown" || got[2].Status != "stopped" {
		t.Errorf("name must be clipped and an unexpected status must become unknown: %d %q %q %q", len(got[0].Name), got[0].Status, got[1].Status, got[2].Status)
	}
}

func TestAgentStringsAreClipped(t *testing.T) {
	e := setup(t)
	long := strings.Repeat("é", 400)
	tok := e.enroll(long).AgentToken
	rep, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, TS: 100,
		Metrics:   protocol.Metrics{Disks: []protocol.Disk{{Mount: long, Total: 10, Used: 1}}},
		Inventory: &protocol.Inventory{Hostname: long, Interfaces: []protocol.Interface{{Name: long}}}})
	if w := e.post("/api/v1/agent/report", tok, rep); w.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	hosts, _ := e.st.Hosts(t.Context())
	h := hosts[0]
	for what, s := range map[string]string{"host name": h.Name, "mount": h.Metrics.Disks[0].Mount, "interface": h.Inventory.Interfaces[0].Name} {
		if n := len([]rune(s)); n != 255 {
			t.Errorf("%s length = %d runes, want 255", what, n)
		}
	}
}

func (e *env) get(path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func TestSelf(t *testing.T) {
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	var self protocol.SelfResponse
	w := e.get("/api/v1/agent/self", tok)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &self) != nil || self.Name != "web-01" || self.HostID == 0 || self.LastSeen != 0 {
		t.Fatalf("before the first report: %d %s", w.Code, w.Body)
	}
	e.post("/api/v1/agent/report", tok, report(100))
	e.now = e.now.Add(20 * time.Second)
	w = e.get("/api/v1/agent/self", tok)
	json.Unmarshal(w.Body.Bytes(), &self)
	if self.LastSeen != e.now.Unix()-20 || self.Now != e.now.Unix() {
		t.Errorf("after a report: %s", w.Body)
	}
	for _, bad := range []string{"", "wrong"} {
		if w := e.get("/api/v1/agent/self", bad); w.Code != http.StatusUnauthorized {
			t.Errorf("token %q: %d, want 401", bad, w.Code)
		}
	}
	e.st.SetAgentDisabled(t.Context(), self.HostID, true)
	if w := e.get("/api/v1/agent/self", tok); w.Code != http.StatusUnauthorized {
		t.Errorf("a disabled agent: %d, want 401", w.Code)
	}
}

func TestEnrollWithBoundTokenKeepsTheHost(t *testing.T) {
	e := setup(t)
	old := e.enroll("web-01")
	hosts, _ := e.st.Hosts(t.Context())
	plain, _ := store.NewToken()
	e.st.CreateHostEnrollmentToken(t.Context(), store.HashToken(plain), hosts[0].ID, e.now, e.now.Add(15*time.Minute))
	events, cancel := e.bus.Subscribe()
	defer cancel()
	body, _ := json.Marshal(protocol.EnrollRequest{Token: plain, Hostname: "web-01", AgentVersion: "0.1.0", ProtocolVersion: 1})
	w := e.post("/api/v1/agent/enroll", "", body)
	var resp protocol.EnrollResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp.AgentID != old.AgentID || resp.AgentToken == old.AgentToken {
		t.Fatalf("re-enroll: %d %s", w.Code, w.Body)
	}
	if ev := <-events; ev.Kind != live.HostUpdated || ev.HostID != hosts[0].ID {
		t.Errorf("a replaced credential must publish HostUpdated, not a new host: %+v", ev)
	}
	if w := e.post("/api/v1/agent/report", old.AgentToken, report(100)); w.Code != http.StatusUnauthorized {
		t.Errorf("the old credential: %d, want 401", w.Code)
	}
	if w := e.post("/api/v1/agent/report", resp.AgentToken, report(100)); w.Code != http.StatusNoContent {
		t.Errorf("the new credential: %d, want 204", w.Code)
	}
}

func TestEnrollAndUpgradeAreLogged(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	if w := e.post("/api/v1/agent/report", tok, report(100)); w.Code != http.StatusNoContent {
		t.Fatalf("first report: %d", w.Code)
	}
	e.now = e.now.Add(10 * time.Second)
	newer, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, AgentVersion: "0.1.2", TS: 110})
	if w := e.post("/api/v1/agent/report", tok, newer); w.Code != http.StatusNoContent {
		t.Fatalf("second report: %d", w.Code)
	}
	e.now = e.now.Add(10 * time.Second)
	again, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, AgentVersion: "0.1.2", TS: 120})
	if w := e.post("/api/v1/agent/report", tok, again); w.Code != http.StatusNoContent {
		t.Fatalf("third report: %d", w.Code)
	}
	// A bound token replaces the credential of the same host.
	bound, _ := store.NewToken()
	e.st.CreateHostEnrollmentToken(t.Context(), store.HashToken(bound), 1, e.now, e.now.Add(time.Minute))
	body, _ := json.Marshal(protocol.EnrollRequest{Token: bound, Hostname: "web-01", AgentVersion: "0.1.2", ProtocolVersion: 1})
	if w := e.post("/api/v1/agent/enroll", "", body); w.Code != http.StatusOK {
		t.Fatalf("bound enroll: %d", w.Code)
	}
	body, _ = json.Marshal(protocol.EnrollRequest{Token: "bogus", Hostname: "x", ProtocolVersion: 1})
	e.post("/api/v1/agent/enroll", "", body)

	got := logged.String()
	for _, want := range []string{
		"server web-01 enrolled, agent 0.1.0\n",
		"agent on web-01 now version 0.1.2, was 0.1.0\n",
		"credential of web-01 replaced, agent 0.1.2\n",
		"enrollment rejected from 192.0.2.1 (unknown or used token)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Count(got, "now version") != 1 {
		t.Errorf("a version change is logged once:\n%s", got)
	}
	if strings.Contains(got, tok) || strings.Contains(got, bound) {
		t.Errorf("a token reached the log:\n%s", got)
	}
}

func TestReportsAreLogged(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	e := setup(t)
	tok := e.enroll("web-01").AgentToken
	if w := e.post("/api/v1/agent/report", tok, report(100)); w.Code != http.StatusNoContent {
		t.Fatalf("first report: %d", w.Code)
	}
	e.post("/api/v1/agent/report", tok, report(101)) // 2 s rule: too often
	e.now = e.now.Add(10 * time.Second)
	e.post("/api/v1/agent/report", tok, report(100)) // replay
	e.post("/api/v1/agent/report", "wrong", report(102))
	e.now = e.now.Add(10 * time.Second)
	full, _ := json.Marshal(protocol.Report{ProtocolVersion: 1, AgentVersion: "0.1.0", TS: 200, Metrics: protocol.Metrics{
		CPUPct: ptr(3.4), Mem: &protocol.Mem{Total: 1000, Used: 410}, Disks: []protocol.Disk{{Mount: "/", Total: 100, Used: 62}, {Mount: "/data", Total: 100, Used: 20}}}})
	if w := e.post("/api/v1/agent/report", tok, full); w.Code != http.StatusNoContent {
		t.Fatalf("full report: %d", w.Code)
	}
	got := logged.String()
	for _, want := range []string{
		"report from web-01: agent 0.1.0, cpu 14%, ram -, disk -\n",
		"report from web-01 rejected (too often, 0s since the last)\n",
		"report from web-01 rejected (timestamp 100 already seen)\n",
		"report rejected from 192.0.2.1 (unknown or disabled credential)\n",
		"report from web-01: agent 0.1.0, cpu 3%, ram 41%, disk 62%\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func ptr(f float64) *float64 { return &f }
