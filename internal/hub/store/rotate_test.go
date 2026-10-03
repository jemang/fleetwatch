package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"fleetwatch/internal/protocol"
)

func TestMigrationFromVersion3AddsTokenHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v3.db")
	old, _ := sql.Open("sqlite", "file:"+path)
	for _, m := range migrations[:3] {
		for _, stmt := range m {
			if _, err := old.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	old.Exec(`PRAGMA user_version = 3`)
	old.Exec(`INSERT INTO enrollment_tokens (token_hash, created_at, expires_at) VALUES ('kept', ?, ?)`, t0.Unix(), t0.Add(time.Hour).Unix())
	old.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if host, ok, err := s.EnrollmentTokenHost(ctx, "kept", t0); err != nil || !ok || host != 0 {
		t.Errorf("a token from schema version 3 must stay usable and unbound: %d %v %v", host, ok, err)
	}
}

func TestEnrollmentTokenHost(t *testing.T) {
	s := open(t)
	_, hostID := enrolled(t, s)
	s.CreateEnrollmentToken(ctx, "fresh", t0, t0.Add(15*time.Minute))
	if err := s.CreateHostEnrollmentToken(ctx, "bound", hostID, t0, t0.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		hash string
		now  time.Time
		host int64
		ok   bool
	}{
		{"fresh", t0, 0, true}, {"bound", t0, hostID, true}, {"unknown", t0, 0, false},
		{"enroll-hash", t0, 0, false},                 // used by enrolled()
		{"fresh", t0.Add(15 * time.Minute), 0, false}, // expired
	}
	for _, c := range cases {
		host, ok, err := s.EnrollmentTokenHost(ctx, c.hash, c.now)
		if err != nil || ok != c.ok || host != c.host {
			t.Errorf("%s at %v: host %d usable %v err %v, want %d %v", c.hash, c.now.Sub(t0), host, ok, err, c.host, c.ok)
		}
	}
	if err := s.CreateHostEnrollmentToken(ctx, "nohost", 999, t0, t0.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Errorf("a token for an unknown host: %v, want ErrNotFound", err)
	}
}

func TestBoundTokenReplacesCredential(t *testing.T) {
	s := open(t)
	agentID, hostID := enrolled(t, s)
	s.CreateHostEnrollmentToken(ctx, "rebind", hostID, t0, t0.Add(15*time.Minute))
	later := t0.Add(time.Minute)
	gotAgent, gotHost, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "rebind", Hostname: "other-name", AgentTokenHash: "agent-2", AgentVersion: "0.2.0", ProtocolVersion: 1, Now: later})
	if err != nil || gotAgent != agentID || gotHost != hostID {
		t.Fatalf("Enroll = %d, %d, %v; want the existing agent %d and host %d", gotAgent, gotHost, err, agentID, hostID)
	}
	hosts, _ := s.Hosts(ctx)
	if len(hosts) != 1 || hosts[0].Name != "web-01" || hosts[0].AgentVersion != "0.2.0" {
		t.Errorf("hosts = %+v; a bound token must keep the one host and its name", hosts)
	}
	if _, err := s.AgentByTokenHash(ctx, "agent-hash"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the old credential must stop working: %v", err)
	}
	if a, err := s.AgentByTokenHash(ctx, "agent-2"); err != nil || a.ID != agentID || a.HostID != hostID {
		t.Errorf("the new credential = %+v, %v", a, err)
	}
	if _, _, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "rebind", Hostname: "x", AgentTokenHash: "agent-3", ProtocolVersion: 1, Now: later}); !errors.Is(err, ErrEnrollmentRejected) {
		t.Errorf("a bound token works once: %v", err)
	}
}

func TestDisableAgent(t *testing.T) {
	s := open(t)
	_, hostID := enrolled(t, s)
	if err := s.SetAgentDisabled(ctx, hostID, true); err != nil {
		t.Fatal(err)
	}
	a, _ := s.AgentByTokenHash(ctx, "agent-hash")
	h, _ := s.Host(ctx, hostID)
	hosts, _ := s.Hosts(ctx)
	if !a.Disabled || !h.Disabled || !hosts[0].Disabled {
		t.Errorf("disabled: agent %v host %v list %v", a.Disabled, h.Disabled, hosts[0].Disabled)
	}
	s.SetAgentDisabled(ctx, hostID, false)
	if h, _ := s.Host(ctx, hostID); h.Disabled {
		t.Error("the agent must be enabled again")
	}
	if err := s.SetAgentDisabled(ctx, 999, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown host: %v, want ErrNotFound", err)
	}
}

func TestDeleteHostRemovesEverythingOfIt(t *testing.T) {
	s := open(t)
	agentID, hostID := enrolled(t, s)
	s.CreateEnrollmentToken(ctx, "e2", t0, t0.Add(time.Minute))
	_, keep, _ := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "e2", Hostname: "web-02", AgentTokenHash: "a2", ProtocolVersion: 1, Now: t0})
	s.AcceptReport(ctx, agentID, protocol.Report{ProtocolVersion: 1, TS: 1, Metrics: protocol.Metrics{UptimeS: 5}}, t0)
	s.QueueMetric(MetricPoint{HostID: hostID, TS: t0.Unix()})
	s.FlushMetrics(ctx)
	s.CreateAlert(ctx, hostID, "cpu_high", "", "", t0, true)
	s.CreateHostEnrollmentToken(ctx, "bound", hostID, t0, t0.Add(time.Minute))
	s.QueueMetric(MetricPoint{HostID: hostID, TS: t0.Unix() + 15})

	if err := s.DeleteHost(ctx, hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Host(ctx, hostID); !errors.Is(err, ErrNotFound) {
		t.Errorf("host still there: %v", err)
	}
	if _, err := s.AgentByTokenHash(ctx, "agent-hash"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the agent's credential must stop working: %v", err)
	}
	if pts, _, _ := s.History(ctx, hostID, t0.Add(-time.Hour), t0.Add(time.Hour), 100); len(pts) != 0 {
		t.Errorf("history must be gone: %v", pts)
	}
	if a, _ := s.Alerts(ctx, 10); len(a) != 0 {
		t.Errorf("alerts must be gone: %v", a)
	}
	if _, usable, _ := s.EnrollmentTokenHost(ctx, "bound", t0); usable {
		t.Error("a token bound to the host must be gone")
	}
	if err := s.FlushMetrics(ctx); err != nil {
		t.Errorf("a queued row of the deleted host must not fail the flush: %v", err)
	}
	if hosts, _ := s.Hosts(ctx); len(hosts) != 1 || hosts[0].ID != keep {
		t.Errorf("the other host must stay: %+v", hosts)
	}
	if err := s.DeleteHost(ctx, hostID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
}
