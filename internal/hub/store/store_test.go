package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fleetwatch/internal/protocol"
)

var (
	ctx = context.Background()
	t0  = time.Unix(1_790_000_000, 0)
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func enrolled(t *testing.T, s *Store) (agentID, hostID int64) {
	t.Helper()
	if err := s.CreateEnrollmentToken(ctx, "enroll-hash", t0, t0.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	agentID, hostID, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "enroll-hash", Hostname: "web-01", AgentTokenHash: "agent-hash", AgentVersion: "0.1.0", ProtocolVersion: 1, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	return agentID, hostID
}

func TestOpenTwiceKeepsDataAndUsesWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.CreateAdmin(ctx, "hash")
	var mode string
	s.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if ok, _ := s.AdminExists(ctx); !ok {
		t.Error("reopening must not recreate the schema")
	}
}

func TestTokens(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) != 43 {
		t.Errorf("tokens must be unique 32-byte base64url values: %q %q", a, b)
	}
	if HashToken(a) == a || HashToken(a) != HashToken(a) || len(HashToken(a)) != 64 {
		t.Error("HashToken must be a stable hex SHA-256")
	}
}

func TestAdmin(t *testing.T) {
	s := open(t)
	if ok, _ := s.AdminExists(ctx); ok {
		t.Fatal("fresh database must have no admin")
	}
	if _, err := s.AdminPasswordHash(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if err := s.CreateAdmin(ctx, "hash"); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.AdminPasswordHash(ctx); h != "hash" {
		t.Errorf("hash = %q", h)
	}
	if err := s.CreateAdmin(ctx, "other"); err == nil {
		t.Error("a second admin row must be rejected")
	}
}

func TestSessions(t *testing.T) {
	s := open(t)
	s.CreateSession(ctx, "old", t0, t0.Add(time.Hour))
	s.CreateSession(ctx, "live", t0.Add(2*time.Hour), t0.Add(10*time.Hour))
	if ok, _ := s.SessionValid(ctx, "live", t0.Add(3*time.Hour)); !ok {
		t.Error("live session must be valid")
	}
	if ok, _ := s.SessionValid(ctx, "live", t0.Add(11*time.Hour)); ok {
		t.Error("expired session must be invalid")
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&n)
	if n != 1 {
		t.Errorf("creating a session must delete expired ones, rows = %d", n)
	}
	s.DeleteSession(ctx, "live")
	if ok, _ := s.SessionValid(ctx, "live", t0.Add(3*time.Hour)); ok {
		t.Error("deleted session must be invalid")
	}
}

func TestEnrollOnceOnly(t *testing.T) {
	s := open(t)
	agentID, hostID := enrolled(t, s)
	if agentID == 0 || hostID == 0 {
		t.Fatalf("ids = %d, %d", agentID, hostID)
	}
	_, _, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "enroll-hash", Hostname: "x", AgentTokenHash: "second", ProtocolVersion: 1, Now: t0})
	if !errors.Is(err, ErrEnrollmentRejected) {
		t.Errorf("reused token: err = %v, want ErrEnrollmentRejected", err)
	}
	a, err := s.AgentByTokenHash(ctx, "agent-hash")
	if err != nil || a.ID != agentID || a.HostID != hostID || a.Disabled {
		t.Errorf("agent = %+v, %v", a, err)
	}
	if _, err := s.AgentByTokenHash(ctx, "enroll-hash"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an enrollment token must not resolve to an agent: %v", err)
	}
}

func TestEnrollRejectsExpiredRevokedAndUnknown(t *testing.T) {
	s := open(t)
	s.CreateEnrollmentToken(ctx, "expired", t0, t0.Add(15*time.Minute))
	s.CreateEnrollmentToken(ctx, "revoked", t0, t0.Add(15*time.Minute))
	s.db.Exec("UPDATE enrollment_tokens SET revoked_at = ? WHERE token_hash = 'revoked'", t0.Unix())
	cases := map[string]time.Time{"expired": t0.Add(15 * time.Minute), "revoked": t0, "unknown": t0}
	for hash, now := range cases {
		_, _, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: hash, Hostname: "x", AgentTokenHash: "a-" + hash, ProtocolVersion: 1, Now: now})
		if !errors.Is(err, ErrEnrollmentRejected) {
			t.Errorf("%s token: err = %v, want ErrEnrollmentRejected", hash, err)
		}
	}
	if hosts, _ := s.Hosts(ctx); len(hosts) != 0 {
		t.Errorf("rejected enrollment must not create hosts, got %d", len(hosts))
	}
}

func TestConcurrentEnrollWithOneTokenSucceedsOnce(t *testing.T) {
	s := open(t)
	s.CreateEnrollmentToken(ctx, "race", t0, t0.Add(15*time.Minute))
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "race", Hostname: "x", AgentTokenHash: fmt.Sprintf("agent-%d", i), ProtocolVersion: 1, Now: t0})
			switch {
			case err == nil:
				ok.Add(1)
			case !errors.Is(err, ErrEnrollmentRejected):
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	hosts, _ := s.Hosts(ctx)
	if ok.Load() != 1 || len(hosts) != 1 {
		t.Errorf("successes = %d, hosts = %d; want 1 and 1", ok.Load(), len(hosts))
	}
}

func TestAcceptReportStoresLatestStateAndRejectsReplay(t *testing.T) {
	s := open(t)
	agentID, hostID := enrolled(t, s)

	h, _ := s.Host(ctx, hostID)
	if h.Name != "web-01" || h.Metrics != nil || !h.LastSeen.IsZero() {
		t.Errorf("fresh host = %+v", h)
	}

	cpu := 14.2
	first := protocol.Report{ProtocolVersion: 1, AgentVersion: "0.1.0", TS: 100,
		Metrics:   protocol.Metrics{CPUPct: &cpu, UptimeS: 60},
		Inventory: &protocol.Inventory{Hostname: "renamed", Cores: 4}}
	seen := t0.Add(time.Minute)
	if err := s.AcceptReport(ctx, agentID, first, seen); err != nil {
		t.Fatal(err)
	}
	second := protocol.Report{ProtocolVersion: 1, TS: 115, Metrics: protocol.Metrics{UptimeS: 75}}
	if err := s.AcceptReport(ctx, agentID, second, seen.Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}

	h, _ = s.Host(ctx, hostID)
	if h.Name != "renamed" || h.Metrics.UptimeS != 75 || h.Metrics.CPUPct != nil {
		t.Errorf("latest state must replace the previous one: %+v metrics %+v", h, h.Metrics)
	}
	if h.Inventory == nil || h.Inventory.Cores != 4 {
		t.Errorf("a report without inventory must keep the stored inventory: %+v", h.Inventory)
	}
	if !h.LastSeen.Equal(seen.Add(15 * time.Second)) {
		t.Errorf("LastSeen = %v, want the Hub time of the last report", h.LastSeen)
	}

	var replay *ReplayError
	for _, ts := range []int64{115, 90} {
		err := s.AcceptReport(ctx, agentID, protocol.Report{ProtocolVersion: 1, TS: ts}, seen.Add(time.Minute))
		if !errors.As(err, &replay) || replay.LastTS != 115 {
			t.Errorf("ts %d: err = %v, want ReplayError with LastTS 115", ts, err)
		}
	}
	h, _ = s.Host(ctx, hostID)
	if h.Metrics.UptimeS != 75 || !h.LastSeen.Equal(seen.Add(15*time.Second)) {
		t.Error("a rejected report must change nothing")
	}
}

func TestHostsOrderedByName(t *testing.T) {
	s := open(t)
	for i, name := range []string{"zeta", "alpha"} {
		eh, ah := fmt.Sprintf("e%d", i), fmt.Sprintf("a%d", i)
		s.CreateEnrollmentToken(ctx, eh, t0, t0.Add(time.Minute))
		s.Enroll(ctx, EnrollParams{EnrollTokenHash: eh, Hostname: name, AgentTokenHash: ah, ProtocolVersion: 1, Now: t0})
	}
	hosts, err := s.Hosts(ctx)
	if err != nil || len(hosts) != 2 || hosts[0].Name != "alpha" {
		t.Errorf("hosts = %+v, %v", hosts, err)
	}
	if _, err := s.Host(ctx, 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown host: err = %v, want ErrNotFound", err)
	}
}
