package web

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

func TestWatcherPublishesOnlyOnStatusChange(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.CreateEnrollmentToken(ctx, "e", now, now.Add(time.Minute))
	agentID, hostID, _ := st.Enroll(ctx, store.EnrollParams{EnrollTokenHash: "e", Hostname: "web-01", AgentTokenHash: "a", ProtocolVersion: 1, Now: now})
	st.AcceptReport(ctx, agentID, protocol.Report{ProtocolVersion: 1, TS: 1}, now)

	clock := now
	bus := live.New()
	events, cancel := bus.Subscribe()
	defer cancel()
	w := NewWatcher(st, bus, func() time.Time { return clock })

	w.Tick(ctx)
	clock = now.Add(30 * time.Second)
	w.Tick(ctx)
	if len(events) != 0 {
		t.Fatal("no event while the status is unchanged, including the first tick")
	}
	clock = now.Add(46 * time.Second)
	w.Tick(ctx)
	w.Tick(ctx)
	if len(events) != 1 {
		t.Fatalf("going offline must publish exactly one event, got %d", len(events))
	}
	if ev := <-events; ev.Kind != live.HostUpdated || ev.HostID != hostID {
		t.Errorf("event = %+v", ev)
	}
}
