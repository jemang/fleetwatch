package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"fleetwatch/internal/protocol"
)

// hourStart is a Unix time on an hour boundary, so buckets are easy to read.
const hourStart = int64(1_789_999_200)

func fp(v float64) *float64 { return &v }

func at(sec int64) time.Time { return time.Unix(hourStart+sec, 0) }

func newHost(t *testing.T, s *Store, name string) int64 {
	t.Helper()
	s.CreateEnrollmentToken(ctx, "e-"+name, t0, t0.Add(time.Minute))
	_, hostID, err := s.Enroll(ctx, EnrollParams{EnrollTokenHash: "e-" + name, Hostname: name, AgentTokenHash: "a-" + name, ProtocolVersion: 1, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	return hostID
}

func rawCPU(t *testing.T, s *Store, host int64, values map[int64]float64) {
	t.Helper()
	for sec, v := range values {
		s.QueueMetric(MetricPoint{HostID: host, TS: hourStart + sec, CPU: fp(v)})
	}
	if err := s.FlushMetrics(ctx); err != nil {
		t.Fatal(err)
	}
}

func cpuAt(t *testing.T, s *Store, host int64, res int, sec int64) (float64, bool) {
	t.Helper()
	var v sql.NullFloat64
	err := s.db.QueryRow(`SELECT cpu FROM host_metrics WHERE host_id = ? AND res = ? AND ts = ?`, host, res, hourStart+sec).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return v.Float64, v.Valid
}

func TestMigrationFromVersion1KeepsDataAndAddsHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range migrations[0] {
		if _, err := old.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	old.Exec(`PRAGMA user_version = 1`)
	old.Exec(`INSERT INTO admin (id, password_hash) VALUES (1, 'kept')`)
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if h, _ := s.AdminPasswordHash(ctx); h != "kept" {
		t.Errorf("data from schema version 1 must survive, admin hash = %q", h)
	}
	var version int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&version)
	if version != len(migrations) {
		t.Errorf("user_version = %d, want %d", version, len(migrations))
	}
	host := newHost(t, s, "web-01")
	rawCPU(t, s, host, map[int64]float64{0: 10})
	if _, ok := cpuAt(t, s, host, 0, 0); !ok {
		t.Error("history table must exist after migration")
	}
}

func TestQueuedMetricsAppearOnlyAfterFlush(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	s.QueueMetric(MetricPoint{HostID: host, TS: hourStart, CPU: fp(10), Mem: fp(20), Disk: fp(30), Load1: fp(0.5)})
	if _, ok := cpuAt(t, s, host, 0, 0); ok {
		t.Fatal("a queued row must not be written before the flush")
	}
	if err := s.FlushMetrics(ctx); err != nil {
		t.Fatal(err)
	}
	pts, _, err := s.History(ctx, host, at(0), at(60), 100)
	if err != nil || len(pts) != 1 || *pts[0].CPU != 10 || *pts[0].Mem != 20 || *pts[0].Disk != 30 || *pts[0].Load1 != 0.5 {
		t.Errorf("history after flush = %+v, %v", pts, err)
	}
	if err := s.FlushMetrics(ctx); err != nil {
		t.Errorf("flushing an empty queue must be a no-op: %v", err)
	}
}

func TestPointFromReport(t *testing.T) {
	cpu := 14.2
	r := protocol.Report{Metrics: protocol.Metrics{
		CPUPct: &cpu, Load: []float64{0.42, 0.3, 0.2},
		Mem:   &protocol.Mem{Total: 1000, Used: 250},
		Disks: []protocol.Disk{{Mount: "/", Total: 1000, Used: 400}, {Mount: "/data", Total: 200, Used: 180}},
	}}
	p := PointFromReport(7, r, at(30))
	if p.HostID != 7 || p.TS != hourStart+30 || *p.CPU != 14.2 || *p.Mem != 25 || *p.Disk != 90 || *p.Load1 != 0.42 {
		t.Errorf("point = %+v (cpu %v mem %v disk %v load %v)", p, *p.CPU, *p.Mem, *p.Disk, *p.Load1)
	}
	empty := PointFromReport(7, protocol.Report{}, at(30))
	if empty.CPU != nil || empty.Mem != nil || empty.Disk != nil || empty.Load1 != nil {
		t.Errorf("a report without values must give a point without values: %+v", empty)
	}
}

func TestRollupAveragesCompletedBucketsOnly(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	rawCPU(t, s, host, map[int64]float64{0: 10, 15: 20, 30: 30, 45: 40, 60: 50, 75: 50, 120: 99})

	if err := s.Rollup(ctx, at(125)); err != nil {
		t.Fatal(err)
	}
	if v, ok := cpuAt(t, s, host, 60, 0); !ok || v != 25 {
		t.Errorf("first minute average = %v, %v; want 25", v, ok)
	}
	if v, ok := cpuAt(t, s, host, 60, 60); !ok || v != 50 {
		t.Errorf("second minute average = %v, %v; want 50", v, ok)
	}
	if _, ok := cpuAt(t, s, host, 60, 120); ok {
		t.Error("the minute still in progress must not be rolled up")
	}
	if _, ok := cpuAt(t, s, host, 300, 0); ok {
		t.Error("the 5-minute bucket is not complete yet")
	}
}

func TestRollupCatchesUpAfterAPause(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	rawCPU(t, s, host, map[int64]float64{0: 10, 30: 30, 60: 50, 3540: 70})
	// The Hub was stopped for an hour: one run must fill every level.
	if err := s.Rollup(ctx, at(3700)); err != nil {
		t.Fatal(err)
	}
	if v, ok := cpuAt(t, s, host, 60, 0); !ok || v != 20 {
		t.Errorf("minute 0 = %v, %v; want 20", v, ok)
	}
	if v, ok := cpuAt(t, s, host, 300, 0); !ok || v != 35 {
		t.Errorf("first 5 minutes = %v, %v; want 35 (average of minute averages 20 and 50)", v, ok)
	}
	if v, ok := cpuAt(t, s, host, 3600, 0); !ok || v != 52.5 {
		t.Errorf("hour = %v, %v; want 52.5 (average of the 5-minute averages 35 and 70)", v, ok)
	}
	// A second run changes nothing.
	s.Rollup(ctx, at(3700))
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM host_metrics WHERE res = 3600`).Scan(&n)
	if n != 1 {
		t.Errorf("repeating the rollup must not add rows, hour rows = %d", n)
	}
}

func TestPruneDeletesOnlyRowsPastTheirRetention(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	now := at(0)
	ret := Retention{Raw: 24 * time.Hour, Min1: 7 * 24 * time.Hour, Min5: 30 * 24 * time.Hour, Hour1: 365 * 24 * time.Hour}
	ages := map[int][2]time.Duration{ // resolution: {kept age, deleted age}
		0:    {23 * time.Hour, 25 * time.Hour},
		60:   {6 * 24 * time.Hour, 8 * 24 * time.Hour},
		300:  {29 * 24 * time.Hour, 31 * 24 * time.Hour},
		3600: {364 * 24 * time.Hour, 366 * 24 * time.Hour},
	}
	for res, pair := range ages {
		for _, age := range pair {
			if _, err := s.db.Exec(`INSERT INTO host_metrics (host_id, res, ts, cpu) VALUES (?, ?, ?, 1)`, host, res, now.Add(-age).Unix()); err != nil {
				t.Fatal(err)
			}
		}
	}
	deleted, err := s.Prune(ctx, now, ret)
	if err != nil || deleted != 4 {
		t.Fatalf("deleted = %d, %v; want 4", deleted, err)
	}
	for res, pair := range ages {
		var n int
		s.db.QueryRow(`SELECT COUNT(*) FROM host_metrics WHERE res = ? AND ts = ?`, res, now.Add(-pair[0]).Unix()).Scan(&n)
		if n != 1 {
			t.Errorf("resolution %d: the row inside the retention must stay", res)
		}
	}
}

func TestHistoryPicksResolutionAndLimitsPoints(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	for sec := int64(0); sec < 3600; sec += 15 {
		s.QueueMetric(MetricPoint{HostID: host, TS: hourStart + sec, CPU: fp(float64(sec / 60))})
	}
	s.FlushMetrics(ctx)
	for sec := int64(0); sec < 86400; sec += 60 {
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO host_metrics (host_id, res, ts, cpu) VALUES (?, 60, ?, 77)`, host, hourStart+sec); err != nil {
			t.Fatal(err)
		}
	}

	pts, step, err := s.History(ctx, host, at(0), at(3600), 60)
	if err != nil || len(pts) != 60 || step != 60 {
		t.Fatalf("1 hour at 60 points: %d points, step %d, %v", len(pts), step, err)
	}
	if *pts[5].CPU != 5 || pts[5].TS != hourStart+300 {
		t.Errorf("an hour is read from raw rows: point 5 = %v at %d", *pts[5].CPU, pts[5].TS-hourStart)
	}
	pts, step, err = s.History(ctx, host, at(0), at(86400), 300)
	if err != nil || len(pts) != 288 || step != 300 || *pts[0].CPU != 77 {
		t.Fatalf("24 hours at 300 points: %d points, step %d, first %v, %v; want the 1-minute rows in 5-minute steps", len(pts), step, pts[0].CPU, err)
	}
	if pts, _, _ := s.History(ctx, host+99, at(0), at(3600), 60); len(pts) != 0 {
		t.Error("an unknown host has no history")
	}
}

func TestFleetHistoryAveragesAcrossHosts(t *testing.T) {
	s := open(t)
	a, b := newHost(t, s, "a"), newHost(t, s, "b")
	rawCPU(t, s, a, map[int64]float64{0: 10, 60: 20})
	rawCPU(t, s, b, map[int64]float64{5: 30})
	pts, err := s.FleetHistory(ctx, at(0), at(120), time.Minute)
	if err != nil || len(pts) != 2 || *pts[0].CPU != 20 || *pts[1].CPU != 20 {
		t.Fatalf("fleet history = %v, %v; want [20 20]", fmt.Sprint(pts), err)
	}
}
