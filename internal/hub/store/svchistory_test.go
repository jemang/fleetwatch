package store

import (
	"strings"
	"testing"
	"time"
)

// hour0 is an hour boundary; t0 is not necessarily one.
var hour0 = time.Unix(t0.Unix()/3600*3600, 0)

func addCheck(t *testing.T, s *Store, id, ts int64, down, ms int) {
	t.Helper()
	msN := 0
	if ms > 0 {
		msN = 1
	}
	if _, err := s.db.Exec(`INSERT INTO service_checks (service_id, res, ts, checks, down, ms_sum, ms_n) VALUES (?, 0, ?, 1, ?, ?, ?)`,
		id, ts, down, ms, msN); err != nil {
		t.Fatal(err)
	}
}

func hourly(t *testing.T, s *Store, id, ts int64) (checks, down, msSum, msN int64, ok bool) {
	t.Helper()
	err := s.db.QueryRow(`SELECT checks, down, ms_sum, ms_n FROM service_checks WHERE service_id = ? AND res = 3600 AND ts = ?`, id, ts).
		Scan(&checks, &down, &msSum, &msN)
	return checks, down, msSum, msN, err == nil
}

func TestRollupServiceChecksSumsCompletedHoursOnly(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	h := hour0.Unix()
	addCheck(t, s, id, h+10, 0, 40)
	addCheck(t, s, id, h+70, 1, 0)
	addCheck(t, s, id, h+3600+5, 0, 60) // the current hour
	if err := s.RollupServiceChecks(ctx, time.Unix(h+3600+30, 0)); err != nil {
		t.Fatal(err)
	}
	if c, d, ms, n, ok := hourly(t, s, id, h); !ok || c != 2 || d != 1 || ms != 40 || n != 1 {
		t.Fatalf("hour row = %d %d %d %d %v; want 2 1 40 1", c, d, ms, n, ok)
	}
	if _, _, _, _, ok := hourly(t, s, id, h+3600); ok {
		t.Fatal("the current hour must not be rolled up")
	}
}

func TestRollupServiceChecksCatchesUpAndRedoesTheLastHour(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	h := hour0.Unix()
	addCheck(t, s, id, h+10, 0, 40)
	s.RollupServiceChecks(ctx, time.Unix(h+3600, 0))
	addCheck(t, s, id, h+3590, 0, 20) // a late row for the hour already rolled up
	for i := int64(1); i <= 3; i++ {
		addCheck(t, s, id, h+i*3600+10, 0, 10)
	}
	s.RollupServiceChecks(ctx, time.Unix(h+4*3600, 0))
	if c, _, _, _, _ := hourly(t, s, id, h); c != 2 {
		t.Fatalf("first hour has %d checks; want 2 after the late row", c)
	}
	for i := int64(1); i <= 3; i++ {
		if c, _, _, _, ok := hourly(t, s, id, h+i*3600); !ok || c != 1 {
			t.Fatalf("hour %d not caught up: %d %v", i, c, ok)
		}
	}
}

func TestPruneServiceHistoryAndIncidents(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	now := t0
	day := 24 * time.Hour
	addCheck(t, s, id, now.Add(-8*day).Unix(), 0, 1) // past raw retention
	addCheck(t, s, id, now.Add(-6*day).Unix(), 0, 1)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO service_checks VALUES (?, 3600, ?, 1, 0, 0, 0)`, []any{id, now.Add(-91 * day).Unix()}},
		{`INSERT INTO service_checks VALUES (?, 3600, ?, 1, 0, 0, 0)`, []any{id, now.Add(-89 * day).Unix()}},
		{`INSERT INTO service_incidents (service_id, started_at, ended_at) VALUES (?, ?, ?)`, []any{id, now.Add(-92 * day).Unix(), now.Add(-91 * day).Unix()}},
		{`INSERT INTO service_incidents (service_id, started_at, ended_at) VALUES (?, ?, ?)`, []any{id, now.Add(-90 * day).Unix(), now.Add(-89 * day).Unix()}},
		{`INSERT INTO service_incidents (service_id, started_at) VALUES (?, ?)`, []any{id, now.Add(-200 * day).Unix()}}, // still open
	} {
		if _, err := s.db.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Prune(ctx, now, DefaultRetention); err != nil {
		t.Fatal(err)
	}
	var raw, hours, inc int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM service_checks WHERE res = 0), (SELECT COUNT(*) FROM service_checks WHERE res = 3600),
		(SELECT COUNT(*) FROM service_incidents)`).Scan(&raw, &hours, &inc)
	if raw != 1 || hours != 1 || inc != 2 {
		t.Fatalf("left %d raw, %d hourly, %d incidents; want 1, 1, 2", raw, hours, inc)
	}
}

func TestCheckStatsUseHourlyRowsAndRawRowsOnce(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	other, _ := s.CreateService(ctx, svc("B", "http://b", ""), t0)
	h := hour0.Unix()
	addCheck(t, s, id, h+10, 0, 40)        // hour h: rolled up below
	addCheck(t, s, id, h+20, 1, 0)         // hour h
	addCheck(t, s, id, h+3600+10, 0, 60)   // hour h+1: not rolled up yet
	addCheck(t, s, other, h+3600+10, 1, 0) // another service
	s.RollupServiceChecks(ctx, time.Unix(h+3600, 0))
	got, err := s.CheckStatsFor(ctx, id, HourStart(time.Unix(h+30, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if want := (CheckStats{Checks: 3, Down: 1, MsSum: 100, MsN: 2}); got != want {
		t.Fatalf("stats = %+v; want %+v (each check once)", got, want)
	}
	all, err := s.CheckStatsAll(ctx, HourStart(time.Unix(h+30, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if all[id] != got || all[other] != (CheckStats{Checks: 1, Down: 1}) {
		t.Fatalf("all = %+v; want the same per service", all)
	}
	// Raw rows of an hour older than the raw retention: only the hourly row is left.
	s.db.Exec(`DELETE FROM service_checks WHERE res = 0 AND ts < ?`, h+3600)
	if got, _ := s.CheckStatsFor(ctx, id, HourStart(time.Unix(h, 0))); got.Checks != 3 {
		t.Fatalf("after raw prune checks = %d; want 3 from hourly + raw", got.Checks)
	}
}

func TestCheckStatsEmptyAndRawChecks(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	if got, err := s.CheckStatsFor(ctx, id, hour0); err != nil || got != (CheckStats{}) {
		t.Fatalf("empty stats = %+v, %v", got, err)
	}
	addCheck(t, s, id, hour0.Unix()+50, 1, 0)
	addCheck(t, s, id, hour0.Unix()+5, 0, 10)
	addCheck(t, s, id, hour0.Unix()-5, 0, 10) // before from
	rows, err := s.RawChecks(ctx, id, hour0)
	if err != nil || len(rows) != 2 || rows[0].TS != hour0.Unix()+5 || rows[0].Down || !rows[1].Down {
		t.Fatalf("raw = %+v, %v; want two rows oldest first", rows, err)
	}
}

func TestCheckStatsAllUsesAnIndex(t *testing.T) {
	s := open(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN SELECT service_id, SUM(checks), SUM(down), SUM(ms_sum), SUM(ms_n) `+statsFrom(``)+` GROUP BY service_id`, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		rows.Scan(&id, &parent, &unused, &detail)
		plan = append(plan, detail)
	}
	for _, p := range plan {
		if strings.HasPrefix(p, "SCAN c") || strings.HasPrefix(p, "SCAN service_checks") {
			t.Fatalf("the 30-day query reads every stored check: %q", plan)
		}
	}
}

func TestRecentIncidents(t *testing.T) {
	s := open(t)
	a, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	b, _ := s.CreateService(ctx, svc("B", "http://b", ""), t0)
	c, _ := s.CreateService(ctx, svc("C", "http://c", ""), t0)
	for _, q := range []struct {
		id, start int64
		ended     any
	}{{a, 100, 200}, {b, 300, nil}, {c, 250, 260}} {
		if _, err := s.db.Exec(`INSERT INTO service_incidents (service_id, started_at, ended_at, reason) VALUES (?, ?, ?, 'timeout')`, q.id, q.start, q.ended); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.RecentIncidents(ctx, 2)
	if err != nil || len(got) != 2 || got[0].ServiceName != "B" || !got[0].Ended.IsZero() || got[1].ServiceName != "C" || got[1].ServiceID != c || got[1].Reason != "timeout" {
		t.Fatalf("recent = %+v, %v", got, err)
	}
	s.DeleteService(ctx, b)
	if got, _ := s.RecentIncidents(ctx, 5); len(got) != 2 || got[0].ServiceName != "C" {
		t.Fatalf("after delete = %+v", got)
	}
}
