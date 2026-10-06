package store

import (
	"context"
	"database/sql"
	"time"
)

// RollupServiceChecks sums raw checks into hourly rows for every completed
// hour since the newest hourly row, which is summed again: a check that
// finished just before the hour can be saved just after the rollup.
func (s *Store) RollupServiceChecks(ctx context.Context, now time.Time) error {
	var start sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE((SELECT MAX(ts) FROM service_checks WHERE res = 3600),
		(SELECT MIN(ts) FROM service_checks WHERE res = 0))`).Scan(&start)
	if err != nil || !start.Valid {
		return err
	}
	from, to := start.Int64/3600*3600, now.Unix()/3600*3600
	if to <= from {
		return nil
	}
	_, err = s.db.ExecContext(ctx, `INSERT OR REPLACE INTO service_checks (service_id, res, ts, checks, down, ms_sum, ms_n)
		SELECT service_id, 3600, (ts / 3600) * 3600, SUM(checks), SUM(down), SUM(ms_sum), SUM(ms_n)
		FROM service_checks WHERE res = 0 AND ts >= ? AND ts < ? GROUP BY service_id, ts / 3600`, from, to)
	return err
}

type CheckStats struct{ Checks, Down, MsSum, MsN int64 }

// HourStart is the hour boundary at or before t; stats windows start there,
// because hourly rows cover whole hours.
func HourStart(t time.Time) time.Time { return time.Unix(t.Unix()/3600*3600, 0) }

// statsFrom is the checks of a window, counted once: the hourly rows, and
// the raw rows of hours that have no hourly row yet. Raw rows before the
// newest hourly row are not read: every hour before it is rolled up.
func statsFrom(where string) string {
	return `FROM (SELECT service_id, checks, down, ms_sum, ms_n FROM service_checks WHERE res = 3600 AND ts >= ?1` + where + `
		UNION ALL
		SELECT service_id, checks, down, ms_sum, ms_n FROM service_checks c WHERE res = 0
			AND ts >= max(?1, (SELECT COALESCE(MAX(ts), 0) FROM service_checks WHERE res = 3600))` + where + `
			AND NOT EXISTS (SELECT 1 FROM service_checks h WHERE h.service_id = c.service_id AND h.res = 3600 AND h.ts = (c.ts / 3600) * 3600))`
}

func (s *Store) CheckStatsFor(ctx context.Context, id int64, from time.Time) (CheckStats, error) {
	var st CheckStats
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(checks), 0), COALESCE(SUM(down), 0), COALESCE(SUM(ms_sum), 0), COALESCE(SUM(ms_n), 0) `+
		statsFrom(` AND service_id = ?2`), from.Unix(), id).Scan(&st.Checks, &st.Down, &st.MsSum, &st.MsN)
	return st, err
}

func (s *Store) CheckStatsAll(ctx context.Context, from time.Time) (map[int64]CheckStats, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT service_id, SUM(checks), SUM(down), SUM(ms_sum), SUM(ms_n) `+
		statsFrom(``)+` GROUP BY service_id`, from.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]CheckStats{}
	for rows.Next() {
		var id int64
		var st CheckStats
		if err := rows.Scan(&id, &st.Checks, &st.Down, &st.MsSum, &st.MsN); err != nil {
			return nil, err
		}
		out[id] = st
	}
	return out, rows.Err()
}

type CheckRow struct {
	TS   int64
	Down bool
}

// RawChecks lists a service's checks since from, oldest first.
func (s *Store) RawChecks(ctx context.Context, id int64, from time.Time) ([]CheckRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, down FROM service_checks WHERE service_id = ? AND res = 0 AND ts >= ? ORDER BY ts`, id, from.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckRow
	for rows.Next() {
		var r CheckRow
		if err := rows.Scan(&r.TS, &r.Down); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
