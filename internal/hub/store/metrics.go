package store

import (
	"context"
	"database/sql"
	"time"

	"fleetwatch/internal/protocol"
)

// MetricPoint is one history row. A nil value means "not reported".
type MetricPoint struct {
	HostID, TS            int64
	CPU, Mem, Disk, Load1 *float64
}

// PointFromReport derives the history row of an accepted report: memory as a
// percentage, disk as the fullest mount.
func PointFromReport(hostID int64, r protocol.Report, now time.Time) MetricPoint {
	p := MetricPoint{HostID: hostID, TS: now.Unix(), CPU: r.Metrics.CPUPct}
	if m := r.Metrics.Mem; m != nil && m.Total > 0 {
		v := float64(m.Used) / float64(m.Total) * 100
		p.Mem = &v
	}
	for _, d := range r.Metrics.Disks {
		if d.Total == 0 {
			continue
		}
		if v := float64(d.Used) / float64(d.Total) * 100; p.Disk == nil || v > *p.Disk {
			p.Disk = &v
		}
	}
	if len(r.Metrics.Load) > 0 {
		v := r.Metrics.Load[0]
		p.Load1 = &v
	}
	return p
}

// QueueMetric holds a history row in memory until the next flush, so many
// reports share one transaction.
func (s *Store) QueueMetric(p MetricPoint) {
	s.mu.Lock()
	s.pending = append(s.pending, p)
	s.mu.Unlock()
}

func (s *Store) FlushMetrics(ctx context.Context) error {
	s.mu.Lock()
	batch := s.pending
	s.pending = nil
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO host_metrics (host_id, res, ts, cpu, mem, disk, load1) VALUES (?, 0, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, p := range batch {
		// A host deleted while its row was queued fails the foreign key; skip it.
		stmt.ExecContext(ctx, p.HostID, p.TS, p.CPU, p.Mem, p.Disk, p.Load1)
	}
	return tx.Commit()
}

// RunMetricWriter flushes the queue on a timer until ctx ends, then once more.
func (s *Store) RunMetricWriter(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.FlushMetrics(context.Background())
			return
		case <-t.C:
			s.FlushMetrics(ctx)
		}
	}
}

// Rollup fills the 1-minute, 5-minute and 1-hour averages for every completed
// bucket since the newest one stored, so a Hub that was stopped catches up.
func (s *Store) Rollup(ctx context.Context, now time.Time) error {
	for _, lvl := range [][2]int64{{0, 60}, {60, 300}, {300, 3600}} {
		src, dst := lvl[0], lvl[1]
		var start sql.NullInt64
		err := s.db.QueryRowContext(ctx,
			`SELECT COALESCE((SELECT MAX(ts) FROM host_metrics WHERE res = ?), (SELECT MIN(ts) FROM host_metrics WHERE res = ?))`,
			dst, src).Scan(&start)
		if err != nil {
			return err
		}
		if !start.Valid {
			continue
		}
		from, to := start.Int64/dst*dst, now.Unix()/dst*dst
		if to <= from {
			continue
		}
		_, err = s.db.ExecContext(ctx,
			`INSERT OR REPLACE INTO host_metrics (host_id, res, ts, cpu, mem, disk, load1)
			 SELECT host_id, ?, (ts / ?) * ?, AVG(cpu), AVG(mem), AVG(disk), AVG(load1)
			 FROM host_metrics WHERE res = ? AND ts >= ? AND ts < ?
			 GROUP BY host_id, ts / ?`,
			dst, dst, dst, src, from, to, dst)
		if err != nil {
			return err
		}
	}
	return nil
}

type Retention struct{ Raw, Min1, Min5, Hour1 time.Duration }

var DefaultRetention = Retention{Raw: 24 * time.Hour, Min1: 7 * 24 * time.Hour, Min5: 30 * 24 * time.Hour, Hour1: 365 * 24 * time.Hour}

// Prune deletes history rows older than their resolution's retention.
func (s *Store) Prune(ctx context.Context, now time.Time, r Retention) (int64, error) {
	var total int64
	for res, keep := range map[int]time.Duration{0: r.Raw, 60: r.Min1, 300: r.Min5, 3600: r.Hour1} {
		result, err := s.db.ExecContext(ctx, `DELETE FROM host_metrics WHERE res = ? AND ts < ?`, res, now.Add(-keep).Unix())
		if err != nil {
			return total, err
		}
		n, _ := result.RowsAffected()
		total += n
	}
	return total, nil
}

// resolutionFor picks the stored resolution for a time span and the spacing
// of its rows in seconds.
func resolutionFor(span time.Duration) (res, base int64) {
	switch {
	case span <= 2*time.Hour:
		return 0, 15
	case span <= 48*time.Hour:
		return 60, 60
	case span <= 14*24*time.Hour:
		return 300, 300
	}
	return 3600, 3600
}

func scanPoints(rows *sql.Rows, hostID int64) ([]MetricPoint, error) {
	defer rows.Close()
	var out []MetricPoint
	for rows.Next() {
		p := MetricPoint{HostID: hostID}
		var cpu, mem, disk, load sql.NullFloat64
		if err := rows.Scan(&p.TS, &cpu, &mem, &disk, &load); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			v   sql.NullFloat64
			dst **float64
		}{{cpu, &p.CPU}, {mem, &p.Mem}, {disk, &p.Disk}, {load, &p.Load1}} {
			if f.v.Valid {
				v := f.v.Float64
				*f.dst = &v
			}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// History returns one host's values between from and to, averaged into at
// most maxPoints buckets. step is the bucket width in seconds.
func (s *Store) History(ctx context.Context, hostID int64, from, to time.Time, maxPoints int) (pts []MetricPoint, step int64, err error) {
	res, base := resolutionFor(to.Sub(from))
	step = base
	if maxPoints > 0 {
		span := to.Unix() - from.Unix()
		if need := (span + int64(maxPoints) - 1) / int64(maxPoints); need > step {
			step = (need + base - 1) / base * base
		}
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT (ts / ?) * ? AS b, AVG(cpu), AVG(mem), AVG(disk), AVG(load1)
		 FROM host_metrics WHERE host_id = ? AND res = ? AND ts >= ? AND ts < ?
		 GROUP BY b ORDER BY b`,
		step, step, hostID, res, from.Unix(), to.Unix())
	if err != nil {
		return nil, step, err
	}
	pts, err = scanPoints(rows, hostID)
	return pts, step, err
}

// FleetHistory averages every host's values per bucket of the given width.
func (s *Store) FleetHistory(ctx context.Context, from, to time.Time, step time.Duration) ([]MetricPoint, error) {
	res, _ := resolutionFor(to.Sub(from))
	sec := int64(step / time.Second)
	rows, err := s.db.QueryContext(ctx,
		`SELECT (ts / ?) * ? AS b, AVG(cpu), AVG(mem), AVG(disk), AVG(load1)
		 FROM host_metrics WHERE res = ? AND ts >= ? AND ts < ?
		 GROUP BY b ORDER BY b`,
		sec, sec, res, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	return scanPoints(rows, 0)
}
