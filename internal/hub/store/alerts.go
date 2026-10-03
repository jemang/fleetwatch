package store

import (
	"context"
	"database/sql"
	"time"
)

// Alert is one condition on one host. An open alert (ResolvedAt zero) is
// pending until FiredAt is set.
type Alert struct {
	ID, HostID                    int64
	Host                          string
	Kind, Subject, Detail         string
	PendingSince                  time.Time
	FiredAt, ResolvedAt           time.Time
	DismissedAt                   time.Time
	NotifiedFire, NotifiedResolve bool
}

func (a Alert) State() string {
	switch {
	case !a.ResolvedAt.IsZero():
		return "resolved"
	case !a.DismissedAt.IsZero():
		return "dismissed"
	case !a.FiredAt.IsZero():
		return "firing"
	}
	return "pending"
}

const alertSelect = `SELECT a.id, a.host_id, ` + shownName + `, a.kind, a.subject, a.detail, a.pending_since,
	a.fired_at, a.resolved_at, a.dismissed_at, a.notified_fire, a.notified_resolve
	FROM alerts a JOIN hosts h ON h.id = a.host_id`

func unixOrZero(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0)
}

func (s *Store) queryAlerts(ctx context.Context, query string, args ...any) ([]Alert, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var pending int64
		var fired, resolved, dismissed sql.NullInt64
		if err := rows.Scan(&a.ID, &a.HostID, &a.Host, &a.Kind, &a.Subject, &a.Detail, &pending, &fired, &resolved, &dismissed, &a.NotifiedFire, &a.NotifiedResolve); err != nil {
			return nil, err
		}
		a.PendingSince, a.FiredAt, a.ResolvedAt, a.DismissedAt = time.Unix(pending, 0), unixOrZero(fired), unixOrZero(resolved), unixOrZero(dismissed)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Alert returns one alert; sql.ErrNoRows when there is none with that id.
func (s *Store) Alert(ctx context.Context, id int64) (Alert, error) {
	out, err := s.queryAlerts(ctx, alertSelect+` WHERE a.id = ?`, id)
	if err == nil && len(out) == 0 {
		err = sql.ErrNoRows
	}
	if err != nil {
		return Alert{}, err
	}
	return out[0], nil
}

func (s *Store) OpenAlerts(ctx context.Context) ([]Alert, error) {
	return s.queryAlerts(ctx, alertSelect+` WHERE a.resolved_at IS NULL ORDER BY a.id`)
}

// Alerts lists open alerts first, then the most recently resolved ones.
func (s *Store) Alerts(ctx context.Context, resolvedLimit int) ([]Alert, error) {
	open, err := s.OpenAlerts(ctx)
	if err != nil {
		return nil, err
	}
	done, err := s.queryAlerts(ctx, alertSelect+` WHERE a.resolved_at IS NOT NULL ORDER BY a.resolved_at DESC, a.id DESC LIMIT ?`, resolvedLimit)
	return append(open, done...), err
}

// UnnotifiedAlerts lists alerts that fired or resolved and whose message has
// not been delivered yet.
func (s *Store) UnnotifiedAlerts(ctx context.Context) ([]Alert, error) {
	return s.queryAlerts(ctx, alertSelect+` WHERE a.fired_at IS NOT NULL AND
		(a.notified_fire = 0 OR (a.resolved_at IS NOT NULL AND a.notified_resolve = 0)) ORDER BY a.id`)
}

func (s *Store) FiringCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE fired_at IS NOT NULL AND resolved_at IS NULL AND dismissed_at IS NULL`).Scan(&n)
	return n, err
}

// CreateAlert opens an alert; fire makes it firing at once. It fails when an
// open alert for the same host, kind and subject exists.
func (s *Store) CreateAlert(ctx context.Context, hostID int64, kind, subject, detail string, now time.Time, fire bool) (int64, error) {
	var fired any
	if fire {
		fired = now.Unix()
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO alerts (host_id, kind, subject, detail, pending_since, fired_at) VALUES (?, ?, ?, ?, ?, ?)`,
		hostID, kind, subject, detail, now.Unix(), fired)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FireAlert(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET fired_at = ? WHERE id = ? AND fired_at IS NULL`, now.Unix(), id)
	return err
}

func (s *Store) SetAlertDetail(ctx context.Context, id int64, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET detail = ? WHERE id = ?`, detail, id)
	return err
}

func (s *Store) ResolveAlert(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET resolved_at = ? WHERE id = ? AND resolved_at IS NULL`, now.Unix(), id)
	return err
}

// DismissAlert hides a firing alert without resolving it, so the condition
// does not raise it again while it lasts.
func (s *Store) DismissAlert(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET dismissed_at = ? WHERE id = ? AND fired_at IS NOT NULL AND resolved_at IS NULL AND dismissed_at IS NULL`, now.Unix(), id)
	return err
}

func (s *Store) DeleteAlert(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE id = ?`, id)
	return err
}

// MarkNotified records that the "firing" or "resolved" message was delivered.
func (s *Store) MarkNotified(ctx context.Context, id int64, event string) error {
	col := "notified_fire"
	if event == "resolved" {
		col = "notified_resolve"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE alerts SET `+col+` = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) PruneAlerts(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (s *Store) SetSettings(ctx context.Context, values map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range values {
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
