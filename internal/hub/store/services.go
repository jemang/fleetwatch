package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Service is a web application. HostID 0 means no related host; Host is that
// host's shown name. IconAt is when the icon was stored, 0 when there is none.
// The fields after CreatedAt are the latest check; times are unix seconds,
// 0 when unknown.
type Service struct {
	ID                            int64
	Name, URL, Group, Description string
	HostID                        int64
	Host                          string
	IntervalS, TimeoutS           int
	ExpectedStatus                int // 0: any 2xx or 3xx
	AcceptSelfSigned, Enabled     bool
	IconAt                        int64
	CreatedAt                     time.Time

	State                                string // unknown, online, degraded, down, paused
	StateSince, CheckedAt, CertExpiresAt int64
	LastMs, LastCode                     int
	LastError                            string
	FailStreak, OkStreak                 int
}

const serviceSelect = `SELECT s.id, s.name, s.url, s.grp, s.description, COALESCE(s.host_id, 0), COALESCE(` + shownName + `, ''),
	s.interval_s, s.timeout_s, s.expected_status, s.accept_selfsigned, s.enabled, s.icon_at, s.created_at,
	s.state, s.state_since, s.checked_at, s.last_ms, s.last_code, s.last_error, s.fail_streak, s.ok_streak, s.cert_expires_at
	FROM services s LEFT JOIN hosts h ON h.id = s.host_id`

func scanService(sc interface{ Scan(...any) error }) (Service, error) {
	var sv Service
	var created int64
	err := sc.Scan(&sv.ID, &sv.Name, &sv.URL, &sv.Group, &sv.Description, &sv.HostID, &sv.Host,
		&sv.IntervalS, &sv.TimeoutS, &sv.ExpectedStatus, &sv.AcceptSelfSigned, &sv.Enabled, &sv.IconAt, &created,
		&sv.State, &sv.StateSince, &sv.CheckedAt, &sv.LastMs, &sv.LastCode, &sv.LastError, &sv.FailStreak, &sv.OkStreak, &sv.CertExpiresAt)
	sv.CreatedAt = time.Unix(created, 0)
	return sv, err
}

// Services lists grouped services first, by group, then the ungrouped ones;
// by name within each.
func (s *Store) Services(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, serviceSelect+` ORDER BY s.grp = '', lower(s.grp), s.grp, lower(s.name), s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		sv, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

func (s *Store) Service(ctx context.Context, id int64) (Service, error) {
	sv, err := scanService(s.db.QueryRowContext(ctx, serviceSelect+` WHERE s.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Service{}, ErrNotFound
	}
	return sv, err
}

func (s *Store) ServiceCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM services`).Scan(&n)
	return n, err
}

func nullHost(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *Store) CreateService(ctx context.Context, sv Service, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO services (name, url, grp, description, host_id, interval_s, timeout_s,
		expected_status, accept_selfsigned, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sv.Name, sv.URL, sv.Group, sv.Description, nullHost(sv.HostID), sv.IntervalS, sv.TimeoutS,
		sv.ExpectedStatus, sv.AcceptSelfSigned, sv.Enabled, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// one turns "no row changed" into ErrNotFound.
func one(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateService saves the editable fields. A new address starts over: what
// was known about the old one says nothing about it. SQLite evaluates every
// right-hand side against the old row, so url = ? compares with the stored URL.
func (s *Store) UpdateService(ctx context.Context, sv Service) error {
	same := sv.URL
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, closeIncident+` AND (SELECT url FROM services WHERE id = ?) != ?`,
		"address changed", sv.ID, sv.ID, sv.URL); err != nil {
		return err
	}
	for _, q := range endServiceAlerts {
		if _, err := tx.ExecContext(ctx, q+` AND (SELECT url FROM services WHERE id = ?) != ?`, sv.ID, sv.ID, sv.URL); err != nil {
			return err
		}
	}
	err = one(tx.ExecContext(ctx, `UPDATE services SET
		state = CASE WHEN url = ? THEN state WHEN ? THEN 'unknown' ELSE 'paused' END,
		state_since = CASE WHEN url = ? THEN state_since ELSE 0 END,
		checked_at = CASE WHEN url = ? THEN checked_at ELSE 0 END,
		last_ms = CASE WHEN url = ? THEN last_ms ELSE 0 END,
		last_code = CASE WHEN url = ? THEN last_code ELSE 0 END,
		last_error = CASE WHEN url = ? THEN last_error ELSE '' END,
		fail_streak = CASE WHEN url = ? THEN fail_streak ELSE 0 END,
		ok_streak = CASE WHEN url = ? THEN ok_streak ELSE 0 END,
		cert_expires_at = CASE WHEN url = ? THEN cert_expires_at ELSE 0 END,
		name = ?, url = ?, grp = ?, description = ?, host_id = ?,
		interval_s = ?, timeout_s = ?, expected_status = ?, accept_selfsigned = ?, enabled = ? WHERE id = ?`,
		same, sv.Enabled, same, same, same, same, same, same, same, same,
		sv.Name, sv.URL, sv.Group, sv.Description, nullHost(sv.HostID), sv.IntervalS, sv.TimeoutS,
		sv.ExpectedStatus, sv.AcceptSelfSigned, sv.Enabled, sv.ID))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// SetServiceEnabled pauses or resumes a service. A resumed service is
// unknown until its next check; a pause ends an ongoing incident.
func (s *Store) SetServiceEnabled(ctx context.Context, id int64, enabled bool) error {
	state := "paused"
	if enabled {
		state = "unknown"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var was bool
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM services WHERE id = ?`, id).Scan(&was); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	// A stale Pause or Resume from a second tab changes nothing.
	if was == enabled {
		return nil
	}
	if err := one(tx.ExecContext(ctx, `UPDATE services SET enabled = ?, state = ?, state_since = 0, fail_streak = 0, ok_streak = 0 WHERE id = ?`, enabled, state, id)); err != nil {
		return err
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, closeIncident, "paused", id); err != nil {
			return err
		}
		for _, q := range endServiceAlerts {
			if _, err := tx.ExecContext(ctx, q, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// CheckState is the latest check of a service and the state it led to. OK is
// whether this check succeeded; Error can still hold the outage's reason
// while a service recovers.
type CheckState struct {
	State                           string
	OK                              bool
	Since, CheckedAt, CertExpiresAt int64
	Ms, Code, FailStreak, OkStreak  int
	Error                           string
}

// SaveCheck stores a check result, its history row and the incident it
// opens, continues or ends, in one transaction. It is dropped (ErrNotFound)
// when the service was removed, paused, or given another address meanwhile.
func (s *Store) SaveCheck(ctx context.Context, id int64, url string, c CheckState) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = one(tx.ExecContext(ctx, `UPDATE services SET state = ?, state_since = ?, checked_at = ?, last_ms = ?, last_code = ?,
		last_error = ?, fail_streak = ?, ok_streak = ?, cert_expires_at = ? WHERE id = ? AND url = ? AND enabled = 1`,
		c.State, c.Since, c.CheckedAt, c.Ms, c.Code, c.Error, c.FailStreak, c.OkStreak, c.CertExpiresAt, id, url))
	if err != nil {
		return err
	}
	var down, msSum, msN int
	if c.State == "down" {
		down = 1
	}
	if c.OK {
		msSum, msN = c.Ms, 1
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO service_checks (service_id, res, ts, checks, down, ms_sum, ms_n)
		VALUES (?, 0, ?, 1, ?, ?, ?)`, id, c.CheckedAt, down, msSum, msN); err != nil {
		return err
	}
	if c.State == "down" {
		_, err = tx.ExecContext(ctx, `INSERT INTO service_incidents (service_id, started_at, reason) VALUES (?, ?, ?)
			ON CONFLICT (service_id) WHERE ended_at IS NULL DO UPDATE SET reason = excluded.reason`, id, c.Since, c.Error)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE service_incidents SET ended_at = ?, end_reason = 'recovered'
			WHERE service_id = ? AND ended_at IS NULL`, c.CheckedAt, id)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// endServiceAlerts ends a service's open alerts without a message when it is
// paused or given a new address: the next check, which can come before the
// alert engine looks, says nothing about the old outage or certificate. A
// pending alert leaves no trace; a fired one ends quietly (see EndAlertQuietly).
var endServiceAlerts = []string{
	`DELETE FROM alerts WHERE service_id = ? AND fired_at IS NULL AND resolved_at IS NULL`,
	`UPDATE alerts SET resolved_at = CAST(strftime('%s', 'now') AS INTEGER), notified_resolve = 2
		WHERE service_id = ? AND resolved_at IS NULL`,
}

// closeIncident ends the open incident of a service, if any, now.
const closeIncident = `UPDATE service_incidents SET ended_at = CAST(strftime('%s', 'now') AS INTEGER), end_reason = ?
	WHERE service_id = ? AND ended_at IS NULL`

type Incident struct {
	ID, ServiceID     int64
	Started, Ended    time.Time // Ended is zero while it lasts
	Reason, EndReason string
}

// Incidents lists a service's incidents, newest first.
func (s *Store) Incidents(ctx context.Context, serviceID int64, limit int) ([]Incident, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, service_id, started_at, ended_at, reason, end_reason
		FROM service_incidents WHERE service_id = ? ORDER BY started_at DESC, id DESC LIMIT ?`, serviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		var in Incident
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&in.ID, &in.ServiceID, &started, &ended, &in.Reason, &in.EndReason); err != nil {
			return nil, err
		}
		in.Started, in.Ended = time.Unix(started, 0), unixOrZero(ended)
		out = append(out, in)
	}
	return out, rows.Err()
}

func (s *Store) ServicesDownCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM services WHERE state = 'down' AND enabled = 1`).Scan(&n)
	return n, err
}

func (s *Store) DeleteService(ctx context.Context, id int64) error {
	return one(s.db.ExecContext(ctx, `DELETE FROM services WHERE id = ?`, id))
}

// SetServiceIcon stores the icon fetched from pageURL. It is dropped
// (ErrNotFound) when the service no longer has that address: the URL was
// edited during the fetch, or the id now belongs to a new service.
func (s *Store) SetServiceIcon(ctx context.Context, id int64, pageURL string, data []byte, typ string, at time.Time) error {
	return one(s.db.ExecContext(ctx, `UPDATE services SET icon = ?, icon_type = ?, icon_at = ? WHERE id = ? AND url = ?`, data, typ, at.Unix(), id, pageURL))
}

func (s *Store) ServiceIcon(ctx context.Context, id int64) ([]byte, string, error) {
	var data []byte
	var typ string
	err := s.db.QueryRowContext(ctx, `SELECT icon, icon_type FROM services WHERE id = ? AND icon IS NOT NULL`, id).Scan(&data, &typ)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	return data, typ, err
}

func (s *Store) ServiceGroups(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT grp FROM services WHERE grp != '' ORDER BY lower(grp)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RecentIncident is an incident with the name of its service.
type RecentIncident struct {
	Incident
	ServiceName string
}

// RecentIncidents lists the newest incidents of all services.
func (s *Store) RecentIncidents(ctx context.Context, limit int) ([]RecentIncident, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT i.id, i.service_id, i.started_at, i.ended_at, i.reason, i.end_reason, s.name
		FROM service_incidents i JOIN services s ON s.id = i.service_id ORDER BY i.started_at DESC, i.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RecentIncident
	for rows.Next() {
		var in RecentIncident
		var started int64
		var ended sql.NullInt64
		if err := rows.Scan(&in.ID, &in.ServiceID, &started, &ended, &in.Reason, &in.EndReason, &in.ServiceName); err != nil {
			return nil, err
		}
		in.Started, in.Ended = time.Unix(started, 0), unixOrZero(ended)
		out = append(out, in)
	}
	return out, rows.Err()
}
