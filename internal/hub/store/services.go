package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Service is a web application. HostID 0 means no related host; Host is that
// host's shown name. IconAt is when the icon was stored, 0 when there is none.
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
}

const serviceSelect = `SELECT s.id, s.name, s.url, s.grp, s.description, COALESCE(s.host_id, 0), COALESCE(` + shownName + `, ''),
	s.interval_s, s.timeout_s, s.expected_status, s.accept_selfsigned, s.enabled, s.icon_at, s.created_at
	FROM services s LEFT JOIN hosts h ON h.id = s.host_id`

func scanService(sc interface{ Scan(...any) error }) (Service, error) {
	var sv Service
	var created int64
	err := sc.Scan(&sv.ID, &sv.Name, &sv.URL, &sv.Group, &sv.Description, &sv.HostID, &sv.Host,
		&sv.IntervalS, &sv.TimeoutS, &sv.ExpectedStatus, &sv.AcceptSelfSigned, &sv.Enabled, &sv.IconAt, &created)
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

func (s *Store) UpdateService(ctx context.Context, sv Service) error {
	return one(s.db.ExecContext(ctx, `UPDATE services SET name = ?, url = ?, grp = ?, description = ?, host_id = ?,
		interval_s = ?, timeout_s = ?, expected_status = ?, accept_selfsigned = ?, enabled = ? WHERE id = ?`,
		sv.Name, sv.URL, sv.Group, sv.Description, nullHost(sv.HostID), sv.IntervalS, sv.TimeoutS,
		sv.ExpectedStatus, sv.AcceptSelfSigned, sv.Enabled, sv.ID))
}

func (s *Store) SetServiceEnabled(ctx context.Context, id int64, enabled bool) error {
	return one(s.db.ExecContext(ctx, `UPDATE services SET enabled = ? WHERE id = ?`, enabled, id))
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
