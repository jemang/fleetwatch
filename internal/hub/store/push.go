package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// PushSubscription is one browser that shows FleetWatch notifications.
type PushSubscription struct {
	ID                     int64
	Endpoint, P256dh, Auth string
	Label                  string // "Chrome on Android"
	CreatedAt, LastOKAt    time.Time
}

const pushSelect = `SELECT id, endpoint, p256dh, auth, label, created_at, last_ok_at FROM push_subscriptions`

func scanPush(row interface{ Scan(...any) error }) (PushSubscription, error) {
	var p PushSubscription
	var created int64
	var ok sql.NullInt64
	if err := row.Scan(&p.ID, &p.Endpoint, &p.P256dh, &p.Auth, &p.Label, &created, &ok); err != nil {
		return p, err
	}
	p.CreatedAt = time.Unix(created, 0)
	if ok.Valid {
		p.LastOKAt = time.Unix(ok.Int64, 0)
	}
	return p, nil
}

// SavePushSubscription stores a browser, or renews the keys and label of one
// already stored.
func (s *Store) SavePushSubscription(ctx context.Context, p PushSubscription, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO push_subscriptions (endpoint, p256dh, auth, label, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (endpoint) DO UPDATE SET p256dh = excluded.p256dh, auth = excluded.auth, label = excluded.label`,
		p.Endpoint, p.P256dh, p.Auth, p.Label, now.Unix())
	return err
}

func (s *Store) PushSubscriptions(ctx context.Context) ([]PushSubscription, error) {
	rows, err := s.db.QueryContext(ctx, pushSelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PushSubscription
	for rows.Next() {
		p, err := scanPush(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PushSubscriptionByEndpoint(ctx context.Context, endpoint string) (PushSubscription, error) {
	p, err := scanPush(s.db.QueryRowContext(ctx, pushSelect+` WHERE endpoint = ?`, endpoint))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) DeletePushSubscription(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeletePushSubscriptionByEndpoint(ctx context.Context, endpoint string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM push_subscriptions WHERE endpoint = ?`, endpoint)
	return err
}

func (s *Store) MarkPushOK(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE push_subscriptions SET last_ok_at = ? WHERE id = ?`, now.Unix(), id)
	return err
}

// PushKey is the Hub's VAPID private key, made with create the first time.
func (s *Store) PushKey(ctx context.Context, create func() (string, error)) (string, error) {
	var k string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'push_vapid_key'`).Scan(&k)
	if err == nil && k != "" {
		return k, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if k, err = create(); err != nil {
		return "", err
	}
	// Two first requests at once keep whichever key was stored first.
	if _, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES ('push_vapid_key', ?) ON CONFLICT (key) DO NOTHING`, k); err != nil {
		return "", err
	}
	err = s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'push_vapid_key'`).Scan(&k)
	return k, err
}
