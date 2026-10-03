package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) AdminExists(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin`).Scan(&n)
	return n > 0, err
}

func (s *Store) CreateAdmin(ctx context.Context, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin (id, password_hash) VALUES (1, ?)`, passwordHash)
	return err
}

func (s *Store) AdminPasswordHash(ctx context.Context) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM admin WHERE id = 1`).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, now, expires time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, expires_at) VALUES (?, ?)`, tokenHash, expires.Unix())
	return err
}

func (s *Store) SessionValid(ctx context.Context, tokenHash string, now time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE token_hash = ? AND expires_at > ?`, tokenHash, now.Unix()).Scan(&n)
	return n > 0, err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, tokenHash string, now, expires time.Time) error {
	// Tokens that expired more than a day ago carry no information any more.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM enrollment_tokens WHERE expires_at < ?`, now.Add(-24*time.Hour).Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens (token_hash, created_at, expires_at) VALUES (?, ?, ?)`, tokenHash, now.Unix(), expires.Unix())
	return err
}

// CreateHostEnrollmentToken makes a token that replaces the credential of an
// existing host when an agent enrolls with it.
func (s *Store) CreateHostEnrollmentToken(ctx context.Context, tokenHash string, hostID int64, now, expires time.Time) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens (token_hash, created_at, expires_at, host_id)
		SELECT ?, ?, ?, id FROM hosts WHERE id = ?`, tokenHash, now.Unix(), expires.Unix(), hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrNotFound
	}
	return nil
}

// EnrollmentTokenHost reports whether a token can still be used, and the host
// it is bound to (0 for a token that adds a new host). It does not use it up.
func (s *Store) EnrollmentTokenHost(ctx context.Context, tokenHash string, now time.Time) (hostID int64, usable bool, err error) {
	var host sql.NullInt64
	err = s.db.QueryRowContext(ctx, `SELECT host_id FROM enrollment_tokens
		WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`, tokenHash, now.Unix()).Scan(&host)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return host.Int64, err == nil, err
}
