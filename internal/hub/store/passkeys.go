package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Passkey is one WebAuthn credential of the admin. Credential holds the
// library's record as JSON; the store does not look inside it.
type Passkey struct {
	ID           int64
	Name         string
	CredentialID []byte
	Credential   []byte
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

func scanPasskey(sc interface{ Scan(...any) error }) (Passkey, error) {
	var p Passkey
	var created int64
	var used sql.NullInt64
	err := sc.Scan(&p.ID, &p.Name, &p.CredentialID, &p.Credential, &created, &used)
	if err == nil {
		p.CreatedAt, p.LastUsedAt = time.Unix(created, 0), unixOrZero(used)
	}
	return p, err
}

const passkeySelect = `SELECT id, name, credential_id, credential_json, created_at, last_used_at FROM passkeys`

func (s *Store) Passkeys(ctx context.Context) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, passkeySelect+` ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) PasskeyByCredentialID(ctx context.Context, credentialID []byte) (Passkey, error) {
	p, err := scanPasskey(s.db.QueryRowContext(ctx, passkeySelect+` WHERE credential_id = ?`, credentialID))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

func (s *Store) AddPasskey(ctx context.Context, name string, credentialID, credential []byte, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO passkeys (name, credential_id, credential_json, created_at) VALUES (?, ?, ?, ?)`,
		name, credentialID, credential, now.Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdatePasskey stores the credential after a login (its sign counter moved)
// and records the use.
func (s *Store) UpdatePasskey(ctx context.Context, id int64, credential []byte, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET credential_json = ?, last_used_at = ? WHERE id = ?`, credential, now.Unix(), id)
	return err
}

func (s *Store) DeletePasskey(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
