// Package store is the only package that touches SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound           = errors.New("store: not found")
	ErrEnrollmentRejected = errors.New("store: enrollment token rejected")
)

type ReplayError struct{ LastTS int64 }

func (e *ReplayError) Error() string {
	return fmt.Sprintf("store: report timestamp is not newer than %d", e.LastTS)
}

type Store struct {
	db *sql.DB

	mu      sync.Mutex
	pending []MetricPoint
}

var schemaV1 = []string{
	`CREATE TABLE admin (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		password_hash TEXT NOT NULL)`,
	`CREATE TABLE sessions (
		token_hash TEXT PRIMARY KEY,
		expires_at INTEGER NOT NULL)`,
	`CREATE TABLE enrollment_tokens (
		id INTEGER PRIMARY KEY,
		token_hash TEXT NOT NULL UNIQUE,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		used_at INTEGER,
		revoked_at INTEGER)`,
	`CREATE TABLE hosts (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		inventory_json TEXT,
		metrics_json TEXT,
		updated_at INTEGER NOT NULL)`,
	`CREATE TABLE agents (
		id INTEGER PRIMARY KEY,
		host_id INTEGER NOT NULL REFERENCES hosts(id),
		token_hash TEXT NOT NULL UNIQUE,
		disabled INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL,
		last_seen INTEGER,
		last_report_ts INTEGER NOT NULL DEFAULT 0,
		agent_version TEXT NOT NULL DEFAULT '',
		protocol_version INTEGER NOT NULL DEFAULT 0)`,
}

var schemaV2 = []string{
	// res is the resolution in seconds: 0 raw, 60, 300, 3600.
	`CREATE TABLE host_metrics (
		host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
		res INTEGER NOT NULL,
		ts INTEGER NOT NULL,
		cpu REAL, mem REAL, disk REAL, load1 REAL,
		PRIMARY KEY (host_id, res, ts)) WITHOUT ROWID`,
}

var schemaV3 = []string{
	`CREATE TABLE alerts (
		id INTEGER PRIMARY KEY,
		host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
		kind TEXT NOT NULL,
		subject TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		pending_since INTEGER NOT NULL,
		fired_at INTEGER,
		resolved_at INTEGER,
		dismissed_at INTEGER,
		notified_fire INTEGER NOT NULL DEFAULT 0,
		notified_resolve INTEGER NOT NULL DEFAULT 0)`,
	// At most one open alert per host, kind and subject.
	`CREATE UNIQUE INDEX alerts_open ON alerts (host_id, kind, subject) WHERE resolved_at IS NULL`,
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
}

var schemaV4 = []string{
	// A token with a host replaces that host's credential instead of adding a host.
	`ALTER TABLE enrollment_tokens ADD COLUMN host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE`,
}

var schemaV5 = []string{
	`CREATE TABLE passkeys (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		credential_id BLOB NOT NULL UNIQUE,
		credential_json BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		last_used_at INTEGER)`,
}

var schemaV6 = []string{
	// A name set on the Hub. Reports never touch it; empty shows the hostname.
	`ALTER TABLE hosts ADD COLUMN label TEXT NOT NULL DEFAULT ''`,
}

// migrations[i] takes the schema from version i to version i+1.
var migrations = [][]string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6}

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serializes writers, so SQLITE_BUSY cannot occur. Code
	// inside a transaction must use only the tx, never s.db.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close writes any queued history rows, then closes the database.
func (s *Store) Close() error {
	flushErr := s.FlushMetrics(context.Background())
	if err := s.db.Close(); err != nil {
		return err
	}
	return flushErr
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	for ; version < len(migrations); version++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range migrations[version] {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: migrate to version %d: %w", version+1, err)
			}
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
