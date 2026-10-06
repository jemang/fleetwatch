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

var schemaV7 = []string{
	// A web application the owner opens and, later, checks.
	`CREATE TABLE services (
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		grp TEXT NOT NULL DEFAULT '',
		description TEXT NOT NULL DEFAULT '',
		host_id INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
		interval_s INTEGER NOT NULL DEFAULT 60,
		timeout_s INTEGER NOT NULL DEFAULT 10,
		expected_status INTEGER NOT NULL DEFAULT 0,
		accept_selfsigned INTEGER NOT NULL DEFAULT 0,
		enabled INTEGER NOT NULL DEFAULT 1,
		icon BLOB,
		icon_type TEXT NOT NULL DEFAULT '',
		icon_at INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL)`,
}

var schemaV8 = []string{
	// The latest check of a service and the state it led to.
	`ALTER TABLE services ADD COLUMN state TEXT NOT NULL DEFAULT 'unknown'`,
	`ALTER TABLE services ADD COLUMN state_since INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE services ADD COLUMN checked_at INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE services ADD COLUMN last_ms INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE services ADD COLUMN last_code INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE services ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE services ADD COLUMN fail_streak INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE services ADD COLUMN ok_streak INTEGER NOT NULL DEFAULT 0`,
	`ALTER TABLE services ADD COLUMN cert_expires_at INTEGER NOT NULL DEFAULT 0`,
}

var schemaV9 = []string{
	// One row per check (res 0) or per completed hour (res 3600). down counts
	// checks taken while the service was confirmed down; ms_* only successful ones.
	`CREATE TABLE service_checks (
		service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
		res INTEGER NOT NULL,
		ts INTEGER NOT NULL,
		checks INTEGER NOT NULL,
		down INTEGER NOT NULL,
		ms_sum INTEGER NOT NULL,
		ms_n INTEGER NOT NULL,
		PRIMARY KEY (service_id, res, ts)) WITHOUT ROWID`,
	`CREATE TABLE service_incidents (
		id INTEGER PRIMARY KEY,
		service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
		started_at INTEGER NOT NULL,
		ended_at INTEGER,
		reason TEXT NOT NULL DEFAULT '',
		end_reason TEXT NOT NULL DEFAULT '')`,
	// At most one open incident per service.
	`CREATE UNIQUE INDEX service_incidents_open ON service_incidents (service_id) WHERE ended_at IS NULL`,
	// The uptime of all services reads hourly rows and recent raw rows by time.
	`CREATE INDEX service_checks_res_ts ON service_checks (res, ts)`,
}

var schemaV10 = []string{
	// An alert belongs to a host or to a service. SQLite cannot drop NOT NULL,
	// so the table is rebuilt; every row keeps its id. Nothing references alerts.
	`CREATE TABLE alerts_new (
		id INTEGER PRIMARY KEY,
		host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
		service_id INTEGER REFERENCES services(id) ON DELETE CASCADE,
		kind TEXT NOT NULL,
		subject TEXT NOT NULL DEFAULT '',
		detail TEXT NOT NULL DEFAULT '',
		pending_since INTEGER NOT NULL,
		fired_at INTEGER,
		resolved_at INTEGER,
		dismissed_at INTEGER,
		notified_fire INTEGER NOT NULL DEFAULT 0,
		notified_resolve INTEGER NOT NULL DEFAULT 0,
		CHECK ((host_id IS NULL) != (service_id IS NULL)))`,
	`INSERT INTO alerts_new (id, host_id, kind, subject, detail, pending_since, fired_at, resolved_at, dismissed_at, notified_fire, notified_resolve)
		SELECT id, host_id, kind, subject, detail, pending_since, fired_at, resolved_at, dismissed_at, notified_fire, notified_resolve FROM alerts`,
	`DROP TABLE alerts`,
	`ALTER TABLE alerts_new RENAME TO alerts`,
	// At most one open alert per host or service, kind and subject.
	`CREATE UNIQUE INDEX alerts_open ON alerts (host_id, kind, subject) WHERE resolved_at IS NULL AND host_id IS NOT NULL`,
	`CREATE UNIQUE INDEX alerts_open_service ON alerts (service_id, kind, subject) WHERE resolved_at IS NULL AND service_id IS NOT NULL`,
}

// migrations[i] takes the schema from version i to version i+1.
var migrations = [][]string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6, schemaV7, schemaV8, schemaV9, schemaV10}

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
