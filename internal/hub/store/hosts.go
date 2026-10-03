package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"fleetwatch/internal/protocol"
)

type EnrollParams struct {
	EnrollTokenHash string
	Hostname        string
	AgentTokenHash  string
	AgentVersion    string
	ProtocolVersion int
	Now             time.Time
}

// Enroll consumes the enrollment token and creates the host and its agent in
// one transaction, so a token can never produce two agents. A token bound to
// a host replaces that host's credential instead; the old one stops working.
func (s *Store) Enroll(ctx context.Context, p EnrollParams) (agentID, hostID int64, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	now := p.Now.Unix()
	res, err := tx.ExecContext(ctx,
		`UPDATE enrollment_tokens SET used_at = ?
		 WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
		now, p.EnrollTokenHash, now)
	if err != nil {
		return 0, 0, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, 0, ErrEnrollmentRejected
	}
	var bound sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT host_id FROM enrollment_tokens WHERE token_hash = ?`, p.EnrollTokenHash).Scan(&bound); err != nil {
		return 0, 0, err
	}
	if bound.Valid {
		hostID = bound.Int64
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET token_hash = ?, agent_version = ?, protocol_version = ? WHERE host_id = ?`,
			p.AgentTokenHash, p.AgentVersion, p.ProtocolVersion, hostID); err != nil {
			return 0, 0, err
		}
		if err := tx.QueryRowContext(ctx, `SELECT id FROM agents WHERE host_id = ?`, hostID).Scan(&agentID); err != nil {
			return 0, 0, err
		}
		return agentID, hostID, tx.Commit()
	}
	res, err = tx.ExecContext(ctx, `INSERT INTO hosts (name, updated_at) VALUES (?, ?)`, p.Hostname, now)
	if err != nil {
		return 0, 0, err
	}
	hostID, _ = res.LastInsertId()
	res, err = tx.ExecContext(ctx,
		`INSERT INTO agents (host_id, token_hash, created_at, agent_version, protocol_version) VALUES (?, ?, ?, ?, ?)`,
		hostID, p.AgentTokenHash, now, p.AgentVersion, p.ProtocolVersion)
	if err != nil {
		return 0, 0, err
	}
	agentID, _ = res.LastInsertId()
	return agentID, hostID, tx.Commit()
}

type Agent struct {
	ID, HostID int64
	Disabled   bool
}

func (s *Store) AgentByTokenHash(ctx context.Context, hash string) (Agent, error) {
	var a Agent
	err := s.db.QueryRowContext(ctx, `SELECT id, host_id, disabled FROM agents WHERE token_hash = ?`, hash).Scan(&a.ID, &a.HostID, &a.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// DeleteHost removes the host with its agent, history, alerts and bound
// tokens. Its agent's credential stops working at once.
func (s *Store) DeleteHost(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// agents has no ON DELETE CASCADE (schema version 1); the rest has.
	if _, err := tx.ExecContext(ctx, `DELETE FROM agents WHERE host_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// SetAgentDisabled switches the agent of a host off or on. The Hub refuses
// the reports of a disabled agent.
func (s *Store) SetAgentDisabled(ctx context.Context, hostID int64, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET disabled = ? WHERE host_id = ?`, disabled, hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetHostLabel names the host on the Hub; an empty label shows the hostname.
func (s *Store) SetHostLabel(ctx context.Context, hostID int64, label string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE hosts SET label = ? WHERE id = ?`, label, hostID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptReport replaces the host's latest state. It returns *ReplayError when
// the report's ts is not greater than the last accepted one.
func (s *Store) AcceptReport(ctx context.Context, agentID int64, r protocol.Report, now time.Time) error {
	metrics, err := json.Marshal(r.Metrics)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`UPDATE agents SET last_report_ts = ?, last_seen = ?, agent_version = ?, protocol_version = ?
		 WHERE id = ? AND last_report_ts < ?`,
		r.TS, now.Unix(), r.AgentVersion, r.ProtocolVersion, agentID, r.TS)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		var last int64
		if err := tx.QueryRowContext(ctx, `SELECT last_report_ts FROM agents WHERE id = ?`, agentID).Scan(&last); err != nil {
			return err
		}
		return &ReplayError{LastTS: last}
	}
	const host = `(SELECT host_id FROM agents WHERE id = ?)`
	if r.Inventory != nil {
		inv, err := json.Marshal(r.Inventory)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE hosts SET metrics_json = ?, inventory_json = ?, name = COALESCE(NULLIF(?, ''), name), updated_at = ? WHERE id = `+host,
			string(metrics), string(inv), r.Inventory.Hostname, now.Unix(), agentID)
		if err != nil {
			return err
		}
	} else if _, err := tx.ExecContext(ctx, `UPDATE hosts SET metrics_json = ?, updated_at = ? WHERE id = `+host, string(metrics), now.Unix(), agentID); err != nil {
		return err
	}
	return tx.Commit()
}

type Host struct {
	ID           int64
	Name         string // the label, or the hostname when there is none
	Label        string
	Hostname     string
	Metrics      *protocol.Metrics
	Inventory    *protocol.Inventory
	LastSeen     time.Time
	AgentVersion string
	Disabled     bool // the Hub refuses this host's agent
}

// shownName is how a host is named on every page and in alerts.
const shownName = `COALESCE(NULLIF(h.label, ''), h.name)`

const hostSelect = `SELECT h.id, ` + shownName + `, h.label, h.name, h.metrics_json, h.inventory_json, a.last_seen, a.agent_version, a.disabled
	FROM hosts h JOIN agents a ON a.host_id = h.id`

func scanHost(sc interface{ Scan(...any) error }) (Host, error) {
	var h Host
	var metrics, inv sql.NullString
	var seen sql.NullInt64
	if err := sc.Scan(&h.ID, &h.Name, &h.Label, &h.Hostname, &metrics, &inv, &seen, &h.AgentVersion, &h.Disabled); err != nil {
		return h, err
	}
	if metrics.Valid {
		h.Metrics = new(protocol.Metrics)
		if err := json.Unmarshal([]byte(metrics.String), h.Metrics); err != nil {
			return h, err
		}
	}
	if inv.Valid {
		h.Inventory = new(protocol.Inventory)
		if err := json.Unmarshal([]byte(inv.String), h.Inventory); err != nil {
			return h, err
		}
	}
	if seen.Valid {
		h.LastSeen = time.Unix(seen.Int64, 0)
	}
	return h, nil
}

func (s *Store) Hosts(ctx context.Context) ([]Host, error) {
	rows, err := s.db.QueryContext(ctx, hostSelect+` ORDER BY `+shownName+`, h.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) Host(ctx context.Context, id int64) (Host, error) {
	h, err := scanHost(s.db.QueryRowContext(ctx, hostSelect+` WHERE h.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}
