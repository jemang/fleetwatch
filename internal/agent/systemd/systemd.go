// Package systemd reads unit states from systemd over the system D-Bus. It
// starts no processes.
package systemd

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"fleetwatch/internal/protocol"
)

// UnitName completes a bare name: "nginx" means "nginx.service".
func UnitName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, ".") {
		return s
	}
	return s + ".service"
}

// StatusOf maps systemd's load and active states to the four FleetWatch states.
func StatusOf(load, active string) string {
	if load == "not-found" {
		return "unknown"
	}
	switch active {
	case "active", "reloading", "activating":
		return "running"
	case "failed":
		return "failed"
	case "inactive", "deactivating":
		return "stopped"
	}
	return "unknown"
}

func Unknown(names []string) []protocol.Service {
	out := make([]protocol.Service, len(names))
	for i, n := range names {
		out[i] = protocol.Service{Name: n, Status: "unknown"}
	}
	return out
}

// unit mirrors one entry of ListUnitsByNames: a(ssssssouso).
type unit struct {
	Name, Description, LoadState, ActiveState, SubState, Followed string
	Path                                                          dbus.ObjectPath
	JobID                                                         uint32
	JobType                                                       string
	JobPath                                                       dbus.ObjectPath
}

// Lister keeps one bus connection and reconnects after an error.
type Lister struct {
	mu   sync.Mutex
	conn *dbus.Conn
}

// List asks systemd for the named units in one call. A host without a system
// bus gives an error; the caller reports the services as unknown.
func (l *Lister) List(names []string) ([]protocol.Service, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		conn, err := dbus.ConnectSystemBus()
		if err != nil {
			return nil, err
		}
		l.conn = conn
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var units []unit
	err := l.conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager.ListUnitsByNames", 0, names).Store(&units)
	if err != nil {
		l.conn.Close()
		l.conn = nil
		return nil, err
	}
	state := make(map[string]string, len(units))
	for _, u := range units {
		state[u.Name] = StatusOf(u.LoadState, u.ActiveState)
	}
	out := make([]protocol.Service, len(names))
	for i, n := range names {
		s, ok := state[n]
		if !ok {
			s = "unknown"
		}
		out[i] = protocol.Service{Name: n, Status: s}
	}
	return out, nil
}
