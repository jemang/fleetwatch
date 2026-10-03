package systemd

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

// Manager controls units over the system D-Bus. Only root may use it; the
// running agent never does.
type Manager struct{ conn *dbus.Conn }

func Connect() (*Manager, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &Manager{conn: conn}, nil
}

func (m *Manager) Close() { m.conn.Close() }

func (m *Manager) call(method string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return m.conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		CallWithContext(ctx, "org.freedesktop.systemd1.Manager."+method, 0, args...).Err
}

func (m *Manager) Stop(unit string) error { return m.call("StopUnit", unit, "replace") }

// TryRestart restarts the unit only if it is running.
func (m *Manager) TryRestart(unit string) error { return m.call("TryRestartUnit", unit, "replace") }

func (m *Manager) Disable(unit string) error {
	return m.call("DisableUnitFiles", []string{unit}, false)
}

// Reload makes systemd read its unit files again.
func (m *Manager) Reload() error { return m.call("Reload") }
