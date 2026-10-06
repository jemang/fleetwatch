package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func svc(name, url, group string) Service {
	return Service{Name: name, URL: url, Group: group, IntervalS: 60, TimeoutS: 10, Enabled: true}
}

func TestServiceCRUD(t *testing.T) {
	s := open(t)
	_, hostID := enrolled(t, s)
	in := Service{Name: "Grafana", URL: "https://grafana.lan", Group: "Infrastructure", Description: "charts",
		HostID: hostID, IntervalS: 120, TimeoutS: 5, ExpectedStatus: 200, AcceptSelfSigned: true, Enabled: true}
	id, err := s.CreateService(ctx, in, t0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := in
	want.ID, want.Host, want.CreatedAt = id, "web-01", time.Unix(t0.Unix(), 0)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("read back\n got %+v\nwant %+v", got, want)
	}
	got.Name, got.URL, got.HostID, got.AcceptSelfSigned = "Grafana 2", "https://g2.lan", 0, false
	if err := s.UpdateService(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Service(ctx, id); again.Name != "Grafana 2" || again.URL != "https://g2.lan" || again.HostID != 0 || again.Host != "" || again.AcceptSelfSigned {
		t.Errorf("after update: %+v", again)
	}
	if err := s.SetServiceEnabled(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Service(ctx, id); again.Enabled {
		t.Error("service must be paused")
	}
	if n, _ := s.ServiceCount(ctx); n != 1 {
		t.Errorf("count = %d", n)
	}
	if err := s.DeleteService(ctx, id); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"read":   func() error { _, err := s.Service(ctx, id); return err }(),
		"update": s.UpdateService(ctx, got),
		"enable": s.SetServiceEnabled(ctx, id, true),
		"delete": s.DeleteService(ctx, id),
		"icon":   s.SetServiceIcon(ctx, id, "https://g2.lan", []byte("x"), "image/png", t0),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s of a removed service: %v, want ErrNotFound", name, err)
		}
	}
}

func TestServicesOrderAndGroups(t *testing.T) {
	s := open(t)
	for _, sv := range []Service{svc("zeta", "http://z", ""), svc("beta", "http://b", "prod"), svc("Alpha", "http://a", "prod"),
		svc("gamma", "http://g", "Infra"), svc("alpha2", "http://a2", "")} {
		if _, err := s.CreateService(ctx, sv, t0); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.Services(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sv := range list {
		names = append(names, sv.Name)
	}
	if want := []string{"gamma", "Alpha", "beta", "alpha2", "zeta"}; !reflect.DeepEqual(names, want) {
		t.Errorf("order = %v, want %v", names, want)
	}
	if groups, _ := s.ServiceGroups(ctx); !reflect.DeepEqual(groups, []string{"Infra", "prod"}) {
		t.Errorf("groups = %v", groups)
	}
}

func TestServiceIcon(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("a", "http://a", ""), t0)
	if _, _, err := s.ServiceIcon(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("no icon yet: %v", err)
	}
	if err := s.SetServiceIcon(ctx, id, "http://a", []byte{1, 2, 3}, "image/png", t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	data, typ, err := s.ServiceIcon(ctx, id)
	if err != nil || !reflect.DeepEqual(data, []byte{1, 2, 3}) || typ != "image/png" {
		t.Errorf("icon = %v %q %v", data, typ, err)
	}
	if got, _ := s.Service(ctx, id); got.IconAt != t0.Add(time.Minute).Unix() {
		t.Errorf("IconAt = %d", got.IconAt)
	}
}

// Removing a host keeps its services, without a host.
func TestRemovingHostKeepsItsServices(t *testing.T) {
	s := open(t)
	_, hostID := enrolled(t, s)
	sv := svc("pve UI", "https://pve:8006", "")
	sv.HostID = hostID
	id, _ := s.CreateService(ctx, sv, t0)
	if err := s.DeleteHost(ctx, hostID); err != nil {
		t.Fatal(err)
	}
	got, err := s.Service(ctx, id)
	if err != nil || got.HostID != 0 || got.Host != "" {
		t.Errorf("after host removal: %+v %v", got, err)
	}
}

func TestMigrationFromVersion6AddsServices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v6.db")
	old, _ := sql.Open("sqlite", "file:"+path)
	for _, m := range migrations[:6] {
		for _, stmt := range m {
			if _, err := old.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	old.Exec(`PRAGMA user_version = 6`)
	old.Exec(`INSERT INTO hosts (name, updated_at) VALUES ('kept', 1)`)
	old.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var hosts int
	s.db.QueryRow(`SELECT COUNT(*) FROM hosts`).Scan(&hosts)
	if n, err := s.ServiceCount(ctx); err != nil || n != 0 || hosts != 1 {
		t.Errorf("after migration: services %d (%v), hosts %d", n, err, hosts)
	}
}

// An icon fetched for an address the service no longer has is not stored:
// the URL was edited meanwhile, or the id now belongs to a new service.
func TestServiceIconForOldURLIsDropped(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("a", "http://new", ""), t0)
	if err := s.SetServiceIcon(ctx, id, "http://old", []byte{1}, "image/png", t0); !errors.Is(err, ErrNotFound) {
		t.Errorf("icon for an old address: %v, want ErrNotFound", err)
	}
	if _, _, err := s.ServiceIcon(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Error("the icon for the old address was stored")
	}
}

// Groups that differ only in case stay apart and are not interleaved.
func TestGroupsDifferingInCaseStayTogether(t *testing.T) {
	s := open(t)
	for _, sv := range []Service{svc("Alpha", "http://a", "Prod"), svc("Bravo", "http://b", "prod"), svc("Charlie", "http://c", "Prod")} {
		s.CreateService(ctx, sv, t0)
	}
	list, _ := s.Services(ctx)
	var groups []string
	for _, sv := range list {
		groups = append(groups, sv.Group)
	}
	if want := []string{"Prod", "Prod", "prod"}; !reflect.DeepEqual(groups, want) {
		t.Errorf("groups in order = %v, want %v", groups, want)
	}
}
