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
	want.State = "unknown"
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

func TestSaveCheckAndDownCount(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("a", "http://a", ""), t0)
	c := CheckState{State: "down", Since: 100, CheckedAt: 200, CertExpiresAt: 300, Ms: 42, Code: 503, FailStreak: 3, Error: "HTTP 503"}
	if err := s.SaveCheck(ctx, id, "http://a", c); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Service(ctx, id)
	if got.State != "down" || got.StateSince != 100 || got.CheckedAt != 200 || got.CertExpiresAt != 300 || got.LastMs != 42 ||
		got.LastCode != 503 || got.FailStreak != 3 || got.OkStreak != 0 || got.LastError != "HTTP 503" {
		t.Errorf("after SaveCheck: %+v", got)
	}
	if n, _ := s.ServicesDownCount(ctx); n != 1 {
		t.Errorf("down count = %d", n)
	}
	if err := s.SaveCheck(ctx, id, "http://other", c); !errors.Is(err, ErrNotFound) {
		t.Errorf("result for another URL: %v", err)
	}
	s.SetServiceEnabled(ctx, id, false)
	if err := s.SaveCheck(ctx, id, "http://a", c); !errors.Is(err, ErrNotFound) {
		t.Errorf("result for a paused service: %v", err)
	}
	if got, _ := s.Service(ctx, id); got.State != "paused" || got.FailStreak != 0 {
		t.Errorf("paused: %+v", got)
	}
	if n, _ := s.ServicesDownCount(ctx); n != 0 {
		t.Errorf("a paused service counts as down: %d", n)
	}
	s.SetServiceEnabled(ctx, id, true)
	if got, _ := s.Service(ctx, id); got.State != "unknown" {
		t.Errorf("resumed: %+v", got)
	}
}

func TestURLEditResetsCheckState(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("a", "http://a", ""), t0)
	s.SaveCheck(ctx, id, "http://a", CheckState{State: "online", Since: 1, CheckedAt: 2, Ms: 9, Code: 200, OkStreak: 4})
	sv, _ := s.Service(ctx, id)
	sv.Name = "renamed"
	s.UpdateService(ctx, sv)
	if got, _ := s.Service(ctx, id); got.State != "online" || got.CheckedAt != 2 {
		t.Errorf("a rename must keep the check state: %+v", got)
	}
	sv.URL = "http://b"
	s.UpdateService(ctx, sv)
	if got, _ := s.Service(ctx, id); got.State != "unknown" || got.CheckedAt != 0 || got.LastMs != 0 || got.OkStreak != 0 || got.StateSince != 0 {
		t.Errorf("a new URL must start from unknown: %+v", got)
	}
	s.SetServiceEnabled(ctx, id, false)
	sv, _ = s.Service(ctx, id)
	sv.URL = "http://c"
	s.UpdateService(ctx, sv)
	if got, _ := s.Service(ctx, id); got.State != "paused" {
		t.Errorf("a paused service stays paused on a URL edit: %+v", got)
	}
}

func TestMigrationFromVersion7AddsCheckState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v7.db")
	old, _ := sql.Open("sqlite", "file:"+path)
	for _, m := range migrations[:7] {
		for _, stmt := range m {
			if _, err := old.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	old.Exec(`PRAGMA user_version = 7`)
	old.Exec(`INSERT INTO services (name, url, created_at) VALUES ('kept', 'http://k', 1)`)
	old.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	list, _ := s.Services(ctx)
	if len(list) != 1 || list[0].Name != "kept" || list[0].State != "unknown" {
		t.Errorf("after migration: %+v", list)
	}
}

func rawChecks(t *testing.T, s *Store, id int64) (n, down, msSum, msN int64) {
	t.Helper()
	err := s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(down),0), COALESCE(SUM(ms_sum),0), COALESCE(SUM(ms_n),0)
		FROM service_checks WHERE service_id = ? AND res = 0`, id).Scan(&n, &down, &msSum, &msN)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestSaveCheckRecordsHistoryAndIncidents(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	at := t0.Unix()
	save := func(c CheckState) {
		t.Helper()
		if err := s.SaveCheck(ctx, id, "http://a", c); err != nil {
			t.Fatal(err)
		}
	}
	save(CheckState{State: "online", OK: true, CheckedAt: at, Ms: 40, Code: 200})
	save(CheckState{State: "online", CheckedAt: at + 60, Ms: 40, Error: "timeout", FailStreak: 1})
	save(CheckState{State: "down", Since: at + 120, CheckedAt: at + 120, Error: "timeout", FailStreak: 2})
	save(CheckState{State: "down", Since: at + 120, CheckedAt: at + 180, Error: "connection refused", FailStreak: 3})
	save(CheckState{State: "down", Since: at + 120, OK: true, CheckedAt: at + 240, Ms: 50, Error: "connection refused", OkStreak: 1})
	if n, down, msSum, msN := rawChecks(t, s, id); n != 5 || down != 3 || msSum != 90 || msN != 2 {
		t.Fatalf("history = %d checks, %d down, ms %d/%d; want 5, 3, 90/2", n, down, msSum, msN)
	}
	inc, err := s.Incidents(ctx, id, 10)
	if err != nil || len(inc) != 1 {
		t.Fatalf("incidents = %v, %v; want one", inc, err)
	}
	if !inc[0].Ended.IsZero() || inc[0].Started.Unix() != at+120 || inc[0].Reason != "connection refused" {
		t.Fatalf("open incident = %+v; want started %d, ongoing, latest reason", inc[0], at+120)
	}
	save(CheckState{State: "online", OK: true, CheckedAt: at + 300, Ms: 30, OkStreak: 2})
	inc, _ = s.Incidents(ctx, id, 10)
	if inc[0].Ended.Unix() != at+300 || inc[0].EndReason != "recovered" {
		t.Fatalf("closed incident = %+v; want ended %d, recovered", inc[0], at+300)
	}
	save(CheckState{State: "down", Since: at + 400, CheckedAt: at + 400, Error: "timeout", FailStreak: 3})
	inc, _ = s.Incidents(ctx, id, 10)
	if len(inc) != 2 || inc[0].Started.Unix() != at+400 || !inc[0].Ended.IsZero() {
		t.Fatalf("incidents = %+v; want a new open one first", inc)
	}
}

func TestStaleSaveCheckWritesNothing(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	down := CheckState{State: "down", Since: t0.Unix(), CheckedAt: t0.Unix(), Error: "timeout", FailStreak: 3}
	if err := s.SaveCheck(ctx, id, "http://old", down); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SaveCheck with another URL = %v; want ErrNotFound", err)
	}
	s.SetServiceEnabled(ctx, id, false)
	if err := s.SaveCheck(ctx, id, "http://a", down); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SaveCheck while paused = %v; want ErrNotFound", err)
	}
	if n, _, _, _ := rawChecks(t, s, id); n != 0 {
		t.Fatalf("stale checks wrote %d history rows", n)
	}
	if inc, _ := s.Incidents(ctx, id, 10); len(inc) != 0 {
		t.Fatalf("stale checks opened incidents: %+v", inc)
	}
}

func TestPauseAndNewAddressCloseTheIncident(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	down := CheckState{State: "down", Since: t0.Unix(), CheckedAt: t0.Unix(), Error: "timeout", FailStreak: 3}
	s.SaveCheck(ctx, id, "http://a", down)
	s.SetServiceEnabled(ctx, id, false)
	inc, _ := s.Incidents(ctx, id, 10)
	if len(inc) != 1 || inc[0].Ended.IsZero() || inc[0].EndReason != "paused" {
		t.Fatalf("after pause = %+v; want ended, paused", inc)
	}
	s.SetServiceEnabled(ctx, id, true)
	s.SaveCheck(ctx, id, "http://a", down)
	sv, _ := s.Service(ctx, id)
	sv.Name = "renamed"
	s.UpdateService(ctx, sv) // same URL: the incident stays open
	if inc, _ = s.Incidents(ctx, id, 10); !inc[0].Ended.IsZero() {
		t.Fatalf("rename closed the incident: %+v", inc[0])
	}
	sv.URL = "http://b"
	s.UpdateService(ctx, sv)
	inc, _ = s.Incidents(ctx, id, 10)
	if inc[0].Ended.IsZero() || inc[0].EndReason != "address changed" {
		t.Fatalf("after new address = %+v; want ended, address changed", inc[0])
	}
}

func TestDeleteServiceRemovesHistoryAndIncidents(t *testing.T) {
	s := open(t)
	id, _ := s.CreateService(ctx, svc("A", "http://a", ""), t0)
	s.SaveCheck(ctx, id, "http://a", CheckState{State: "down", Since: t0.Unix(), CheckedAt: t0.Unix(), Error: "timeout"})
	s.DeleteService(ctx, id)
	var n int
	s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM service_checks) + (SELECT COUNT(*) FROM service_incidents)`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d history or incident rows left after delete", n)
	}
}
