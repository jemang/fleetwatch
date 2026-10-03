package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMigrationFromVersion2AddsAlertsAndSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	old, _ := sql.Open("sqlite", "file:"+path)
	for _, m := range migrations[:2] {
		for _, stmt := range m {
			if _, err := old.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	old.Exec(`PRAGMA user_version = 2`)
	old.Exec(`INSERT INTO admin (id, password_hash) VALUES (1, 'kept')`)
	old.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if h, _ := s.AdminPasswordHash(ctx); h != "kept" {
		t.Error("data from schema version 2 must survive")
	}
	if err := s.SetSettings(ctx, map[string]string{"webhook_url": "https://x"}); err != nil {
		t.Errorf("settings table must exist after migration: %v", err)
	}
}

func TestAlertLifeCycle(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	id, err := s.CreateAlert(ctx, host, "cpu_high", "", "CPU 93%", t0, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAlert(ctx, host, "cpu_high", "", "CPU 95%", t0, false); err == nil {
		t.Error("a second open alert for the same host, kind and subject must be refused")
	}
	if _, err := s.CreateAlert(ctx, host, "disk_full", "/data", "/data 90%", t0, true); err != nil {
		t.Fatalf("a different kind or subject is a separate alert: %v", err)
	}
	open, _ := s.OpenAlerts(ctx)
	if len(open) != 2 || open[0].Host != "web-01" || open[0].State() != "pending" || open[1].State() != "firing" {
		t.Fatalf("open alerts = %+v", open)
	}
	if n, _ := s.FiringCount(ctx); n != 1 {
		t.Errorf("firing count = %d, want 1 (pending does not count)", n)
	}
	s.FireAlert(ctx, id, t0.Add(5*time.Minute))
	s.MarkNotified(ctx, id, "firing")
	s.ResolveAlert(ctx, id, t0.Add(10*time.Minute))
	if one, err := s.Alert(ctx, id); err != nil || one.State() != "resolved" || !one.NotifiedFire || one.Detail != "CPU 93%" {
		t.Errorf("Alert(%d) = %+v, %v", id, one, err)
	}
	if _, err := s.Alert(ctx, 999); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("Alert(999) err = %v, want sql.ErrNoRows", err)
	}
	all, _ := s.Alerts(ctx, 100)
	var got *Alert
	for i := range all {
		if all[i].ID == id {
			got = &all[i]
		}
	}
	if got == nil || got.State() != "resolved" || !got.NotifiedFire || got.NotifiedResolve || !got.FiredAt.Equal(t0.Add(5*time.Minute)) || !got.ResolvedAt.Equal(t0.Add(10*time.Minute)) {
		t.Fatalf("resolved alert = %+v", got)
	}
	if all[0].State() != "firing" {
		t.Errorf("open alerts are listed before resolved ones: first is %q", all[0].State())
	}
	if _, err := s.CreateAlert(ctx, host, "cpu_high", "", "CPU 91%", t0.Add(time.Hour), false); err != nil {
		t.Errorf("after an alert is resolved the same condition may open a new one: %v", err)
	}
}

func TestDismissAndDeleteAndPrune(t *testing.T) {
	s := open(t)
	host := newHost(t, s, "web-01")
	firing, _ := s.CreateAlert(ctx, host, "guest_stopped", "115", "ocrmypdf stopped", t0, true)
	pending, _ := s.CreateAlert(ctx, host, "ram_high", "", "RAM 92%", t0, false)
	if err := s.DismissAlert(ctx, firing, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	open, _ := s.OpenAlerts(ctx)
	if len(open) != 2 || open[0].State() != "dismissed" {
		t.Fatalf("a dismissed alert stays open so it is not raised again: %+v", open)
	}
	if n, _ := s.FiringCount(ctx); n != 0 {
		t.Errorf("a dismissed alert does not count as firing: %d", n)
	}
	s.DeleteAlert(ctx, pending)
	if open, _ := s.OpenAlerts(ctx); len(open) != 1 {
		t.Errorf("a pending alert that cleared is deleted, open = %d", len(open))
	}
	s.ResolveAlert(ctx, firing, t0.Add(2*time.Minute))
	if n, _ := s.PruneAlerts(ctx, t0.Add(time.Minute)); n != 0 {
		t.Errorf("alerts resolved after the cut-off stay, deleted %d", n)
	}
	if n, _ := s.PruneAlerts(ctx, t0.Add(time.Hour)); n != 1 {
		t.Errorf("alerts resolved before the cut-off are deleted, deleted %d", n)
	}
}

func TestSettings(t *testing.T) {
	s := open(t)
	if got, err := s.Settings(ctx); err != nil || len(got) != 0 {
		t.Fatalf("fresh settings = %v, %v", got, err)
	}
	s.SetSettings(ctx, map[string]string{"webhook_url": "https://a", "cpu_for_min": "5"})
	s.SetSettings(ctx, map[string]string{"webhook_url": "https://b"})
	got, _ := s.Settings(ctx)
	if !reflect.DeepEqual(got, map[string]string{"webhook_url": "https://b", "cpu_for_min": "5"}) {
		t.Errorf("settings = %v; a later write replaces a key and keeps the others", got)
	}
}
