package web

import (
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
)

func TestUptimeText(t *testing.T) {
	for _, c := range []struct {
		st   store.CheckStats
		want string
	}{
		{store.CheckStats{}, "–"},
		{store.CheckStats{Checks: 10}, "100%"},
		{store.CheckStats{Checks: 10000, Down: 1}, "99.99%"},
		{store.CheckStats{Checks: 100000, Down: 1}, "99.99%"},
		{store.CheckStats{Checks: 200, Down: 1}, "99.5%"},
		{store.CheckStats{Checks: 3, Down: 1}, "66.66%"},
		{store.CheckStats{Checks: 4, Down: 4}, "0%"},
	} {
		if got := uptimeText(c.st); got != c.want {
			t.Errorf("uptimeText(%+v) = %q; want %q", c.st, got, c.want)
		}
	}
}

func TestAvailabilityBar(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	start := now.Add(-24 * time.Hour).Unix()
	rows := []store.CheckRow{
		{TS: start + 10}, {TS: start + 20}, // block 0: up
		{TS: start + 1800 + 1}, {TS: start + 1800 + 2, Down: true}, {TS: start + 1800 + 3}, // block 1: partial (1 of 3)
		{TS: start + 3600 + 1, Down: true}, {TS: start + 3600 + 2}, // block 2: down (half)
		{TS: now.Unix() - 1}, // last block
	}
	bar := availabilityBar(rows, now)
	if len(bar) != 48 {
		t.Fatalf("%d blocks; want 48", len(bar))
	}
	for i, want := range map[int]string{0: "up", 1: "partial", 2: "down", 3: "none", 47: "up"} {
		if bar[i].State != want {
			t.Errorf("block %d = %q; want %q", i, bar[i].State, want)
		}
	}
	if bar[1].Up != "66.66%" || bar[3].Up != "" || bar[0].From != start || bar[0].To != start+1800 {
		t.Errorf("block details = %+v %+v %+v", bar[0], bar[1], bar[3])
	}
}

func TestCertInfo(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	day := int64(86400)
	date := func(ts int64) string { return time.Unix(ts, 0).Format("2 Jan 2006") }
	for _, c := range []struct {
		url       string
		exp       int64
		self      bool
		show      bool
		text, lvl string
	}{
		{"http://a", now.Unix() + 90*day, false, false, "", ""},
		{"https://a", 0, false, false, "", ""},
		{"https://a", now.Unix() + 73*day + 5, false, true, "valid · expires in 73 days (" + date(now.Unix()+73*day+5) + ")", ""},
		{"https://a", now.Unix() + 5*day, true, true, "valid · expires in 5 days (" + date(now.Unix()+5*day) + ") · self-signed accepted", "warn"},
		{"https://a", now.Unix() + 100, false, true, "valid · expires within a day", "warn"},
		{"https://a", now.Unix() - 3*day, false, true, "expired 3 days ago", "bad"},
		{"https://a", now.Unix() - 7200, false, true, "expired less than a day ago", "bad"},
	} {
		got := certInfo(store.Service{URL: c.url, CertExpiresAt: c.exp, AcceptSelfSigned: c.self}, now)
		if got.Show != c.show || (c.show && (got.Text != c.text || got.Level != c.lvl)) {
			t.Errorf("certInfo(%s, %d) = %+v; want %v %q %q", c.url, c.exp, got, c.show, c.text, c.lvl)
		}
	}
}

func TestDurationText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		14 * time.Second:               "14 s",
		8*time.Minute + 14*time.Second: "8 min 14 s",
		9 * time.Minute:                "9 min",
		2*time.Hour + 5*time.Minute:    "2 h 5 min",
		3*24*time.Hour + 4*time.Hour:   "3 d 4 h",
		0:                              "0 s",
	} {
		if got := durationText(d); got != want {
			t.Errorf("durationText(%v) = %q; want %q", d, got, want)
		}
	}
}

func TestAvailabilityBarKeepsTheCheckOfThisSecond(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	bar := availabilityBar([]store.CheckRow{{TS: now.Unix(), Down: true}}, now)
	if bar[47].State != "down" {
		t.Fatalf("last block = %+v; the check that triggered the redraw must count", bar[47])
	}
}
