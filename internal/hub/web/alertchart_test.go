package web

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
)

func TestBuildAlertChart(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*3600)
	now := time.Date(2026, 10, 17, 13, 0, 0, 0, loc)
	at := func(day, hour int) time.Time { return time.Date(2026, 10, day, hour, 0, 0, 0, loc) }
	alerts := []store.Alert{
		{Kind: "host_offline", Host: "web-01", FiredAt: at(15, 1)},
		{Kind: "host_offline", Host: "web-01", FiredAt: at(15, 2)},
		{Kind: "svc_down", Service: "Wiki", FiredAt: at(15, 3)},
		{Kind: "ram_high", Host: "nas-01", FiredAt: at(15, 23)},
		{Kind: "host_offline", Host: "nas-01", FiredAt: at(17, 0)},                           // local midnight starts the 17th
		{Kind: "guest_stopped", Host: "web-01", FiredAt: at(16, 7).Add(-24 * 30 * time.Hour)}, // before the window
	}
	c := BuildAlertChart(alerts, now, loc)

	if c.Empty || len(c.Bars) != alertChartDays {
		t.Fatalf("Empty=%v bars=%d", c.Empty, len(c.Bars))
	}
	if c.Total != 5 || c.Offline != 3 || c.Service != 1 || c.Resource != 1 {
		t.Errorf("totals = %d (%d offline, %d service, %d resource), want 5 (3, 1, 1)", c.Total, c.Offline, c.Service, c.Resource)
	}
	last, oct15 := c.Bars[alertChartDays-1], c.Bars[alertChartDays-3]
	if last.Total != 1 || oct15.Total != 4 || c.Bars[alertChartDays-2].Total != 0 {
		t.Errorf("day counts: 15th %d, 16th %d, 17th %d", oct15.Total, c.Bars[alertChartDays-2].Total, last.Total)
	}
	if !strings.Contains(oct15.Tip, "Thu 15 Oct") || !strings.Contains(oct15.Tip, "4 alerts: 2 offline, 1 service, 1 resource") {
		t.Errorf("tip = %q", oct15.Tip)
	}
	if len(oct15.Segs) != 3 || oct15.Segs[0].Class != "offline" {
		t.Errorf("segments of the 15th = %+v", oct15.Segs)
	}
	if c.Busiest != "Thu 15 Oct (4)" {
		t.Errorf("busiest = %q", c.Busiest)
	}
	if len(c.Top) != 3 || c.Top[0] != (SourceCount{"nas-01", 2}) || c.Top[1] != (SourceCount{"web-01", 2}) || c.Top[2] != (SourceCount{"Wiki", 1}) {
		t.Errorf("top sources = %+v", c.Top)
	}
	if c.YMax < 4 || c.YMax%2 != 0 {
		t.Errorf("YMax = %d, want an even number of at least 4", c.YMax)
	}
	// Bars stay inside the plot and the tallest reaches no higher than the top.
	for _, s := range oct15.Segs {
		if s.Y < chartTop-0.01 || s.Y+s.H > chartBottom+0.01 {
			t.Errorf("segment outside the plot: %+v", s)
		}
	}
	lastX, _ := strconv.ParseFloat(last.SlotX, 64)
	lastW, _ := strconv.ParseFloat(last.SlotW, 64)
	if end := lastX + lastW; end < alertChartRight-0.2 || end > alertChartRight+0.2 {
		t.Errorf("the last day's column ends at %.1f, want the plot's right edge %.0f", end, alertChartRight)
	}
}

func TestBuildAlertChartEmpty(t *testing.T) {
	c := BuildAlertChart(nil, time.Date(2026, 10, 17, 13, 0, 0, 0, time.UTC), time.UTC)
	if !c.Empty || c.Total != 0 {
		t.Errorf("no alerts: Empty=%v Total=%d", c.Empty, c.Total)
	}
}
