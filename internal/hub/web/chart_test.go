package web

import (
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
)

func pt(sec int64, cpu float64) store.MetricPoint {
	return store.MetricPoint{TS: now.Unix() + sec, CPU: &cpu}
}

func cpuOf(p store.MetricPoint) *float64 { return p.CPU }

func TestBuildChartScalesToThePlotArea(t *testing.T) {
	from, to := now, now.Add(time.Hour)
	c := BuildChart("CPU", []store.MetricPoint{pt(0, 0), pt(1800, 100), pt(3600, 50)}, cpuOf, from, to, 1800, 90)
	// Plot area: x 36..412, y 12 (100%) .. 128 (0%).
	if c.Path != "M36.0 128.0L224.0 12.0L412.0 70.0" {
		t.Errorf("path = %q", c.Path)
	}
	if c.Area != "M36.0 128.0L36.0 128.0L224.0 12.0L412.0 70.0L412.0 128.0Z" {
		t.Errorf("area = %q", c.Area)
	}
	if c.Empty || c.Last != "50%" || c.Min != "0%" || c.Max != "100%" || c.Avg != "50%" {
		t.Errorf("stats: empty %v last %q min %q avg %q max %q", c.Empty, c.Last, c.Min, c.Avg, c.Max)
	}
	if c.Limit != 90 || c.LimitY != "23.6" {
		t.Errorf("limit line: %d at y %q, want 90 at 23.6", c.Limit, c.LimitY)
	}
	if len(c.XTicks) != 5 || c.XTicks[0].X != "36.0" || c.XTicks[4].X != "412.0" || c.XTicks[2].TS != now.Unix()+1800 {
		t.Errorf("x ticks = %+v", c.XTicks)
	}
	if c.Points != "[[1790000000,0],[1790001800,100],[1790003600,50]]" {
		t.Errorf("hover data = %s", c.Points)
	}
}

func TestBuildChartBreaksTheLineAtGaps(t *testing.T) {
	from, to := now, now.Add(time.Hour)
	pts := []store.MetricPoint{pt(0, 10), pt(60, 10), pt(1800, 20), pt(1860, 20), {TS: now.Unix() + 1920}, pt(1980, 20)}
	c := BuildChart("CPU", pts, cpuOf, from, to, 60, 0)
	if n := strings.Count(c.Path, "M"); n != 3 {
		t.Errorf("a silence longer than the step, and a row without a value, must each start a new line: %d segments in %q", n, c.Path)
	}
	if n := strings.Count(c.Area, "Z"); n != 3 {
		t.Errorf("each segment needs its own closed area, got %d", n)
	}
	if c.Limit != 0 || c.LimitY != "" {
		t.Error("no limit line when the limit is 0")
	}
}

func TestBuildChartSinglePointIsVisible(t *testing.T) {
	c := BuildChart("CPU", []store.MetricPoint{pt(1800, 40)}, cpuOf, now, now.Add(time.Hour), 60, 0)
	if c.Path != "M224.0 81.6L224.1 81.6" {
		t.Errorf("one sample must still draw a dot-sized stroke, path = %q", c.Path)
	}
}

func TestBuildChartWithoutData(t *testing.T) {
	c := BuildChart("CPU", nil, cpuOf, now, now.Add(time.Hour), 60, 90)
	if !c.Empty || c.Path != "" || c.Last != "–" || c.Points != "[]" {
		t.Errorf("empty chart = %+v", c)
	}
}

func TestSparkPath(t *testing.T) {
	if got := SparkPath(nil, cpuOf); got != "" {
		t.Errorf("no data, no trend line: %q", got)
	}
	if got := SparkPath([]store.MetricPoint{pt(0, 5)}, cpuOf); got != "" {
		t.Errorf("one sample is not a trend: %q", got)
	}
	// Values 10..30: a 20-point range fills the 2..26 band of the 100x28 box.
	got := SparkPath([]store.MetricPoint{pt(0, 10), pt(60, 30), pt(120, 20)}, cpuOf)
	if got != "M0.0 26.0L50.0 2.0L100.0 14.0" {
		t.Errorf("spark = %q", got)
	}
	// A nearly flat series must not be stretched into a dramatic line.
	flat := SparkPath([]store.MetricPoint{pt(0, 50), pt(60, 51)}, cpuOf)
	if flat != "M0.0 15.2L100.0 12.8" {
		t.Errorf("flat spark = %q; want a 10-point minimum range centred on the data", flat)
	}
}
