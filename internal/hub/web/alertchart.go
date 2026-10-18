package web

import (
	"cmp"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"fleetwatch/internal/hub/store"
)

// alertChartDays is how many days the Dashboard's alert chart covers, today
// included. Resolved alerts are kept 90 days, so the window is always whole.
const alertChartDays = 30

// The alert chart spans the page, so its viewBox is twice as wide as the host
// charts' (840x152) to keep axis text at a readable size.
const alertChartRight = 832.0

// AlertSeg is one category's part of a day's bar, in viewBox units.
type AlertSeg struct {
	Class  string // offline, service or resource
	Y, H   float64
	YS, HS string
}

type AlertBar struct {
	X, W, SlotX, SlotW string
	Total              int
	Segs               []AlertSeg // bottom first
	Tip                string
}

type SourceCount struct {
	Name string
	N    int
}

// AlertChart counts the alerts that fired per day, split by what went wrong.
type AlertChart struct {
	Bars                              []AlertBar
	XTicks                            []struct{ X, Label string }
	YMax                              int
	YMid                              string
	Total, Offline, Service, Resource int
	TotalText                         string // "5 alerts"
	Busiest                           string // "" when there were none
	Top                               []SourceCount
	Empty                             bool
}

func alertCategory(kind string) string {
	switch {
	case kind == "host_offline":
		return "offline"
	case strings.HasPrefix(kind, "svc_"):
		return "service"
	}
	return "resource"
}

// BuildAlertChart draws the last alertChartDays days up to now. Days start at
// midnight in loc, the Hub's time zone, as in alert messages.
func BuildAlertChart(alerts []store.Alert, now time.Time, loc *time.Location) AlertChart {
	now = now.In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	first := today.AddDate(0, 0, -(alertChartDays - 1))
	cats := []string{"offline", "service", "resource"}
	counts := make([]map[string]int, alertChartDays)
	for i := range counts {
		counts[i] = map[string]int{}
	}
	var c AlertChart
	sources := map[string]int{}
	for _, a := range alerts {
		t := a.FiredAt.In(loc)
		if t.Before(first) || !t.Before(today.AddDate(0, 0, 1)) {
			continue
		}
		day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
		i := int(math.Round(day.Sub(first).Hours() / 24)) // DST days are 23 or 25 hours
		cat := alertCategory(a.Kind)
		counts[i][cat]++
		c.Total++
		switch cat {
		case "offline":
			c.Offline++
		case "service":
			c.Service++
		default:
			c.Resource++
		}
		name := a.Host
		if a.ServiceID != 0 || (name == "" && a.Service != "") {
			name = a.Service
		}
		if name != "" {
			sources[name]++
		}
	}
	c.Empty, c.TotalText = c.Total == 0, plural1(c.Total, "alert")

	peak, peakDay := 0, -1
	for i, m := range counts {
		if n := m["offline"] + m["service"] + m["resource"]; n > peak {
			peak, peakDay = n, i
		}
	}
	c.YMax = max(4, (peak+1)/2*2)
	c.YMid = strconv.Itoa(c.YMax / 2)
	dayText := func(i int) string { return first.AddDate(0, 0, i).Format("Mon 2 Jan") }
	if peakDay >= 0 {
		c.Busiest = dayText(peakDay) + " (" + strconv.Itoa(peak) + ")"
	}

	slot := (alertChartRight - chartLeft) / alertChartDays
	unit := (chartBottom - chartTop) / float64(c.YMax)
	for i, m := range counts {
		x := chartLeft + float64(i)*slot
		b := AlertBar{X: f1(x + slot*0.15), W: f1(slot * 0.7), SlotX: f1(x), SlotW: f1(slot)}
		y := chartBottom
		var parts []string
		for _, cat := range cats {
			n := m[cat]
			if n == 0 {
				continue
			}
			b.Total += n
			h := float64(n) * unit
			y -= h
			b.Segs = append(b.Segs, AlertSeg{Class: cat, Y: y, H: h, YS: f1(y), HS: f1(h)})
			parts = append(parts, strconv.Itoa(n)+" "+cat)
		}
		b.Tip = dayText(i) + "\n"
		if b.Total == 0 {
			b.Tip += "no alerts"
		} else {
			b.Tip += plural1(b.Total, "alert") + ": " + strings.Join(parts, ", ")
		}
		c.Bars = append(c.Bars, b)
	}
	for _, i := range []int{0, 7, 14, 21, alertChartDays - 1} {
		c.XTicks = append(c.XTicks, struct{ X, Label string }{f1(chartLeft + (float64(i)+0.5)*slot), first.AddDate(0, 0, i).Format("2 Jan")})
	}

	for name, n := range sources {
		c.Top = append(c.Top, SourceCount{name, n})
	}
	slices.SortFunc(c.Top, func(a, b SourceCount) int {
		return cmp.Or(cmp.Compare(b.N, a.N), cmp.Compare(a.Name, b.Name))
	})
	c.Top = c.Top[:min(3, len(c.Top))]
	return c
}
