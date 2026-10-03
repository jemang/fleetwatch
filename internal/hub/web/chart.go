package web

import (
	"math"
	"strconv"
	"strings"
	"time"

	"fleetwatch/internal/hub/store"
)

// Chart geometry inside a 420x152 viewBox. The box is close to the size a
// chart is shown at, so axis text keeps a readable size.
const (
	chartLeft, chartRight = 36.0, 412.0
	chartTop, chartBottom = 12.0, 128.0
	chartXTicks           = 5
)

type XTick struct {
	X  string
	TS int64 // the browser formats it in the viewer's time zone
}

// Chart is one percentage series over time, ready for the template.
type Chart struct {
	Title               string
	Path, Area          string
	XTicks              []XTick
	Limit               int    // 0 means no limit line
	LimitY              string // y of the limit line
	Points              string // [[ts,value],…] for the hover layer
	Last, Min, Avg, Max string
	Empty               bool
}

func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

func pctLabel(v float64) string { return strconv.Itoa(int(math.Round(v))) + "%" }

// BuildChart draws values between from and to on a fixed 0–100% axis. A
// silence longer than 2.5 steps, or a row without a value, breaks the line:
// an offline host must not look like a flat one.
func BuildChart(title string, pts []store.MetricPoint, pick func(store.MetricPoint) *float64, from, to time.Time, step int64, limit int) Chart {
	c := Chart{Title: title, Limit: limit, Last: "–", Min: "–", Avg: "–", Max: "–", Empty: true, Points: "[]"}
	span := float64(to.Unix() - from.Unix())
	x := func(ts int64) float64 { return chartLeft + float64(ts-from.Unix())/span*(chartRight-chartLeft) }
	y := func(v float64) float64 { return chartBottom - min(max(v, 0), 100)/100*(chartBottom-chartTop) }

	if limit > 0 {
		c.LimitY = f1(y(float64(limit)))
	}
	for i := 0; i < chartXTicks; i++ {
		frac := float64(i) / (chartXTicks - 1)
		c.XTicks = append(c.XTicks, XTick{X: f1(chartLeft + frac*(chartRight-chartLeft)), TS: from.Unix() + int64(frac*span)})
	}

	var path, area, data strings.Builder
	var sum, lo, hi, last float64
	var n, segLen int
	var segFirstX, prevX float64
	var prevTS int64
	closeSegment := func() {
		if segLen == 0 {
			return
		}
		if segLen == 1 { // a lone sample: widen it so the round stroke shows a dot
			path.WriteString("L" + f1(prevX+0.1) + " " + f1(y(last)))
			area.WriteString("L" + f1(prevX+0.1) + " " + f1(y(last)))
			prevX += 0.1
		}
		area.WriteString("L" + f1(prevX) + " " + f1(chartBottom) + "Z")
		segLen = 0
	}
	for _, p := range pts {
		v := pick(p)
		if v == nil {
			closeSegment()
			continue
		}
		if segLen > 0 && float64(p.TS-prevTS) > 2.5*float64(step) {
			closeSegment()
		}
		px, py := x(p.TS), y(*v)
		if segLen == 0 {
			segFirstX = px
			path.WriteString("M" + f1(px) + " " + f1(py))
			area.WriteString("M" + f1(segFirstX) + " " + f1(chartBottom) + "L" + f1(px) + " " + f1(py))
		} else {
			path.WriteString("L" + f1(px) + " " + f1(py))
			area.WriteString("L" + f1(px) + " " + f1(py))
		}
		segLen++
		prevX, prevTS, last = px, p.TS, *v
		if n == 0 || *v < lo {
			lo = *v
		}
		if n == 0 || *v > hi {
			hi = *v
		}
		sum += *v
		if n > 0 {
			data.WriteByte(',')
		}
		data.WriteString("[" + strconv.FormatInt(p.TS, 10) + "," + strconv.FormatFloat(math.Round(*v*10)/10, 'f', -1, 64) + "]")
		n++
	}
	closeSegment()
	if n == 0 {
		return c
	}
	c.Empty = false
	c.Path, c.Area, c.Points = path.String(), area.String(), "["+data.String()+"]"
	c.Last, c.Min, c.Avg, c.Max = pctLabel(last), pctLabel(lo), pctLabel(sum/float64(n)), pctLabel(hi)
	return c
}

// SparkPath is a trend line for a 100x28 box. The value range is at least 10
// points wide, so small noise does not look like a swing.
func SparkPath(pts []store.MetricPoint, pick func(store.MetricPoint) *float64) string {
	type sample struct {
		ts int64
		v  float64
	}
	var s []sample
	for _, p := range pts {
		if v := pick(p); v != nil {
			s = append(s, sample{p.TS, *v})
		}
	}
	if len(s) < 2 {
		return ""
	}
	lo, hi := s[0].v, s[0].v
	for _, p := range s {
		lo, hi = min(lo, p.v), max(hi, p.v)
	}
	if hi-lo < 10 {
		mid := (lo + hi) / 2
		lo, hi = mid-5, mid+5
		if lo < 0 {
			lo, hi = 0, 10
		}
		if hi > 100 {
			lo, hi = 90, 100
		}
	}
	span := float64(s[len(s)-1].ts - s[0].ts)
	var b strings.Builder
	for i, p := range s {
		if i == 0 {
			b.WriteByte('M')
		} else {
			b.WriteByte('L')
		}
		b.WriteString(f1(float64(p.ts-s[0].ts)/span*100) + " " + f1(26-(p.v-lo)/(hi-lo)*24))
	}
	return b.String()
}
