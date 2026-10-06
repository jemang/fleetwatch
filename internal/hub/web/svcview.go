package web

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"fleetwatch/internal/hub/store"
)

// ServiceCard is one service on the Services page.
type ServiceCard struct {
	ID                               int64
	Name, URL, Group, Letter, Search string
	IconURL                          string // "" shows the letter tile
	Paused                           bool

	// The live status line: State is paused while disabled; Reason is the
	// failure shown as a tooltip.
	State, MsText, Reason string
	Checked, Since        int64
	Uptime                string // 30 days, "–" without checks
}

type ServiceGroup struct {
	Name  string
	Cards []ServiceCard
}

const ungrouped = "Ungrouped"

func serviceCard(sv store.Service) ServiceCard {
	c := ServiceCard{ID: sv.ID, Name: sv.Name, URL: sv.URL, Group: sv.Group, Paused: !sv.Enabled}
	if r, _ := utf8.DecodeRuneInString(sv.Name); r != utf8.RuneError {
		c.Letter = string(unicode.ToUpper(r))
	}
	if sv.IconAt != 0 {
		c.IconURL = "/services/" + strconv.FormatInt(sv.ID, 10) + "/icon?v=" + strconv.FormatInt(sv.IconAt, 10)
	}
	host := ""
	if u, err := url.Parse(sv.URL); err == nil {
		host = u.Host
	}
	c.State, c.MsText, c.Checked, c.Since = sv.State, msText(sv.LastMs), sv.CheckedAt, sv.StateSince
	switch {
	case !sv.Enabled:
		c.State = "paused"
	case c.State == "":
		c.State = "unknown"
	}
	if c.State == "down" || (c.State == "unknown" && sv.CheckedAt != 0) {
		c.Reason = sv.LastError
	}
	c.Search = strings.ToLower(strings.Join(strings.Fields(sv.Name+" "+host+" "+sv.Group+" "+sv.Description), " "))
	return c
}

// BuildServiceGroups keeps the store's order: grouped services by group, the
// ungrouped ones last.
func BuildServiceGroups(list []store.Service, stats map[int64]store.CheckStats) []ServiceGroup {
	var out []ServiceGroup
	for _, sv := range list {
		name := sv.Group
		if name == "" {
			name = ungrouped
		}
		if len(out) == 0 || out[len(out)-1].Name != name {
			out = append(out, ServiceGroup{Name: name})
		}
		c := serviceCard(sv)
		c.Uptime = uptimeText(stats[sv.ID])
		out[len(out)-1].Cards = append(out[len(out)-1].Cards, c)
	}
	return out
}

// msText prints a response time with thousands separators: "1,842 ms".
func msText(ms int) string {
	s := strconv.Itoa(ms)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s + " ms"
}

// uptimeText rounds down to two decimals, so one down check in 10000 is not
// shown as 100%.
func uptimeText(st store.CheckStats) string {
	if st.Checks == 0 {
		return "–"
	}
	bp := (st.Checks - st.Down) * 10000 / st.Checks
	s := strconv.FormatInt(bp/100, 10)
	if f := bp % 100; f != 0 {
		s += "." + strings.TrimRight(fmt.Sprintf("%02d", f), "0")
	}
	return s + "%"
}

func avgMsText(st store.CheckStats) string {
	if st.MsN == 0 {
		return "–"
	}
	return msText(int(st.MsSum / st.MsN))
}

// BarBlock is 30 minutes of the availability bar. Up is "" without checks.
type BarBlock struct {
	State, Up string
	From, To  int64
}

const barBlocks, barBlock = 48, int64(1800)

// availabilityBar splits the last 24 hours into 30-minute blocks: up when no
// check was down, partial when under half were, down otherwise, none without
// checks.
func availabilityBar(rows []store.CheckRow, now time.Time) []BarBlock {
	start := now.Unix() - barBlocks*barBlock
	var checks, down [barBlocks]int64
	for _, r := range rows {
		i := (r.TS - start) / barBlock
		if r.TS < start || r.TS > now.Unix() {
			continue
		}
		if i == barBlocks {
			i-- // finished this second: the redraw it caused must show it
		}
		checks[i]++
		if r.Down {
			down[i]++
		}
	}
	out := make([]BarBlock, barBlocks)
	for i := range out {
		b := BarBlock{From: start + int64(i)*barBlock, To: start + int64(i+1)*barBlock, State: "none"}
		if checks[i] > 0 {
			b.Up = uptimeText(store.CheckStats{Checks: checks[i], Down: down[i]})
			switch {
			case down[i] == 0:
				b.State = "up"
			case down[i]*2 < checks[i]:
				b.State = "partial"
			default:
				b.State = "down"
			}
		}
		out[i] = b
	}
	return out
}

type CertInfo struct {
	Show        bool
	Text, Level string
}

// certInfo describes the certificate the last HTTPS check saw; HTTP services
// and services without a seen certificate show nothing.
func certInfo(sv store.Service, now time.Time) CertInfo {
	if !strings.HasPrefix(strings.ToLower(sv.URL), "https://") || sv.CertExpiresAt == 0 {
		return CertInfo{}
	}
	left := sv.CertExpiresAt - now.Unix()
	if left <= 0 {
		return CertInfo{Show: true, Level: "bad", Text: "expired " + plural(-left/86400, "day") + " ago"}
	}
	c := CertInfo{Show: true}
	if days := left / 86400; days == 0 {
		c.Text = "valid · expires within a day"
	} else {
		c.Text = "valid · expires in " + plural(days, "day") + " (" + time.Unix(sv.CertExpiresAt, 0).UTC().Format("2 Jan 2006") + ")"
	}
	if left < 14*86400 {
		c.Level = "warn"
	}
	if sv.AcceptSelfSigned {
		c.Text += " · self-signed accepted"
	}
	return c
}

func plural(n int64, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.FormatInt(n, 10) + " " + word + "s"
}

// durationText shows the two largest units: "8 min 14 s", "3 d 4 h".
func durationText(d time.Duration) string {
	s := int64(d / time.Second)
	units := []struct {
		n    int64
		name string
	}{{s / 86400, "d"}, {s % 86400 / 3600, "h"}, {s % 3600 / 60, "min"}, {s % 60, "s"}}
	for i, u := range units[:3] {
		if u.n > 0 {
			out := strconv.FormatInt(u.n, 10) + " " + u.name
			if next := units[i+1]; next.n > 0 {
				out += " " + strconv.FormatInt(next.n, 10) + " " + next.name
			}
			return out
		}
	}
	return strconv.FormatInt(s, 10) + " s"
}
