// Package web serves the dashboard.
package web

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"fleetwatch/internal/hub/alert"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

const (
	OfflineAfter = 45 * time.Second
	warnCPU      = alert.LimitCPU
	warnRAM      = alert.LimitRAM
	warnDisk     = alert.LimitDisk
)

func Online(lastSeen, now time.Time) bool {
	return !lastSeen.IsZero() && now.Sub(lastSeen) <= OfflineAfter
}

type Usage struct {
	Known bool
	Pct   int
	Warn  bool
	Tip   string // amounts behind the percentage, shown on hover
}

type HostRow struct {
	ID             int64
	Name           string
	Label          string // set on the Hub; Name is the label, or the hostname without one
	Hostname       string
	IP, IPTitle    string
	IPKey          string // the IPv4 address as a number, for sorting; empty otherwise
	CPU, RAM, Disk Usage
	Uptime         string
	UptimeS        uint64 // 0 when unknown
	Online         bool
	Disabled       bool // the Hub refuses this host's agent; never Online
	LastSeenUnix   int64
	FailedServices int // counted only while the host is online
	// Proxmox hosts only: "running / total" guests, the total as a sort key,
	// and the number of inactive storages while the host is online.
	Guests, GuestKey string
	InactiveStorage  int
}

// Status is the host state as the page marks it up.
func (r HostRow) Status() string {
	switch {
	case r.Disabled:
		return "disabled"
	case r.Online:
		return "online"
	}
	return "offline"
}

func (r HostRow) StatusLabel() string {
	return strings.ToUpper(r.Status()[:1]) + r.Status()[1:]
}

// Stat is one fleet-wide tile: the average and the highest host.
type Stat struct {
	Known   bool
	Avg     int
	Max     int
	MaxHost string
	MaxWarn bool
}

type Summary struct {
	Hosts, Online, Offline int
	Disabled               int // counted neither as online nor as offline
	CPU, RAM, Disk         Stat
	Warnings               int    // hosts with at least one value over its limit
	WarnHosts              string // up to three names, then a count
}

const warnNames = 3

func Summarize(rows []HostRow) Summary {
	s := Summary{Hosts: len(rows)}
	var names []string
	var cpu, ram, disk statAcc
	for _, r := range rows {
		if r.Online {
			s.Online++
		}
		if r.Disabled {
			s.Disabled++
		}
		cpu.add(r.CPU, r.Name)
		ram.add(r.RAM, r.Name)
		disk.add(r.Disk, r.Name)
		if r.CPU.Warn || r.RAM.Warn || r.Disk.Warn || r.FailedServices > 0 || r.InactiveStorage > 0 {
			names = append(names, r.Name)
		}
	}
	s.Offline = s.Hosts - s.Online - s.Disabled
	s.CPU, s.RAM, s.Disk = cpu.stat(), ram.stat(), disk.stat()
	s.Warnings = len(names)
	if len(names) > warnNames {
		s.WarnHosts = fmt.Sprintf("%s +%d more", strings.Join(names[:warnNames], ", "), len(names)-warnNames)
	} else {
		s.WarnHosts = strings.Join(names, ", ")
	}
	return s
}

type statAcc struct {
	n, sum int
	best   Stat
}

func (a *statAcc) add(u Usage, host string) {
	if !u.Known {
		return
	}
	a.n++
	a.sum += u.Pct
	if !a.best.Known || u.Pct > a.best.Max {
		a.best = Stat{Known: true, Max: u.Pct, MaxHost: host, MaxWarn: u.Warn}
	}
}

func (a *statAcc) stat() Stat {
	if a.n == 0 {
		return Stat{}
	}
	a.best.Avg = int(math.Round(float64(a.sum) / float64(a.n)))
	return a.best
}

func usage(pct float64, warnAt int, tip string) Usage {
	n := min(max(int(math.Round(pct)), 0), 100)
	return Usage{Known: true, Pct: n, Warn: n >= warnAt, Tip: tip}
}

func ratio(used, total uint64) float64 { return float64(used) / float64(total) * 100 }

// BuildRow turns stored state into what one table row shows. An offline host
// shows no metrics: they would be stale.
func BuildRow(h store.Host, now time.Time) HostRow {
	row := HostRow{ID: h.ID, Name: h.Name, IP: "–", Uptime: "–", Online: !h.Disabled && Online(h.LastSeen, now), Disabled: h.Disabled, Label: h.Label, Hostname: h.Hostname}
	if !h.LastSeen.IsZero() {
		row.LastSeenUnix = h.LastSeen.Unix()
	}
	if h.Inventory != nil {
		row.IP, row.IPTitle = pickIP(h.Inventory.Interfaces)
		row.IPKey = ipKey(row.IP)
	}
	if !row.Online || h.Metrics == nil {
		return row
	}
	m := h.Metrics
	if m.CPUPct != nil {
		tip := strconv.FormatFloat(*m.CPUPct, 'f', 1, 64) + "%"
		if h.Inventory != nil && h.Inventory.Cores > 0 {
			tip += " of " + strconv.Itoa(h.Inventory.Cores) + " cores"
		}
		row.CPU = usage(*m.CPUPct, warnCPU, tip)
	}
	if m.Mem != nil && m.Mem.Total > 0 {
		row.RAM = usage(ratio(m.Mem.Used, m.Mem.Total), warnRAM, fmtBytes(m.Mem.Used)+" / "+fmtBytes(m.Mem.Total))
	}
	// The bar shows the fullest disk; the tooltip lists all, fullest first.
	disks := make([]protocol.Disk, 0, len(m.Disks))
	for _, d := range m.Disks {
		if d.Total > 0 {
			disks = append(disks, d)
		}
	}
	sort.SliceStable(disks, func(i, j int) bool { return ratio(disks[i].Used, disks[i].Total) > ratio(disks[j].Used, disks[j].Total) })
	if len(disks) > 0 {
		lines := make([]string, len(disks))
		for i, d := range disks {
			p := ratio(d.Used, d.Total)
			lines[i] = fmt.Sprintf("%s: %s / %s (%d%%)", d.Mount, fmtBytes(d.Used), fmtBytes(d.Total), int(math.Round(p)))
		}
		row.Disk = usage(ratio(disks[0].Used, disks[0].Total), warnDisk, strings.Join(lines, "\n"))
	}
	if m.UptimeS > 0 {
		row.Uptime, row.UptimeS = fmtUptime(m.UptimeS), m.UptimeS
	}
	for _, svc := range m.Services {
		if svc.Status == "failed" {
			row.FailedServices++
		}
	}
	if p := m.Proxmox; p != nil && p.Configured && p.Error == "" {
		running := 0
		for _, g := range p.Guests {
			if g.Status == "running" {
				running++
			}
		}
		row.Guests, row.GuestKey = fmt.Sprintf("%d / %d", running, len(p.Guests)), strconv.Itoa(len(p.Guests))
		for _, st := range p.Storage {
			if !st.Active {
				row.InactiveStorage++
			}
		}
	}
	return row
}

func ipKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return ""
	}
	b := a.As4()
	return strconv.FormatUint(uint64(b[0])<<24|uint64(b[1])<<16|uint64(b[2])<<8|uint64(b[3]), 10)
}

// pickIP prefers the first IPv4 of the default-route interface, then any
// IPv4, then any IPv6.
func pickIP(ifs []protocol.Interface) (ip, title string) {
	var all []string
	var preferred, any4, any6 string
	for _, i := range ifs {
		for _, a := range i.IPv4 {
			all = append(all, i.Name+" "+a)
		}
		for _, a := range i.IPv6 {
			all = append(all, i.Name+" "+a)
		}
		if len(i.IPv4) > 0 {
			if i.DefaultRoute && preferred == "" {
				preferred = i.IPv4[0]
			}
			if any4 == "" {
				any4 = i.IPv4[0]
			}
		}
		if len(i.IPv6) > 0 && any6 == "" {
			any6 = i.IPv6[0]
		}
	}
	ip = "–"
	for _, c := range []string{preferred, any4, any6} {
		if c != "" {
			ip = c
			break
		}
	}
	return ip, strings.Join(all, ", ")
}

func fmtUptime(sec uint64) string {
	d, h, m := sec/86400, sec%86400/3600, sec%3600/60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}
