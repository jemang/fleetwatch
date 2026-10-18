// Package alert decides which hosts need attention, keeps the alerts and
// sends the messages.
package alert

import (
	"cmp"
	"fmt"
	"math"
	"strconv"
	"time"

	"fleetwatch/internal/hub/store"
)

const (
	KindOffline = "host_offline"
	KindCPU     = "cpu_high"
	KindRAM     = "ram_high"
	KindDisk    = "disk_full"
	KindStorage = "storage_inactive"
	KindGuest   = "guest_stopped"
	KindService = "service_failed"

	// The report interval agents are told to keep (setting report_interval_s).
	DefaultReportInterval = 30 * time.Second
	MinReportInterval     = 10 * time.Second
	MaxReportInterval     = 10 * time.Minute

	// How many reports in a row a host may miss before "Agent disconnected"
	// fires (setting offline_misses).
	DefaultOfflineMisses, MinOfflineMisses, MaxOfflineMisses = 3, 2, 20
)

// Title is the short name of an alert kind for people.
var Title = map[string]string{
	KindOffline: "Agent disconnected", KindCPU: "CPU high", KindRAM: "Memory high", KindDisk: "Disk full",
	KindStorage: "Storage inactive", KindGuest: "Guest stopped", KindService: "Service failed",
	KindSvcDown: "Service DOWN", KindSvcSlow: "Service slow", KindSvcCert: "Certificate expiring",
}

// ResolvedTitle is the alert's name in its "resolved" message, where the
// plain title would say the opposite of what happened.
var ResolvedTitle = map[string]string{
	KindOffline: "Agent connected", KindSvcDown: "Service recovered", KindSvcSlow: "Service fast again", KindSvcCert: "Certificate renewed",
}

// Limits are the percentages at or above which CPU, memory and disk count as
// high (settings cpu_limit_pct, ram_limit_pct, disk_limit_pct). The host list
// and charts mark the same values in amber.
type Limits struct{ CPU, RAM, Disk int }

var DefaultLimits = Limits{CPU: 90, RAM: 90, Disk: 85}

// orDefault fills a zero limit with its default, so Rules made without
// settings do not alert on everything.
func (l Limits) orDefault() Limits {
	return Limits{cmp.Or(l.CPU, DefaultLimits.CPU), cmp.Or(l.RAM, DefaultLimits.RAM), cmp.Or(l.Disk, DefaultLimits.Disk)}
}

// Rules holds the levels and how long a condition must last before its alert
// fires.
type Rules struct {
	OfflineMisses                       int
	Limits                              Limits
	CPUFor, RAMFor, DiskFor, StorageFor time.Duration
}

// RulesFrom reads the waiting times from settings; a missing or unreadable
// value keeps its default.
func RulesFrom(settings map[string]string) Rules {
	get := func(key string, def, unit time.Duration) time.Duration {
		n, err := strconv.Atoi(settings[key])
		if err != nil || n < 0 {
			return def
		}
		return time.Duration(n) * unit
	}
	pct := func(key string, def int) int {
		n, err := strconv.Atoi(settings[key])
		if err != nil || n < 1 || n > 100 {
			return def
		}
		return n
	}
	misses, err := strconv.Atoi(settings["offline_misses"])
	if err != nil || misses < MinOfflineMisses || misses > MaxOfflineMisses {
		misses = DefaultOfflineMisses
	}
	return Rules{
		OfflineMisses: misses,
		Limits:        Limits{pct("cpu_limit_pct", DefaultLimits.CPU), pct("ram_limit_pct", DefaultLimits.RAM), pct("disk_limit_pct", DefaultLimits.Disk)},
		CPUFor:        get("cpu_for_min", 5*time.Minute, time.Minute),
		RAMFor:        get("ram_for_min", 5*time.Minute, time.Minute),
		DiskFor:       get("disk_for_min", 2*time.Minute, time.Minute),
		StorageFor:    2 * time.Minute,
	}
}

// ReportInterval is how long agents are told to wait between reports; a
// missing or out-of-range value keeps the default.
func ReportInterval(settings map[string]string) time.Duration {
	n, err := strconv.Atoi(settings["report_interval_s"])
	d := time.Duration(n) * time.Second
	if err != nil || d < MinReportInterval || d > MaxReportInterval {
		return DefaultReportInterval
	}
	return d
}

// StaleAfter is how long a host whose agent waits interval between reports
// may stay silent before nothing is known about it: one report may be lost
// and the next may be slow. An unknown interval (0) counts as the default.
func StaleAfter(interval time.Duration) time.Duration {
	if interval <= 0 {
		interval = DefaultReportInterval
	}
	return 2*interval + 15*time.Second
}

// OfflineAlertAfter is how long a host whose agent waits interval between
// reports may stay silent before "Agent disconnected" fires: misses reports,
// the last of them up to 15 s late. With misses at least 2 it is never
// shorter than StaleAfter.
func OfflineAlertAfter(interval time.Duration, misses int) time.Duration {
	if interval <= 0 {
		interval = DefaultReportInterval
	}
	return time.Duration(misses)*interval + 15*time.Second
}

// Condition is something that is wrong right now. Its alert fires once the
// condition has lasted For.
type Condition struct {
	HostID                int64
	Kind, Subject, Detail string
	For                   time.Duration
}

type GuestKey struct {
	HostID int64
	Guest  int
}

func pct(used, total uint64) int { return int(math.Round(float64(used) / float64(total) * 100)) }

// Evaluate lists what is wrong now. unknown marks hosts that are not
// reporting: nothing can be said about their other conditions. seenRunning
// remembers guests that were seen running, so only those can "stop".
func Evaluate(hosts []store.Host, now time.Time, r Rules, seenRunning map[GuestKey]bool) (conds []Condition, unknown map[int64]bool) {
	unknown = map[int64]bool{}
	lim := r.Limits.orDefault()
	for _, h := range hosts {
		// A disabled agent is silent on purpose: nothing is wrong, so its
		// open alerts end.
		if h.Disabled {
			continue
		}
		if h.LastSeen.IsZero() {
			unknown[h.ID] = true
			continue
		}
		if silent := now.Sub(h.LastSeen); silent > StaleAfter(h.ReportInterval) {
			unknown[h.ID] = true
			if silent >= OfflineAlertAfter(h.ReportInterval, r.OfflineMisses) {
				conds = append(conds, Condition{HostID: h.ID, Kind: KindOffline})
			}
			continue
		}
		m := h.Metrics
		if m == nil {
			continue
		}
		if m.CPUPct != nil {
			if v := int(math.Round(*m.CPUPct)); v >= lim.CPU {
				conds = append(conds, Condition{h.ID, KindCPU, "", fmt.Sprintf("CPU %d%%", v), r.CPUFor})
			}
		}
		if m.Mem != nil && m.Mem.Total > 0 {
			if v := pct(m.Mem.Used, m.Mem.Total); v >= lim.RAM {
				conds = append(conds, Condition{h.ID, KindRAM, "", fmt.Sprintf("memory %d%%", v), r.RAMFor})
			}
		}
		for _, d := range m.Disks {
			if d.Total == 0 {
				continue
			}
			if v := pct(d.Used, d.Total); v >= lim.Disk {
				conds = append(conds, Condition{h.ID, KindDisk, d.Mount, fmt.Sprintf("%s %d%%", d.Mount, v), r.DiskFor})
			}
		}
		present := map[int]bool{}
		if p := m.Proxmox; p != nil && p.Configured && p.Error == "" {
			for _, g := range p.Guests {
				key := GuestKey{h.ID, g.ID}
				present[g.ID] = true
				switch {
				case g.Status == "running":
					seenRunning[key] = true
				case g.Status == "stopped" && seenRunning[key]:
					kind := "VM"
					if g.Type == "lxc" {
						kind = "LXC"
					}
					conds = append(conds, Condition{h.ID, KindGuest, strconv.Itoa(g.ID), fmt.Sprintf("%s (%s %d) stopped", g.Name, kind, g.ID), 0})
				}
			}
			for _, s := range p.Storage {
				if !s.Active {
					conds = append(conds, Condition{h.ID, KindStorage, s.Name, s.Name + " inactive", r.StorageFor})
				}
			}
			for key := range seenRunning {
				if key.HostID == h.ID && !present[key.Guest] {
					delete(seenRunning, key)
				}
			}
		}
		for _, svc := range m.Services {
			if svc.Status == "failed" {
				conds = append(conds, Condition{h.ID, KindService, svc.Name, svc.Name + " failed", 0})
			}
		}
	}
	return conds, unknown
}
