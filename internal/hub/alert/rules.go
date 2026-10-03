// Package alert decides which hosts need attention, keeps the alerts and
// sends the messages.
package alert

import (
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

	// Limits in percent. The dashboard marks the same values in amber.
	LimitCPU, LimitRAM, LimitDisk = 90, 90, 85

	// staleAfter: without a report for this long nothing is known about a host.
	staleAfter = 45 * time.Second
)

// Title is the short name of an alert kind for people.
var Title = map[string]string{
	KindOffline: "Agent disconnected", KindCPU: "CPU high", KindRAM: "Memory high", KindDisk: "Disk full",
	KindStorage: "Storage inactive", KindGuest: "Guest stopped", KindService: "Service failed",
}

// Rules holds how long a condition must last before its alert fires.
type Rules struct{ OfflineAfter, CPUFor, RAMFor, DiskFor, StorageFor time.Duration }

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
	return Rules{
		OfflineAfter: get("offline_after_s", 60*time.Second, time.Second),
		CPUFor:       get("cpu_for_min", 5*time.Minute, time.Minute),
		RAMFor:       get("ram_for_min", 5*time.Minute, time.Minute),
		DiskFor:      get("disk_for_min", 2*time.Minute, time.Minute),
		StorageFor:   2 * time.Minute,
	}
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
		if silent := now.Sub(h.LastSeen); silent > staleAfter {
			unknown[h.ID] = true
			if silent >= r.OfflineAfter {
				conds = append(conds, Condition{HostID: h.ID, Kind: KindOffline})
			}
			continue
		}
		m := h.Metrics
		if m == nil {
			continue
		}
		if m.CPUPct != nil {
			if v := int(math.Round(*m.CPUPct)); v >= LimitCPU {
				conds = append(conds, Condition{h.ID, KindCPU, "", fmt.Sprintf("CPU %d%%", v), r.CPUFor})
			}
		}
		if m.Mem != nil && m.Mem.Total > 0 {
			if v := pct(m.Mem.Used, m.Mem.Total); v >= LimitRAM {
				conds = append(conds, Condition{h.ID, KindRAM, "", fmt.Sprintf("memory %d%%", v), r.RAMFor})
			}
		}
		for _, d := range m.Disks {
			if d.Total == 0 {
				continue
			}
			if v := pct(d.Used, d.Total); v >= LimitDisk {
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
