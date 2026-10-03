package web

import (
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

var now = time.Unix(1_790_000_000, 0)

func f(v float64) *float64 { return &v }

func onlineHost() store.Host {
	return store.Host{
		ID: 1, Name: "pve-01", LastSeen: now.Add(-6 * time.Second),
		Metrics: &protocol.Metrics{
			CPUPct: f(14.2), UptimeS: 3628800,
			Mem:   &protocol.Mem{Total: 1000, Used: 600},
			Disks: []protocol.Disk{{Mount: "/", Total: 1000, Used: 400}, {Mount: "/data", Total: 1000, Used: 900}},
		},
		Inventory: &protocol.Inventory{Interfaces: []protocol.Interface{
			{Name: "docker0", IPv4: []string{"172.17.0.1"}, IPv6: []string{}},
			{Name: "eno1", DefaultRoute: true, IPv4: []string{"192.168.10.10"}, IPv6: []string{"2001:db8::10"}},
		}},
	}
}

func TestBuildRowOnline(t *testing.T) {
	r := BuildRow(onlineHost(), now)
	if !r.Online || r.Name != "pve-01" || r.LastSeenUnix != now.Add(-6*time.Second).Unix() {
		t.Errorf("row = %+v", r)
	}
	if r.CPU != (Usage{Known: true, Pct: 14}) || r.RAM != (Usage{Known: true, Pct: 60}) {
		t.Errorf("cpu = %+v ram = %+v", r.CPU, r.RAM)
	}
	if r.Disk != (Usage{Known: true, Pct: 90, Warn: true, Label: "/data"}) {
		t.Errorf("disk must be the mount with the highest usage: %+v", r.Disk)
	}
	if r.Uptime != "42d 0h" {
		t.Errorf("uptime = %q", r.Uptime)
	}
	if r.IP != "192.168.10.10" || r.IPTitle != "docker0 172.17.0.1, eno1 192.168.10.10, eno1 2001:db8::10" {
		t.Errorf("ip = %q title = %q", r.IP, r.IPTitle)
	}
}

func TestBuildRowSortKeys(t *testing.T) {
	r := BuildRow(onlineHost(), now)
	if r.IPKey != "3232238090" || r.UptimeS != 3628800 {
		t.Errorf("sort keys: ip %q uptime %d; want the IPv4 as a number and uptime in seconds", r.IPKey, r.UptimeS)
	}
	h := onlineHost()
	h.LastSeen = now.Add(-3 * time.Minute)
	if r := BuildRow(h, now); r.UptimeS != 0 || r.IPKey != "3232238090" {
		t.Errorf("offline row: uptime key %d must be unknown, ip key %q must stay", r.UptimeS, r.IPKey)
	}
	h.Inventory.Interfaces = []protocol.Interface{{Name: "eth0", IPv4: []string{}, IPv6: []string{"2001:db8::1"}}}
	if r := BuildRow(h, now); r.IPKey != "" {
		t.Errorf("an IPv6-only host has no numeric IP key, got %q", r.IPKey)
	}
}

func TestSummarizeStats(t *testing.T) {
	rows := []HostRow{
		{Name: "pve-01", Online: true, CPU: Usage{Known: true, Pct: 12}, RAM: Usage{Known: true, Pct: 61}, Disk: Usage{Known: true, Pct: 55}},
		{Name: "pve-office", Online: true, CPU: Usage{Known: true, Pct: 93, Warn: true}, RAM: Usage{Known: true, Pct: 44}, Disk: Usage{Known: true, Pct: 88, Warn: true}},
		{Name: "pve-dr"},
	}
	s := Summarize(rows)
	if s.CPU != (Stat{Known: true, Avg: 53, Max: 93, MaxHost: "pve-office", MaxWarn: true}) {
		t.Errorf("cpu = %+v", s.CPU)
	}
	if s.RAM != (Stat{Known: true, Avg: 53, Max: 61, MaxHost: "pve-01"}) {
		t.Errorf("ram = %+v", s.RAM)
	}
	if s.Disk != (Stat{Known: true, Avg: 72, Max: 88, MaxHost: "pve-office", MaxWarn: true}) {
		t.Errorf("disk = %+v", s.Disk)
	}
	if s.Warnings != 1 || s.WarnHosts != "pve-office" {
		t.Errorf("a host over two limits counts once: %d %q", s.Warnings, s.WarnHosts)
	}
}

func TestSummarizeWithoutDataAndWithManyWarnings(t *testing.T) {
	s := Summarize([]HostRow{{Name: "a"}, {Name: "b"}})
	if s.CPU.Known || s.RAM.Known || s.Disk.Known || s.Warnings != 0 || s.WarnHosts != "" {
		t.Errorf("hosts without metrics give no averages and no warnings: %+v", s)
	}
	var rows []HostRow
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		rows = append(rows, HostRow{Name: n, Online: true, CPU: Usage{Known: true, Pct: 95, Warn: true}})
	}
	s = Summarize(rows)
	if s.Warnings != 5 || s.WarnHosts != "a, b, c +2 more" {
		t.Errorf("warning list must name three hosts and count the rest: %d %q", s.Warnings, s.WarnHosts)
	}
}

func TestWarnThresholds(t *testing.T) {
	h := onlineHost()
	h.Metrics.CPUPct = f(89.6) // rounds to 90
	h.Metrics.Mem = &protocol.Mem{Total: 1000, Used: 894}
	h.Metrics.Disks = []protocol.Disk{{Mount: "/", Total: 1000, Used: 850}}
	r := BuildRow(h, now)
	if !r.CPU.Warn || r.RAM.Warn || !r.Disk.Warn {
		t.Errorf("want CPU warn at 90, RAM no warn at 89, disk warn at 85: %+v %+v %+v", r.CPU, r.RAM, r.Disk)
	}
}

func TestBuildRowOfflineHidesMetricsButKeepsIP(t *testing.T) {
	h := onlineHost()
	h.LastSeen = now.Add(-3 * time.Minute)
	r := BuildRow(h, now)
	if r.Online || r.CPU.Known || r.RAM.Known || r.Disk.Known || r.Uptime != "–" {
		t.Errorf("offline row must not show stale metrics: %+v", r)
	}
	if r.IP != "192.168.10.10" || r.LastSeenUnix == 0 {
		t.Errorf("offline row keeps IP and last report time: %+v", r)
	}
}

func TestBuildRowNeverReported(t *testing.T) {
	r := BuildRow(store.Host{ID: 2, Name: "new"}, now)
	if r.Online || r.LastSeenUnix != 0 || r.IP != "–" || r.Uptime != "–" || r.CPU.Known {
		t.Errorf("row = %+v", r)
	}
}

func TestIPFallbackWithoutDefaultRoute(t *testing.T) {
	h := onlineHost()
	h.Inventory.Interfaces[1].DefaultRoute = false
	if r := BuildRow(h, now); r.IP != "172.17.0.1" {
		t.Errorf("no default route: IP = %q, want the first IPv4 found", r.IP)
	}
	h.Inventory.Interfaces = []protocol.Interface{{Name: "eth0", IPv4: []string{}, IPv6: []string{"2001:db8::1"}}}
	if r := BuildRow(h, now); r.IP != "2001:db8::1" {
		t.Errorf("IPv6-only host: IP = %q", r.IP)
	}
	h.Inventory.Interfaces = nil
	if r := BuildRow(h, now); r.IP != "–" {
		t.Errorf("no addresses: IP = %q", r.IP)
	}
}

func TestUptimeFormat(t *testing.T) {
	for sec, want := range map[uint64]string{59: "0m", 720: "12m", 18720: "5h 12m", 3639600: "42d 3h"} {
		if got := fmtUptime(sec); got != want {
			t.Errorf("fmtUptime(%d) = %q, want %q", sec, got, want)
		}
	}
}

func TestFailedServicesCountAsWarnings(t *testing.T) {
	h := onlineHost()
	h.Metrics.Services = []protocol.Service{{Name: "nginx.service", Status: "running"}, {Name: "db.service", Status: "failed"}, {Name: "x.service", Status: "failed"}}
	r := BuildRow(h, now)
	if r.FailedServices != 2 {
		t.Fatalf("failed services = %d, want 2", r.FailedServices)
	}
	quiet := HostRow{Name: "quiet", Online: true, FailedServices: 1}
	if s := Summarize([]HostRow{quiet}); s.Warnings != 1 || s.WarnHosts != "quiet" {
		t.Errorf("a host with a failed service belongs in Warnings: %+v", s)
	}
	h.LastSeen = now.Add(-3 * time.Minute)
	if r := BuildRow(h, now); r.FailedServices != 0 {
		t.Error("an offline host's last known services must not raise a warning")
	}
	d := BuildDetail(onlineHostWithServices(), now)
	if len(d.Services) != 2 || d.Services[1] != (ServiceRow{Name: "db.service", Status: "failed"}) {
		t.Errorf("detail services = %+v", d.Services)
	}
}

func onlineHostWithServices() store.Host {
	h := onlineHost()
	h.Metrics.Services = []protocol.Service{{Name: "nginx.service", Status: "running"}, {Name: "db.service", Status: "failed"}}
	return h
}

func pveHost() store.Host {
	h := onlineHost()
	quorate := true
	h.Metrics.Proxmox = &protocol.Proxmox{Detected: true, Configured: true, Version: "8.2.4", Node: "pve-01", Cluster: "lab", Quorate: &quorate,
		Guests: []protocol.Guest{
			{ID: 101, Type: "lxc", Name: "nginx", Status: "running", CPUs: 2, CPUPct: 1, MemUsed: 128 << 20, MemMax: 512 << 20, DiskUsed: 1 << 30, DiskMax: 8 << 30, UptimeS: 3600, IPs: []string{"192.168.10.21"}},
			{ID: 110, Type: "qemu", Name: "app-server", Status: "running", CPUs: 4, CPUPct: 12.5, MemUsed: 2 << 30, MemMax: 8 << 30, DiskMax: 50 << 30, UptimeS: 86400},
			{ID: 115, Type: "lxc", Name: "ocrmypdf", Status: "stopped", CPUs: 1, MemMax: 512 << 20, DiskMax: 8 << 30},
		},
		Storage: []protocol.Storage{{Name: "local", Type: "dir", Active: true, Total: 100 << 30, Used: 40 << 30}, {Name: "nas", Type: "nfs"}},
	}
	return h
}

func TestProxmoxInRowAndDetail(t *testing.T) {
	r := BuildRow(pveHost(), now)
	if r.Guests != "2 / 3" || r.GuestKey != "3" || r.InactiveStorage != 1 {
		t.Errorf("row: guests %q key %q inactive storage %d", r.Guests, r.GuestKey, r.InactiveStorage)
	}
	if s := Summarize([]HostRow{{Name: "pve-01", Online: true, InactiveStorage: 1}}); s.Warnings != 1 {
		t.Error("inactive storage belongs in Warnings")
	}
	if plain := BuildRow(onlineHost(), now); plain.Guests != "" || plain.GuestKey != "" {
		t.Errorf("a host without Proxmox shows no guest count: %q %q", plain.Guests, plain.GuestKey)
	}
	d := BuildDetail(pveHost(), now)
	if d.PVE == nil || d.PVE.Summary != "Proxmox VE 8.2.4 · node pve-01 · cluster lab (quorate)" || d.PVE.Note != "" {
		t.Fatalf("proxmox line = %+v", d.PVE)
	}
	// The bars carry the percentage; the tooltip carries the amounts. A stopped
	// guest and a VM disk (Proxmox reports no usage) have no bar, only the size.
	want := []GuestRow{
		{ID: 101, Name: "nginx", Type: "LXC", Status: "running",
			CPU:    Usage{Known: true, Pct: 1, Tip: "1% of 2 CPUs"},
			Mem:    Usage{Known: true, Pct: 25, Tip: "128.0 MiB / 512.0 MiB"},
			Disk:   Usage{Known: true, Pct: 13, Tip: "1.0 GiB / 8.0 GiB"},
			Uptime: "1h 0m", IP: "192.168.10.21"},
		{ID: 110, Name: "app-server", Type: "VM", Status: "running",
			CPU:    Usage{Known: true, Pct: 13, Tip: "12.5% of 4 CPUs"},
			Mem:    Usage{Known: true, Pct: 25, Tip: "2.0 GiB / 8.0 GiB"},
			Disk:   Usage{Tip: "50.0 GiB allocated, usage not reported for VMs"},
			Uptime: "1d 0h", IP: "Unknown"},
		{ID: 115, Name: "ocrmypdf", Type: "LXC", Status: "stopped",
			CPU:    Usage{Tip: "1 CPU, stopped"},
			Mem:    Usage{Tip: "512.0 MiB allocated, stopped"},
			Disk:   Usage{Tip: "8.0 GiB allocated, stopped"},
			Uptime: "–", IP: "–"},
	}
	for i, w := range want {
		if d.PVE.Guests[i] != w {
			t.Errorf("guest %d = %+v\nwant      %+v", i, d.PVE.Guests[i], w)
		}
	}
	busy := pveHost()
	busy.Metrics.Proxmox.Guests = []protocol.Guest{{ID: 1, Type: "lxc", Status: "running", CPUs: 1, CPUPct: 95, MemUsed: 95, MemMax: 100, DiskUsed: 95, DiskMax: 100},
		{ID: 2, Type: "lxc", Status: "running", CPUs: 1}}
	g := BuildDetail(busy, now).PVE.Guests
	if !g[0].CPU.Warn || !g[0].Mem.Warn || !g[0].Disk.Warn {
		t.Errorf("a guest over the limits must be coloured as a warning: %+v", g[0])
	}
	if g[1].Mem.Known || g[1].Disk.Known {
		t.Errorf("a guest without sizes must have no bar, not a division by zero: %+v", g[1])
	}
	if len(d.PVE.Storage) != 2 || d.PVE.Storage[0].Size != "40.0 GiB / 100.0 GiB" || d.PVE.Storage[0].Usage.Pct != 40 || !d.PVE.Storage[0].Active || d.PVE.Storage[1].Active || d.PVE.Storage[1].Usage.Known {
		t.Errorf("storage = %+v", d.PVE.Storage)
	}
	h := onlineHost()
	h.Metrics.Proxmox = &protocol.Proxmox{Detected: true}
	if d := BuildDetail(h, now); d.PVE == nil || !strings.Contains(d.PVE.Note, "API token") || !strings.Contains(d.PVE.Note, "Replace credential") {
		t.Errorf("detected without a token must say what to do: %+v", d.PVE)
	}
	h.Metrics.Proxmox = &protocol.Proxmox{Detected: true, Configured: true, Error: "pve: /version answered HTTP 401"}
	if d := BuildDetail(h, now); d.PVE == nil || !strings.Contains(d.PVE.Note, "401") {
		t.Errorf("an API error must be shown: %+v", d.PVE)
	}
}

func TestFmtBytes(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 8 << 30: "8.0 GiB", 3 << 39: "1.5 TiB"} {
		if got := fmtBytes(n); got != want {
			t.Errorf("fmtBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestOnlineBoundary(t *testing.T) {
	if !Online(now.Add(-45*time.Second), now) {
		t.Error("45 seconds since the last report is still online")
	}
	if Online(now.Add(-46*time.Second), now) || Online(time.Time{}, now) {
		t.Error("more than 45 seconds, or never, is offline")
	}
}

func TestDisabledHostIsNeitherOnlineNorOffline(t *testing.T) {
	h := onlineHost()
	h.Disabled = true
	row := BuildRow(h, now)
	if row.Online || !row.Disabled || row.Status() != "disabled" || row.StatusLabel() != "Disabled" || row.CPU.Known {
		t.Errorf("row of a disabled host = %+v", row)
	}
	s := Summarize([]HostRow{row, {Online: true}, {}})
	if s.Hosts != 3 || s.Online != 1 || s.Offline != 1 || s.Disabled != 1 {
		t.Errorf("summary = %+v", s)
	}
	if on := BuildRow(onlineHost(), now); on.Status() != "online" || on.StatusLabel() != "Online" {
		t.Errorf("online row status = %q %q", on.Status(), on.StatusLabel())
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize([]HostRow{{Online: true}, {Online: false}, {Online: true}})
	if s != (Summary{Hosts: 3, Online: 2, Offline: 1}) {
		t.Errorf("summary = %+v", s)
	}
}
