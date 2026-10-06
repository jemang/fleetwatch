package web

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

func fmtBytes(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	v, units := float64(n)/1024, []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

type DiskRow struct {
	Mount, FS, Size string
	Usage           Usage
}

type NetRow struct{ Name, State, Addrs, Rx, Tx string }

type ServiceRow struct{ Name, Status string }

type GuestRow struct {
	ID                             int
	Name, Type, Status, Uptime, IP string
	CPU, Mem, Disk                 Usage
}

type StorageRow struct {
	Name, Type, Size string
	Active           bool
	Usage            Usage
}

// PVEView is the Proxmox part of the host page. Note explains why there is no
// guest list (no token, or an API error).
type PVEView struct {
	Summary, Note string
	Guests        []GuestRow
	Storage       []StorageRow
}

func cpuCount(n int) string {
	if n == 1 {
		return "1 CPU"
	}
	return strconv.Itoa(n) + " CPUs"
}

func buildPVE(p *protocol.Proxmox) *PVEView {
	if p == nil || !p.Detected {
		return nil
	}
	v := &PVEView{Summary: "Proxmox VE"}
	switch {
	case !p.Configured:
		v.Note = "Proxmox was detected on this host, but the agent has no API token. To see guests and storage, use Replace credential on this page and run the install command it shows: it creates a read-only token."
		return v
	case p.Error != "":
		v.Note = "The Proxmox API could not be read: " + p.Error
		return v
	}
	v.Summary += " " + p.Version + " · node " + p.Node
	if p.Cluster != "" {
		v.Summary += " · cluster " + p.Cluster
		if p.Quorate != nil {
			if *p.Quorate {
				v.Summary += " (quorate)"
			} else {
				v.Summary += " (NO QUORUM)"
			}
		}
	}
	for _, g := range p.Guests {
		row := GuestRow{ID: g.ID, Name: g.Name, Type: "VM", Status: g.Status, Uptime: "–", IP: "–"}
		if g.Type == "lxc" {
			row.Type = "LXC"
		}
		running := g.Status == "running"
		row.CPU.Tip = cpuCount(g.CPUs) + ", stopped"
		row.Mem.Tip = fmtBytes(g.MemMax) + " allocated, stopped"
		row.Disk.Tip = fmtBytes(g.DiskMax) + " allocated, stopped"
		if running {
			row.CPU = usage(g.CPUPct, warnCPU, strconv.FormatFloat(g.CPUPct, 'f', -1, 64)+"% of "+cpuCount(g.CPUs))
			if g.MemMax > 0 {
				row.Mem = usage(ratio(g.MemUsed, g.MemMax), warnRAM, fmtBytes(g.MemUsed)+" / "+fmtBytes(g.MemMax))
			}
			row.Disk.Tip = fmtBytes(g.DiskMax) + " allocated, usage not reported for VMs"
			if g.DiskUsed > 0 && g.DiskMax > 0 { // Proxmox reports no disk usage for VMs
				row.Disk = usage(ratio(g.DiskUsed, g.DiskMax), warnDisk, fmtBytes(g.DiskUsed)+" / "+fmtBytes(g.DiskMax))
			}
			if g.UptimeS > 0 {
				row.Uptime = fmtUptime(g.UptimeS)
			}
			row.IP = "Unknown" // shown instead of a guess
			if len(g.IPs) > 0 {
				row.IP = strings.Join(g.IPs, ", ")
			}
		}
		v.Guests = append(v.Guests, row)
	}
	for _, s := range p.Storage {
		row := StorageRow{Name: s.Name, Type: s.Type, Active: s.Active, Size: "–"}
		if s.Total > 0 {
			row.Size = fmtBytes(s.Used) + " / " + fmtBytes(s.Total)
			row.Usage = usage(ratio(s.Used, s.Total), warnDisk, "")
		}
		v.Storage = append(v.Storage, row)
	}
	return v
}

// HostDetail is everything the detail page shows about one host. Values under
// Row follow the list's rule: an offline host shows no current usage.
type HostDetail struct {
	Row                    HostRow
	OS, Kernel, CPUModel   string
	Cores                  int
	MemTotal, AgentVersion string
	Mem, Swap, Load        string
	SwapUsage              Usage
	Disks                  []DiskRow
	Nets                   []NetRow
	Services               []ServiceRow
	PVE                    *PVEView
	Stale                  bool // host is offline: tables show the last report
}

func BuildDetail(h store.Host, now time.Time) HostDetail {
	d := HostDetail{Row: BuildRow(h, now), AgentVersion: h.AgentVersion, Mem: "–", Swap: "–", Load: "–", MemTotal: "–"}
	d.Stale = !d.Row.Online
	addrs := map[string]string{}
	if inv := h.Inventory; inv != nil {
		d.OS, d.Kernel, d.CPUModel, d.Cores = inv.OS, inv.Kernel, inv.CPUModel, inv.Cores
		for _, i := range inv.Interfaces {
			addrs[i.Name] = strings.Join(append(append([]string{}, i.IPv4...), i.IPv6...), ", ")
		}
	}
	m := h.Metrics
	if m == nil {
		return d
	}
	if m.Mem != nil {
		d.MemTotal = fmtBytes(m.Mem.Total)
		d.Mem = fmtBytes(m.Mem.Used) + " / " + fmtBytes(m.Mem.Total)
	}
	if m.Swap != nil && m.Swap.Total > 0 {
		d.Swap = fmtBytes(m.Swap.Used) + " / " + fmtBytes(m.Swap.Total)
		if d.Row.Online {
			d.SwapUsage = usage(ratio(m.Swap.Used, m.Swap.Total), 101, "")
		}
	}
	if len(m.Load) == 3 {
		d.Load = fmt.Sprintf("%.2f %.2f %.2f", m.Load[0], m.Load[1], m.Load[2])
	}
	for _, disk := range m.Disks {
		if disk.Total == 0 {
			continue
		}
		d.Disks = append(d.Disks, DiskRow{Mount: disk.Mount, FS: disk.FS,
			Size:  fmtBytes(disk.Used) + " / " + fmtBytes(disk.Total),
			Usage: usage(ratio(disk.Used, disk.Total), warnDisk, "")})
	}
	for _, svc := range m.Services {
		d.Services = append(d.Services, ServiceRow{Name: svc.Name, Status: svc.Status})
	}
	d.PVE = buildPVE(m.Proxmox)
	for _, n := range m.Net {
		d.Nets = append(d.Nets, NetRow{Name: n.Name, State: n.State, Addrs: addrs[n.Name], Rx: fmtBytes(n.RxBytes), Tx: fmtBytes(n.TxBytes)})
	}
	return d
}

type chartRange struct {
	Key, Label, Fmt string
	Span            time.Duration
}

// Fmt tells the browser how to print the time axis: hours and minutes, day
// and time, or month and day.
var chartRanges = []chartRange{
	{"1h", "1 hour", "hm", time.Hour},
	{"24h", "24 hours", "hm", 24 * time.Hour},
	{"7d", "7 days", "dhm", 7 * 24 * time.Hour},
	{"30d", "30 days", "md", 30 * 24 * time.Hour},
}

const chartMaxPoints = 240

type rangeTab struct {
	Key, Label string
	Active     bool
}

type chartsData struct {
	HostID   int64
	Tabs     []rangeTab
	Range    string
	Fmt      string
	From, To int64
	Charts   []Chart
}

type hostPageData struct {
	chrome
	Detail   HostDetail
	Services []ServiceCard // the services whose related host this is, by name
}

// hostServices lists the services that name this host as their host.
func (w *Web) hostServices(r *http.Request, hostID int64) ([]ServiceCard, error) {
	list, err := w.st.Services(r.Context())
	if err != nil {
		return nil, err
	}
	var out []ServiceCard
	for _, sv := range list {
		if sv.HostID == hostID {
			out = append(out, serviceCard(sv))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

// hostServicesFragment is the host page's service list, redrawn on changes.
func (w *Web) hostServicesFragment(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.hostFromPath(rw, r)
	if !ok {
		return
	}
	list, err := w.hostServices(r, h.ID)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "hostservices", list)
}

func (w *Web) hostFromPath(rw http.ResponseWriter, r *http.Request) (store.Host, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var h store.Host
		if h, err = w.st.Host(r.Context(), id); err == nil {
			return h, true
		}
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusNotFound)
	fmt.Fprintln(rw, "No such host.")
	return store.Host{}, false
}

func (w *Web) hostPage(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.hostFromPath(rw, r)
	if !ok {
		return
	}
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	services, err := w.hostServices(r, h.ID)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "host", hostPageData{chrome: w.chrome(r, "hosts", rows), Detail: BuildDetail(h, w.now()), Services: services})
}

func (w *Web) hostCharts(rw http.ResponseWriter, r *http.Request) {
	h, ok := w.hostFromPath(rw, r)
	if !ok {
		return
	}
	chosen := chartRanges[0]
	for _, cr := range chartRanges {
		if cr.Key == r.URL.Query().Get("range") {
			chosen = cr
		}
	}
	to := w.now()
	from := to.Add(-chosen.Span)
	pts, step, err := w.st.History(r.Context(), h.ID, from, to, chartMaxPoints)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	data := chartsData{HostID: h.ID, Range: chosen.Key, Fmt: chosen.Fmt, From: from.Unix(), To: to.Unix()}
	for _, cr := range chartRanges {
		data.Tabs = append(data.Tabs, rangeTab{cr.Key, cr.Label, cr.Key == chosen.Key})
	}
	data.Charts = []Chart{
		BuildChart("CPU", pts, func(p store.MetricPoint) *float64 { return p.CPU }, from, to, step, warnCPU),
		BuildChart("Memory", pts, func(p store.MetricPoint) *float64 { return p.Mem }, from, to, step, warnRAM),
		BuildChart("Disk", pts, func(p store.MetricPoint) *float64 { return p.Disk }, from, to, step, warnDisk),
	}
	w.render(rw, http.StatusOK, "charts", data)
}
