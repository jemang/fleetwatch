package collect

import (
	"crypto/sha256"
	"encoding/json"
	"sync/atomic"
	"time"

	"fleetwatch/internal/protocol"
)

const (
	SlowEvery      = 30 * time.Second
	InventoryEvery = 5 * time.Minute
)

type result[T any] struct {
	v   T
	err error
}

// guard runs a collector with a timeout and refuses to start it again while a
// previous run is still blocked, so a hung collector costs one goroutine.
type guard[T any] struct{ busy atomic.Bool }

func (g *guard[T]) run(timeout time.Duration, fn func() (T, error)) (T, bool) {
	var zero T
	if !g.busy.CompareAndSwap(false, true) {
		return zero, false
	}
	ch := make(chan result[T], 1)
	go func() {
		v, err := fn()
		// Free before sending: the caller may run again as soon as it reads.
		g.busy.Store(false)
		ch <- result[T]{v, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.v, r.err == nil
	case <-timer.C:
		return zero, false
	}
}

type fast struct {
	cpu    *CPUTimes
	load   []float64
	uptime uint64
	mem    *protocol.Mem
	swap   *protocol.Swap
}

// Sampler builds one full metrics snapshot per call. It is not safe for
// concurrent use.
type Sampler struct {
	Root    string
	Statfs  StatfsFunc
	Addrs   AddrsFunc
	Now     func() time.Time
	Timeout time.Duration
	// Services are the systemd units to report; ListServices asks systemd.
	Services     []string
	ListServices func(names []string) ([]protocol.Service, error)
	// Proxmox returns the latest Proxmox snapshot without waiting, or nil.
	Proxmox func() *protocol.Proxmox

	prevCPU  *CPUTimes
	services []protocol.Service
	slowAt   time.Time
	disks    []protocol.Disk
	net      []protocol.NetIf

	invAt    time.Time
	invHash  [sha256.Size]byte
	invKnown bool
	resend   bool

	fastG guard[fast]
	diskG guard[[]protocol.Disk]
	netG  guard[[]protocol.NetIf]
	svcG  guard[[]protocol.Service]
	invG  guard[*protocol.Inventory]
}

func (s *Sampler) Sample() (protocol.Metrics, *protocol.Inventory) {
	now := s.Now()
	root, statfs := s.Root, s.Statfs
	var m protocol.Metrics

	if f, ok := s.fastG.run(s.Timeout, func() (fast, error) { return readFast(root), nil }); ok {
		m.Load, m.UptimeS, m.Mem, m.Swap = f.load, f.uptime, f.mem, f.swap
		if f.cpu != nil {
			if s.prevCPU != nil {
				if pct, ok := CPUPercent(*s.prevCPU, *f.cpu); ok {
					m.CPUPct = &pct
				}
			}
			s.prevCPU = f.cpu
		}
	}

	if s.slowAt.IsZero() || now.Sub(s.slowAt) >= SlowEvery {
		s.slowAt = now
		s.disks, _ = s.diskG.run(s.Timeout, func() ([]protocol.Disk, error) { return ReadDisks(root, statfs) })
		s.net, _ = s.netG.run(s.Timeout, func() ([]protocol.NetIf, error) { return ReadNet(root, s.Addrs) })
		if names, list := s.Services, s.ListServices; len(names) > 0 {
			svc, ok := []protocol.Service(nil), false
			if list != nil {
				svc, ok = s.svcG.run(s.Timeout, func() ([]protocol.Service, error) { return list(names) })
			}
			if !ok { // systemd could not be asked: say so per service instead of dropping them
				svc = make([]protocol.Service, len(names))
				for i, n := range names {
					svc[i] = protocol.Service{Name: n, Status: "unknown"}
				}
			}
			s.services = svc
		}
	}
	m.Disks, m.Net, m.Services = s.disks, s.net, s.services
	if s.Proxmox != nil {
		m.Proxmox = s.Proxmox()
	}

	return m, s.inventory(now)
}

func readFast(root string) fast {
	var f fast
	if c, err := ReadCPUTimes(root); err == nil {
		f.cpu = &c
	}
	if l, err := ReadLoad(root); err == nil {
		f.load = l
	}
	if u, err := ReadUptime(root); err == nil {
		f.uptime = u
	}
	if m, sw, err := ReadMem(root); err == nil {
		f.mem, f.swap = &m, &sw
	}
	return f
}

func (s *Sampler) ResendInventory() { s.resend = true }

func (s *Sampler) inventory(now time.Time) *protocol.Inventory {
	due := s.invAt.IsZero() || s.resend || now.Sub(s.invAt) >= InventoryEvery
	if !due {
		return nil
	}
	root, addrs := s.Root, s.Addrs
	inv, ok := s.invG.run(s.Timeout, func() (*protocol.Inventory, error) {
		ifs, err := ReadInterfaces(root, addrs)
		if err != nil {
			return nil, err
		}
		h := ReadHostInfo(root)
		return &protocol.Inventory{Hostname: h.Hostname, OS: h.OS, Kernel: h.Kernel, CPUModel: h.CPUModel, Cores: h.Cores, Interfaces: ifs}, nil
	})
	if !ok {
		return nil // invAt is not advanced, so the next sample tries again
	}
	s.invAt = now
	b, _ := json.Marshal(inv)
	h := sha256.Sum256(b)
	if s.invKnown && !s.resend && h == s.invHash {
		return nil
	}
	s.invHash, s.invKnown, s.resend = h, true, false
	return inv
}
