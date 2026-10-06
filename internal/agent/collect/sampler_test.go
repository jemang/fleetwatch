package collect

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"fleetwatch/internal/protocol"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestSampler(t *testing.T) (*Sampler, *fakeClock, *atomic.Int32, *string) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(1_790_000_000, 0)}
	var statfsCalls atomic.Int32
	ip := "192.168.10.10"
	s := &Sampler{
		Root: fullTree(t),
		Statfs: func(string) (uint64, uint64, error) {
			statfsCalls.Add(1)
			return 1000, 400, nil
		},
		Addrs: func() (map[string][]netip.Addr, error) {
			return map[string][]netip.Addr{"eth0": {netip.MustParseAddr(ip)}}, nil
		},
		Now:     clock.now,
		Timeout: time.Second,
	}
	return s, clock, &statfsCalls, &ip
}

func TestSampleFirstTickHasNoCPUButHasInventory(t *testing.T) {
	s, _, _, _ := newTestSampler(t)
	m, inv := s.Sample()
	if m.CPUPct != nil {
		t.Error("first sample has no CPU delta, cpu_pct must be absent")
	}
	if m.Mem == nil || m.Swap == nil || len(m.Load) != 3 || m.UptimeS != 3628800 {
		t.Errorf("fast metrics missing: %+v", m)
	}
	if len(m.Disks) != 1 || len(m.Net) != 1 {
		t.Errorf("disk and network must be in the first sample: %+v", m)
	}
	if inv == nil || inv.Hostname != "web-01" || inv.Cores != 2 || !inv.Interfaces[0].DefaultRoute {
		t.Errorf("inventory = %+v", inv)
	}
}

func TestSampleCadence(t *testing.T) {
	s, clock, statfsCalls, _ := newTestSampler(t)
	s.Sample()
	os.WriteFile(filepath.Join(s.Root, "proc/stat"), []byte("cpu  200 0 200 1300 100 0 0 0 0 0\n"), 0o644)
	clock.advance(15 * time.Second)
	m, inv := s.Sample()
	if m.CPUPct == nil || *m.CPUPct != 25.0 {
		t.Errorf("cpu_pct = %v, want 25.0", m.CPUPct)
	}
	if inv != nil {
		t.Error("unchanged inventory must not be sent again")
	}
	if len(m.Disks) != 1 || statfsCalls.Load() != 1 {
		t.Errorf("disk must come from cache at 15s: disks=%d statfs calls=%d", len(m.Disks), statfsCalls.Load())
	}
	clock.advance(15 * time.Second)
	s.Sample()
	if statfsCalls.Load() != 2 {
		t.Errorf("disk must be collected again at 30s, statfs calls = %d", statfsCalls.Load())
	}
}

func TestInventorySentAgainOnChangeAndOnResend(t *testing.T) {
	s, clock, _, ip := newTestSampler(t)
	s.Sample()
	*ip = "192.168.10.99"
	clock.advance(15 * time.Second)
	if _, inv := s.Sample(); inv != nil {
		t.Error("inventory is rechecked only every 5 minutes")
	}
	clock.advance(InventoryEvery)
	_, inv := s.Sample()
	if inv == nil || inv.Interfaces[0].IPv4[0] != "192.168.10.99" {
		t.Errorf("changed inventory must be sent at the 5 minute recheck: %+v", inv)
	}
	clock.advance(15 * time.Second)
	s.ResendInventory()
	if _, inv := s.Sample(); inv == nil {
		t.Error("ResendInventory must force inventory into the next sample")
	}
	clock.advance(15 * time.Second)
	if _, inv := s.Sample(); inv != nil {
		t.Error("resend applies to one sample only")
	}
}

func TestServicesFollowTheSlowCadenceAndFallBackToUnknown(t *testing.T) {
	s, clock, _, _ := newTestSampler(t)
	if m, _ := s.Sample(); m.Services != nil {
		t.Fatalf("no services configured, none reported: %+v", m.Services)
	}

	s, clock, _, _ = newTestSampler(t)
	var calls atomic.Int32
	fail := false
	s.Services = []string{"nginx.service", "docker.service"}
	s.ListServices = func(names []string) ([]protocol.Service, error) {
		calls.Add(1)
		if fail {
			return nil, errors.New("no system bus")
		}
		return []protocol.Service{{Name: names[0], Status: "running"}, {Name: names[1], Status: "failed"}}, nil
	}
	m, _ := s.Sample()
	if len(m.Services) != 2 || m.Services[1] != (protocol.Service{Name: "docker.service", Status: "failed"}) {
		t.Fatalf("services = %+v", m.Services)
	}
	clock.advance(15 * time.Second)
	if m, _ := s.Sample(); len(m.Services) != 2 || calls.Load() != 1 {
		t.Errorf("at 15s services come from cache: %d services, %d calls", len(m.Services), calls.Load())
	}
	fail = true
	clock.advance(15 * time.Second)
	m, _ = s.Sample()
	if calls.Load() != 2 || len(m.Services) != 2 || m.Services[0] != (protocol.Service{Name: "nginx.service", Status: "unknown"}) || m.Services[1].Status != "unknown" {
		t.Errorf("when systemd cannot be asked every configured service is unknown: %+v (%d calls)", m.Services, calls.Load())
	}
}

func TestProxmoxSnapshotIsAttachedWhenPresent(t *testing.T) {
	s, _, _, _ := newTestSampler(t)
	if m, _ := s.Sample(); m.Proxmox != nil {
		t.Fatal("no Proxmox source, no Proxmox data")
	}
	snapshot := &protocol.Proxmox{Detected: true, Node: "pve-01"}
	s.Proxmox = func() *protocol.Proxmox { return snapshot }
	if m, _ := s.Sample(); m.Proxmox != snapshot {
		t.Errorf("the latest Proxmox snapshot must travel with the metrics: %+v", m.Proxmox)
	}
}

func TestHangingCollectorIsSkippedAndNotStartedTwice(t *testing.T) {
	s, clock, _, _ := newTestSampler(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var calls atomic.Int32
	s.Statfs = func(string) (uint64, uint64, error) {
		calls.Add(1)
		<-release
		return 0, 0, nil
	}
	s.Timeout = 50 * time.Millisecond

	start := time.Now()
	m, _ := s.Sample()
	if time.Since(start) > time.Second {
		t.Fatal("Sample must return after the collector timeout")
	}
	if m.Disks != nil || m.Mem == nil {
		t.Errorf("hung disk collector must omit disks only: %+v", m)
	}
	clock.advance(SlowEvery)
	s.Sample()
	if calls.Load() != 1 {
		t.Errorf("a collector that is still running must not be started again, calls = %d", calls.Load())
	}
}

// A finished collection must not block the next one: the guard is free
// before its result can be read.
func TestGuardIsFreeWhenTheResultArrives(t *testing.T) {
	var g guard[int]
	for i := 0; i < 20000; i++ {
		if _, ok := g.run(time.Second, func() (int, error) { return i, nil }); !ok {
			t.Fatalf("run %d was refused right after the previous one finished", i)
		}
	}
}
