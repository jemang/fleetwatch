package collect

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestReadNetSkipsLoopbackAndNonInterfaces(t *testing.T) {
	root := fullTree(t)
	writeInto(t, root, "sys/class/net/lo/operstate", "unknown\n")
	writeInto(t, root, "sys/class/net/lo/statistics/rx_bytes", "9\n")
	writeInto(t, root, "sys/class/net/bonding_masters", "\n")
	got, err := ReadNet(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "eth0" || got[0].State != "up" || got[0].RxBytes != 1000 || got[0].TxBytes != 2000 {
		t.Errorf("net = %+v", got)
	}
}

func TestDefaultRouteIfacePicksLowestMetric(t *testing.T) {
	root := tree(t, map[string]string{"proc/net/route": routeHeader +
		"wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"})
	if got := DefaultRouteIface(root); got != "eth0" {
		t.Errorf("default route interface = %q, want eth0", got)
	}
	if got := DefaultRouteIface(t.TempDir()); got != "" {
		t.Errorf("missing route file must give empty name, got %q", got)
	}
}

func TestReadInterfaces(t *testing.T) {
	addrs := func() (map[string][]netip.Addr, error) {
		return map[string][]netip.Addr{
			"eth0":       {netip.MustParseAddr("192.168.10.10"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8::10")},
			"tailscale0": {netip.MustParseAddr("100.64.0.5")},
			"dummy0":     nil,
		}, nil
	}
	got, err := ReadInterfaces(fullTree(t), addrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "dummy0" || got[1].Name != "eth0" || got[2].Name != "tailscale0" {
		t.Fatalf("interfaces must be sorted by name: %+v", got)
	}
	eth := got[1]
	if !eth.DefaultRoute || !reflect.DeepEqual(eth.IPv4, []string{"192.168.10.10"}) || !reflect.DeepEqual(eth.IPv6, []string{"2001:db8::10"}) {
		t.Errorf("eth0 = %+v (link-local addresses must be left out)", eth)
	}
	if got[0].IPv4 == nil || got[0].IPv6 == nil {
		t.Error("address lists must be empty slices, not nil, so JSON shows []")
	}
	if got[2].DefaultRoute {
		t.Error("only the default-route interface is flagged")
	}
}
