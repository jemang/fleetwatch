package collect

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"fleetwatch/internal/protocol"
)

func readUint(path string) uint64 {
	v, _ := strconv.ParseUint(readTrim(path), 10, 64)
	return v
}

func ReadNet(root string) ([]protocol.NetIf, error) {
	dir := filepath.Join(root, "/sys/class/net")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []protocol.NetIf
	for _, e := range entries {
		name := e.Name()
		state := readTrim(filepath.Join(dir, name, "operstate"))
		if name == "lo" || state == "" {
			continue
		}
		out = append(out, protocol.NetIf{
			Name:    name,
			State:   state,
			RxBytes: readUint(filepath.Join(dir, name, "statistics/rx_bytes")),
			TxBytes: readUint(filepath.Join(dir, name, "statistics/tx_bytes")),
		})
	}
	return out, nil
}

type AddrsFunc func() (map[string][]netip.Addr, error)

func SystemAddrs() (map[string][]netip.Addr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := map[string][]netip.Addr{}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		out[ifc.Name] = nil
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
				out[ifc.Name] = append(out[ifc.Name], ip.Unmap())
			}
		}
	}
	return out, nil
}

// DefaultRouteIface returns the interface of the IPv4 default route with the
// lowest metric, or "" when there is none.
func DefaultRouteIface(root string) string {
	lines := strings.Split(readTrim(filepath.Join(root, "/proc/net/route")), "\n")
	best, bestMetric := "", uint64(0)
	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		metric, _ := strconv.ParseUint(f[6], 10, 64)
		if best == "" || metric < bestMetric {
			best, bestMetric = f[0], metric
		}
	}
	return best
}

func ReadInterfaces(root string, addrs AddrsFunc) ([]protocol.Interface, error) {
	m, err := addrs()
	if err != nil {
		return nil, err
	}
	def := DefaultRouteIface(root)
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]protocol.Interface, 0, len(names))
	for _, name := range names {
		ifc := protocol.Interface{Name: name, DefaultRoute: name == def, IPv4: []string{}, IPv6: []string{}}
		for _, a := range m[name] {
			switch {
			case a.IsLinkLocalUnicast():
			case a.Is4():
				ifc.IPv4 = append(ifc.IPv4, a.String())
			default:
				ifc.IPv6 = append(ifc.IPv6, a.String())
			}
		}
		out = append(out, ifc)
	}
	return out, nil
}
