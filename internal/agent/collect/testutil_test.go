package collect

import (
	"os"
	"path/filepath"
	"testing"
)

const routeHeader = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		writeInto(t, root, name, content)
	}
	return root
}

func writeInto(t *testing.T, root, name, content string) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fullTree(t *testing.T) string {
	t.Helper()
	return tree(t, map[string]string{
		"proc/stat":                 "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 100 0 100 700 100 0 0 0 0 0\n",
		"proc/meminfo":              "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    400 kB\nSwapTotal:       200 kB\nSwapFree:        150 kB\n",
		"proc/loadavg":              "0.42 0.31 0.20 1/123 4567\n",
		"proc/uptime":               "3628800.55 100.00\n",
		"proc/mounts":               "/dev/sda1 / ext4 rw 0 0\n",
		"proc/net/route":            routeHeader + "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
		"proc/sys/kernel/hostname":  "web-01\n",
		"proc/sys/kernel/osrelease": "6.1.0-18-amd64\n",
		"proc/cpuinfo":              "processor\t: 0\nmodel name\t: Test CPU\n\nprocessor\t: 1\nmodel name\t: Test CPU\n",
		"etc/os-release":            "NAME=\"Debian\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n",

		"sys/class/net/eth0/operstate":           "up\n",
		"sys/class/net/eth0/statistics/rx_bytes": "1000\n",
		"sys/class/net/eth0/statistics/tx_bytes": "2000\n",
	})
}
