// Package collect reads host metrics from /proc and /sys.
package collect

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fleetwatch/internal/protocol"
)

type CPUTimes struct{ Idle, Total uint64 }

func ReadCPUTimes(root string) (CPUTimes, error) {
	b, err := os.ReadFile(filepath.Join(root, "/proc/stat"))
	if err != nil {
		return CPUTimes{}, err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return CPUTimes{}, fmt.Errorf("collect: unexpected first line of /proc/stat: %q", line)
	}
	var t CPUTimes
	for i, s := range f[1:] {
		if i >= 8 {
			break // guest and guest_nice are already counted in user and nice
		}
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return CPUTimes{}, fmt.Errorf("collect: /proc/stat field %d: %w", i+1, err)
		}
		t.Total += v
		if i == 3 || i == 4 { // idle, iowait
			t.Idle += v
		}
	}
	return t, nil
}

// CPUPercent returns busy time between two samples, rounded to one decimal.
func CPUPercent(prev, cur CPUTimes) (float64, bool) {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0, false
	}
	total := float64(cur.Total - prev.Total)
	idle := float64(cur.Idle - prev.Idle)
	if idle > total {
		return 0, false
	}
	return math.Round((total-idle)/total*1000) / 10, true
}

func ReadMem(root string) (protocol.Mem, protocol.Swap, error) {
	b, err := os.ReadFile(filepath.Join(root, "/proc/meminfo"))
	if err != nil {
		return protocol.Mem{}, protocol.Swap{}, err
	}
	vals := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		vals[key] = v * 1024
	}
	total, okT := vals["MemTotal"]
	avail, okA := vals["MemAvailable"]
	if !okT || !okA {
		return protocol.Mem{}, protocol.Swap{}, fmt.Errorf("collect: MemTotal or MemAvailable missing in /proc/meminfo")
	}
	mem := protocol.Mem{Total: total, Available: avail}
	if total > avail {
		mem.Used = total - avail
	}
	swap := protocol.Swap{Total: vals["SwapTotal"]}
	if swap.Total > vals["SwapFree"] {
		swap.Used = swap.Total - vals["SwapFree"]
	}
	return mem, swap, nil
}

func ReadLoad(root string) ([]float64, error) {
	b, err := os.ReadFile(filepath.Join(root, "/proc/loadavg"))
	if err != nil {
		return nil, err
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return nil, fmt.Errorf("collect: unexpected /proc/loadavg: %q", b)
	}
	out := make([]float64, 3)
	for i := range out {
		if out[i], err = strconv.ParseFloat(f[i], 64); err != nil {
			return nil, fmt.Errorf("collect: /proc/loadavg field %d: %w", i, err)
		}
	}
	return out, nil
}

func ReadUptime(root string) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(root, "/proc/uptime"))
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, fmt.Errorf("collect: empty /proc/uptime")
	}
	sec, err := strconv.ParseFloat(f[0], 64)
	if err != nil || sec < 0 {
		return 0, fmt.Errorf("collect: unexpected /proc/uptime: %q", b)
	}
	return uint64(sec), nil
}

type HostInfo struct {
	Hostname, OS, Kernel, CPUModel string
	Cores                          int
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ReadHostInfo(root string) HostInfo {
	h := HostInfo{
		Hostname: readTrim(filepath.Join(root, "/proc/sys/kernel/hostname")),
		Kernel:   readTrim(filepath.Join(root, "/proc/sys/kernel/osrelease")),
	}
	for _, line := range strings.Split(readTrim(filepath.Join(root, "/etc/os-release")), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			h.OS = strings.Trim(v, `"`)
		}
	}
	board := ""
	for _, line := range strings.Split(readTrim(filepath.Join(root, "/proc/cpuinfo")), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "processor":
			h.Cores++
		case "model name":
			if h.CPUModel == "" {
				h.CPUModel = strings.TrimSpace(val)
			}
		case "Model": // arm64 boards: there is no "model name" line
			board = strings.TrimSpace(val)
		}
	}
	if h.CPUModel == "" {
		h.CPUModel = board
	}
	return h
}
