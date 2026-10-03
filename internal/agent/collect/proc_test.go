package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCPUPercentFromTwoSamples(t *testing.T) {
	root := fullTree(t)
	prev, err := ReadCPUTimes(root)
	if err != nil {
		t.Fatal(err)
	}
	if prev.Total != 1000 || prev.Idle != 800 {
		t.Fatalf("prev = %+v, want Total 1000 Idle 800 (idle + iowait)", prev)
	}
	os.WriteFile(filepath.Join(root, "proc/stat"), []byte("cpu  200 0 200 1300 100 0 0 0 0 0\n"), 0o644)
	cur, _ := ReadCPUTimes(root)
	pct, ok := CPUPercent(prev, cur)
	if !ok || pct != 25.0 {
		t.Errorf("CPUPercent = %v, %v; want 25.0, true", pct, ok)
	}
}

func TestCPUPercentRejectsNoProgressAndCounterReset(t *testing.T) {
	a := CPUTimes{Idle: 800, Total: 1000}
	if _, ok := CPUPercent(a, a); ok {
		t.Error("identical samples must not produce a percentage")
	}
	if _, ok := CPUPercent(a, CPUTimes{Idle: 10, Total: 20}); ok {
		t.Error("counters going backward must not produce a percentage")
	}
}

func TestReadCPUTimesErrors(t *testing.T) {
	if _, err := ReadCPUTimes(t.TempDir()); err == nil {
		t.Error("missing /proc/stat must be an error")
	}
	if _, err := ReadCPUTimes(tree(t, map[string]string{"proc/stat": "intr 1 2 3\n"})); err == nil {
		t.Error("first line that is not the cpu line must be an error")
	}
	if _, err := ReadCPUTimes(tree(t, map[string]string{"proc/stat": "cpu  1 x 3 4\n"})); err == nil {
		t.Error("non-numeric field must be an error")
	}
}

func TestReadMemUsesMemAvailable(t *testing.T) {
	mem, swap, err := ReadMem(fullTree(t))
	if err != nil {
		t.Fatal(err)
	}
	if mem.Total != 1000*1024 || mem.Available != 400*1024 || mem.Used != 600*1024 {
		t.Errorf("mem = %+v", mem)
	}
	if swap.Total != 200*1024 || swap.Used != 50*1024 {
		t.Errorf("swap = %+v", swap)
	}
}

func TestReadMemRequiresMemAvailable(t *testing.T) {
	root := tree(t, map[string]string{"proc/meminfo": "MemTotal: 1000 kB\ngarbage line\n"})
	if _, _, err := ReadMem(root); err == nil {
		t.Error("meminfo without MemAvailable must be an error")
	}
}

func TestReadLoadAndUptime(t *testing.T) {
	root := fullTree(t)
	load, err := ReadLoad(root)
	if err != nil || len(load) != 3 || load[0] != 0.42 || load[2] != 0.20 {
		t.Errorf("load = %v, %v", load, err)
	}
	up, err := ReadUptime(root)
	if err != nil || up != 3628800 {
		t.Errorf("uptime = %v, %v", up, err)
	}
}

func TestReadHostInfo(t *testing.T) {
	h := ReadHostInfo(fullTree(t))
	want := HostInfo{Hostname: "web-01", OS: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-18-amd64", CPUModel: "Test CPU", Cores: 2}
	if h != want {
		t.Errorf("host info = %+v, want %+v", h, want)
	}
}

func TestReadHostInfoUsesBoardModelWhenThereIsNoModelName(t *testing.T) {
	// arm64 kernels print no "model name"; Raspberry Pi and similar boards print "Model".
	root := tree(t, map[string]string{"proc/cpuinfo": "processor\t: 0\nBogoMIPS\t: 108.00\n\nprocessor\t: 1\nBogoMIPS\t: 108.00\n\nRevision\t: d03114\nModel\t\t: Raspberry Pi 4 Model B Rev 1.4\n"})
	h := ReadHostInfo(root)
	if h.CPUModel != "Raspberry Pi 4 Model B Rev 1.4" || h.Cores != 2 {
		t.Errorf("host info = %+v", h)
	}
	x86 := tree(t, map[string]string{"proc/cpuinfo": "processor\t: 0\nmodel name\t: Real CPU\nModel\t\t: Some Board\n"})
	if got := ReadHostInfo(x86).CPUModel; got != "Real CPU" {
		t.Errorf("model name wins over the board model, got %q", got)
	}
}

func TestReadHostInfoToleratesMissingFiles(t *testing.T) {
	// arm64 has no "model name" line; a bare container may lack os-release.
	root := tree(t, map[string]string{"proc/cpuinfo": "processor\t: 0\nBogoMIPS\t: 48.00\n"})
	h := ReadHostInfo(root)
	if h.Cores != 1 || h.CPUModel != "" || h.Hostname != "" {
		t.Errorf("host info = %+v", h)
	}
}
