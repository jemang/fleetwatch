package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fleetwatch/internal/protocol"
)

var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "tmpfs": true, "devtmpfs": true, "devpts": true,
	"cgroup": true, "cgroup2": true, "overlay": true, "squashfs": true, "securityfs": true,
	"pstore": true, "debugfs": true, "tracefs": true, "configfs": true, "fusectl": true,
	"mqueue": true, "hugetlbfs": true, "bpf": true, "autofs": true, "binfmt_misc": true,
	"efivarfs": true, "ramfs": true, "nsfs": true, "rpc_pipefs": true, "fuse.lxcfs": true,
}

type StatfsFunc func(path string) (total, used uint64, err error)

// ReadDisks lists real filesystems. Mounts of one device collapse to the
// shortest mount path; a mount whose statfs fails is left out.
func ReadDisks(root string, statfs StatfsFunc) ([]protocol.Disk, error) {
	b, err := os.ReadFile(filepath.Join(root, "/proc/mounts"))
	if err != nil {
		return nil, err
	}
	type mount struct{ path, fs string }
	best := map[string]mount{}
	var order []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || pseudoFS[f[2]] {
			continue
		}
		dev, m := f[0], mount{unescapeMount(f[1]), f[2]}
		cur, seen := best[dev]
		if !seen {
			order = append(order, dev)
		}
		if !seen || len(m.path) < len(cur.path) {
			best[dev] = m
		}
	}
	var out []protocol.Disk
	for _, dev := range order {
		m := best[dev]
		total, used, err := statfs(m.path)
		if err != nil || total == 0 {
			continue
		}
		out = append(out, protocol.Disk{Mount: m.path, FS: m.fs, Total: total, Used: used})
	}
	return out, nil
}

// unescapeMount decodes the octal escapes /proc/mounts uses for space, tab,
// newline and backslash.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
