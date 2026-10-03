// Package pve reads guests and storage of the local Proxmox VE node through
// the node's own API, with a read-only API token. It starts no processes.
package pve

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fleetwatch/internal/protocol"
)

const (
	DefaultAPIURL = "https://127.0.0.1:8006"
	DefaultCAFile = "/etc/pve/pve-root-ca.pem"

	ipEvery  = 5 * time.Minute // how often a guest's addresses are looked up
	ipBudget = 4 * time.Second // time one cycle may spend on address lookups
)

type Config struct{ APIURL, TokenID, TokenSecret, CAFile string }

type Client struct {
	base, auth string
	http       *http.Client
}

// NewClient trusts only the CA in cfg.CAFile, the cluster CA of the node.
func NewClient(cfg Config) (*Client, error) {
	pemBytes, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("pve: CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("pve: no certificate found in %s", cfg.CAFile)
	}
	return &Client{
		base: strings.TrimRight(cfg.APIURL, "/") + "/api2/json",
		auth: "PVEAPIToken=" + cfg.TokenID + "=" + cfg.TokenSecret,
		http: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.auth)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pve: %s answered HTTP %d", path, resp.StatusCode)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("pve: %s: %w", path, err)
	}
	return json.Unmarshal(env.Data, out)
}

// num reads a JSON number that the API may also send as a quoted string.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return err
	}
	*n = num(v)
	return nil
}

func (n num) uint() uint64 {
	if n <= 0 {
		return 0
	}
	return uint64(n)
}

type resource struct {
	Type       string `json:"type"`
	VMID       num    `json:"vmid"`
	Name       string `json:"name"`
	Node       string `json:"node"`
	Status     string `json:"status"`
	MaxCPU     num    `json:"maxcpu"`
	CPU        num    `json:"cpu"`
	Mem        num    `json:"mem"`
	MaxMem     num    `json:"maxmem"`
	Disk       num    `json:"disk"`
	MaxDisk    num    `json:"maxdisk"`
	Uptime     num    `json:"uptime"`
	Template   num    `json:"template"`
	Storage    string `json:"storage"`
	PluginType string `json:"plugintype"`
}

type ipEntry struct {
	ips []string
	at  time.Time
}

// Collector produces the Proxmox part of a report. Run keeps a snapshot fresh
// in the background; Latest returns it without waiting.
type Collector struct {
	Root   string  // filesystem root, "" in production
	Client *Client // nil when no API token is configured
	Now    func() time.Time

	ips map[int]ipEntry

	mu     sync.Mutex
	latest *protocol.Proxmox
}

func (c *Collector) Detected() bool {
	st, err := os.Stat(filepath.Join(c.Root, "/etc/pve"))
	return err == nil && st.IsDir()
}

func (c *Collector) Latest() *protocol.Proxmox {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latest
}

func (c *Collector) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		snapshot := c.Collect(ctx)
		c.mu.Lock()
		c.latest = snapshot
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func brief(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Collect returns nil on a host without Proxmox.
func (c *Collector) Collect(ctx context.Context) *protocol.Proxmox {
	if !c.Detected() {
		return nil
	}
	p := &protocol.Proxmox{Detected: true}
	if c.Client == nil {
		return p
	}
	p.Configured = true

	var version struct {
		Version string `json:"version"`
	}
	var status []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Local   num    `json:"local"`
		Quorate num    `json:"quorate"`
	}
	var res []resource
	for path, out := range map[string]any{"/version": &version, "/cluster/status": &status, "/cluster/resources": &res} {
		if err := c.Client.get(ctx, path, out); err != nil {
			p.Error = brief(err)
			return p
		}
	}
	p.Version = version.Version
	for _, s := range status {
		switch {
		case s.Type == "cluster":
			q := s.Quorate != 0
			p.Cluster, p.Quorate = s.Name, &q
		case s.Type == "node" && s.Local != 0:
			p.Node = s.Name
		}
	}

	for _, r := range res {
		if r.Node != p.Node {
			continue
		}
		switch r.Type {
		case "qemu", "lxc":
			if r.Template != 0 {
				continue
			}
			status := r.Status
			if status != "running" && status != "stopped" && status != "paused" {
				status = "unknown"
			}
			p.Guests = append(p.Guests, protocol.Guest{
				ID: int(r.VMID), Type: r.Type, Name: r.Name, Status: status, CPUs: int(r.MaxCPU),
				CPUPct:  math.Round(float64(r.CPU)*1000) / 10,
				MemUsed: r.Mem.uint(), MemMax: r.MaxMem.uint(), DiskUsed: r.Disk.uint(), DiskMax: r.MaxDisk.uint(), UptimeS: r.Uptime.uint(),
			})
		case "storage":
			p.Storage = append(p.Storage, protocol.Storage{Name: r.Storage, Type: r.PluginType, Active: r.Status == "available", Total: r.MaxDisk.uint(), Used: r.Disk.uint()})
		}
	}
	sort.Slice(p.Guests, func(i, j int) bool { return p.Guests[i].ID < p.Guests[j].ID })
	sort.Slice(p.Storage, func(i, j int) bool { return p.Storage[i].Name < p.Storage[j].Name })
	c.fillAddresses(ctx, p)
	return p
}

// fillAddresses looks up the addresses of running guests, at most every
// ipEvery per guest and within ipBudget per cycle. A guest whose lookup fails
// keeps no address: an address is never guessed.
func (c *Collector) fillAddresses(ctx context.Context, p *protocol.Proxmox) {
	if c.ips == nil {
		c.ips = map[int]ipEntry{}
	}
	now := c.Now()
	deadline := time.Now().Add(ipBudget)
	seen := map[int]bool{}
	for i := range p.Guests {
		g := &p.Guests[i]
		seen[g.ID] = true
		if g.Status != "running" {
			delete(c.ips, g.ID)
			continue
		}
		entry, cached := c.ips[g.ID]
		if (!cached || now.Sub(entry.at) >= ipEvery) && time.Now().Before(deadline) {
			ips, err := c.guestAddresses(ctx, p.Node, *g)
			if err != nil {
				ips = nil
			}
			entry = ipEntry{ips: ips, at: now}
			c.ips[g.ID] = entry
		}
		g.IPs = entry.ips
	}
	for id := range c.ips {
		if !seen[id] {
			delete(c.ips, id)
		}
	}
}

func (c *Collector) guestAddresses(ctx context.Context, node string, g protocol.Guest) ([]string, error) {
	var raw []string
	switch g.Type {
	case "lxc":
		var ifs []struct {
			Name  string `json:"name"`
			Inet  string `json:"inet"`
			Inet6 string `json:"inet6"`
		}
		if err := c.Client.get(ctx, fmt.Sprintf("/nodes/%s/lxc/%d/interfaces", node, g.ID), &ifs); err != nil {
			return nil, err
		}
		for _, i := range ifs {
			raw = append(raw, i.Inet, i.Inet6)
		}
	case "qemu":
		var reply struct {
			Result []struct {
				Addrs []struct {
					Addr string `json:"ip-address"`
				} `json:"ip-addresses"`
			} `json:"result"`
		}
		if err := c.Client.get(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/agent/network-get-interfaces", node, g.ID), &reply); err != nil {
			return nil, err
		}
		for _, i := range reply.Result {
			for _, a := range i.Addrs {
				raw = append(raw, a.Addr)
			}
		}
	default:
		return nil, errors.New("pve: unknown guest type")
	}
	var v4, v6 []string
	for _, s := range raw {
		s, _, _ = strings.Cut(s, "/")
		a, err := netip.ParseAddr(s)
		if err != nil || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	return append(v4, v6...), nil
}
