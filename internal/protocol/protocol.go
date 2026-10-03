// Package protocol defines the wire format shared by the agent and the Hub.
package protocol

const Version = 1

type EnrollRequest struct {
	Token           string `json:"token"`
	Hostname        string `json:"hostname"`
	AgentVersion    string `json:"agent_version"`
	ProtocolVersion int    `json:"protocol_version"`
}

type EnrollResponse struct {
	AgentID    string `json:"agent_id"`
	AgentToken string `json:"agent_token"`
}

type Report struct {
	ProtocolVersion int        `json:"protocol_version"`
	AgentVersion    string     `json:"agent_version"`
	TS              int64      `json:"ts"`
	Metrics         Metrics    `json:"metrics"`
	Inventory       *Inventory `json:"inventory,omitempty"`
}

// Metrics fields are omitted when their collector produced no value.
type Metrics struct {
	CPUPct   *float64  `json:"cpu_pct,omitempty"`
	Load     []float64 `json:"load,omitempty"`
	UptimeS  uint64    `json:"uptime_s,omitempty"`
	Mem      *Mem      `json:"mem,omitempty"`
	Swap     *Swap     `json:"swap,omitempty"`
	Disks    []Disk    `json:"disks,omitempty"`
	Net      []NetIf   `json:"net,omitempty"`
	Services []Service `json:"services,omitempty"`
	Proxmox  *Proxmox  `json:"proxmox,omitempty"`
}

// Proxmox is present only on hosts where Proxmox VE was detected.
type Proxmox struct {
	Detected   bool      `json:"detected"`
	Configured bool      `json:"configured"`
	Error      string    `json:"error,omitempty"`
	Version    string    `json:"version,omitempty"`
	Node       string    `json:"node,omitempty"`
	Cluster    string    `json:"cluster,omitempty"`
	Quorate    *bool     `json:"quorate,omitempty"`
	Guests     []Guest   `json:"guests,omitempty"`
	Storage    []Storage `json:"storage,omitempty"`
}

// Guest type is "qemu" or "lxc"; status is running, stopped, paused or unknown.
// IPs is empty when the address is not known: it is never guessed.
type Guest struct {
	ID       int      `json:"id"`
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	CPUs     int      `json:"cpus"`
	CPUPct   float64  `json:"cpu_pct"`
	MemUsed  uint64   `json:"mem_used"`
	MemMax   uint64   `json:"mem_max"`
	DiskUsed uint64   `json:"disk_used"`
	DiskMax  uint64   `json:"disk_max"`
	UptimeS  uint64   `json:"uptime_s"`
	IPs      []string `json:"ips,omitempty"`
}

type Storage struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Active bool   `json:"active"`
	Total  uint64 `json:"total"`
	Used   uint64 `json:"used"`
}

// Service status is one of: running, stopped, failed, unknown.
type Service struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Mem struct {
	Total     uint64 `json:"total"`
	Used      uint64 `json:"used"`
	Available uint64 `json:"available"`
}

type Swap struct {
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type Disk struct {
	Mount string `json:"mount"`
	FS    string `json:"fs"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type NetIf struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

type Inventory struct {
	Hostname   string      `json:"hostname"`
	OS         string      `json:"os"`
	Kernel     string      `json:"kernel"`
	CPUModel   string      `json:"cpu_model"`
	Cores      int         `json:"cores"`
	Interfaces []Interface `json:"interfaces"`
}

type Interface struct {
	Name         string   `json:"name"`
	DefaultRoute bool     `json:"default_route,omitempty"`
	IPv4         []string `json:"ipv4"`
	IPv6         []string `json:"ipv6"`
}

// ReplayResponse is the body of a 409 reply to a report.
type ReplayResponse struct {
	LastTS int64 `json:"last_ts"`
}

// SelfResponse tells an agent how the Hub knows it. LastSeen is 0 until the
// first report arrives; Now is the Hub clock.
type SelfResponse struct {
	HostID   int64  `json:"host_id"`
	Name     string `json:"name"`
	LastSeen int64  `json:"last_seen"`
	Now      int64  `json:"now"`
}
