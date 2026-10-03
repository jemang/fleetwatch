// Package api serves the agent-facing endpoints.
package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/protocol"
)

const (
	MaxBody     = 256 << 10
	MinInterval = 5 * time.Second
	maxString   = 255
	maxServices = 100
	maxGuests   = 2000
	maxStorage  = 200
	// MaxExpanded bounds a gzip report after decompression.
	MaxExpanded = 4 << 20
)

var guestStatus = map[string]bool{"running": true, "stopped": true, "paused": true, "unknown": true}

var serviceStatus = map[string]bool{"running": true, "stopped": true, "failed": true, "unknown": true}

type API struct {
	st          *store.Store
	bus         *live.Bus
	now         func() time.Time
	enrollLimit *limit.Limiter

	mu         sync.Mutex
	lastAccept map[int64]time.Time
	// lastVersion remembers each agent's version since the Hub started, so
	// an upgrade gets one log line.
	lastVersion map[int64]string
	// names caches host names by agent for the report log line; a host keeps
	// its name for life, a re-enrolled server gets a new agent.
	names map[int64]string
}

func New(st *store.Store, bus *live.Bus, now func() time.Time) *API {
	return &API{st: st, bus: bus, now: now, enrollLimit: limit.New(5, time.Minute, now),
		lastAccept: map[int64]time.Time{}, lastVersion: map[int64]string{}, names: map[int64]string{}}
}

// hostName is the name of the agent's host, read once from the store.
func (a *API) hostName(r *http.Request, agent store.Agent) string {
	a.mu.Lock()
	name, ok := a.names[agent.ID]
	a.mu.Unlock()
	if ok {
		return name
	}
	h, err := a.st.Host(r.Context(), agent.HostID)
	if err != nil {
		return "host " + strconv.FormatInt(agent.HostID, 10)
	}
	a.mu.Lock()
	a.names[agent.ID] = h.Name
	a.mu.Unlock()
	return h.Name
}

// pct prints a usage value as the log shows it.
func pct(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%.0f%%", *v)
}

func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/agent/enroll", a.enroll)
	mux.HandleFunc("POST /api/v1/agent/report", a.report)
	mux.HandleFunc("GET /api/v1/agent/self", a.self)
}

// agentFor identifies the agent by its bearer token. It answers 401 itself
// for a missing, unknown or disabled credential.
func (a *API) agentFor(w http.ResponseWriter, r *http.Request) (store.Agent, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return store.Agent{}, false
	}
	agent, err := a.st.AgentByTokenHash(r.Context(), store.HashToken(token))
	if errors.Is(err, store.ErrNotFound) || (err == nil && agent.Disabled) {
		if r.URL.Path == "/api/v1/agent/report" {
			log.Printf("report rejected from %s (unknown or disabled credential)", limit.RemoteIP(r))
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return store.Agent{}, false
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return store.Agent{}, false
	}
	return agent, true
}

func (a *API) self(w http.ResponseWriter, r *http.Request) {
	agent, ok := a.agentFor(w, r)
	if !ok {
		return
	}
	host, err := a.st.Host(r.Context(), agent.HostID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := protocol.SelfResponse{HostID: host.ID, Name: host.Name, Now: a.now().Unix()}
	if !host.LastSeen.IsZero() {
		resp.LastSeen = host.LastSeen.Unix()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (a *API) enroll(w http.ResponseWriter, r *http.Request) {
	ip := limit.RemoteIP(r)
	if !a.enrollLimit.Allow(ip) {
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	var req protocol.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return
	}
	if req.ProtocolVersion != protocol.Version {
		http.Error(w, "unsupported protocol_version", http.StatusBadRequest)
		return
	}
	hostname := clip(strings.TrimSpace(req.Hostname))
	if hostname == "" {
		hostname = "unknown"
	}
	agentToken, err := store.NewToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// A token bound to a host replaces a credential; it adds no host.
	boundHost, _, _ := a.st.EnrollmentTokenHost(r.Context(), store.HashToken(req.Token), a.now())
	agentID, hostID, err := a.st.Enroll(r.Context(), store.EnrollParams{
		EnrollTokenHash: store.HashToken(req.Token),
		Hostname:        hostname,
		AgentTokenHash:  store.HashToken(agentToken),
		AgentVersion:    clip(req.AgentVersion),
		ProtocolVersion: req.ProtocolVersion,
		Now:             a.now(),
	})
	if errors.Is(err, store.ErrEnrollmentRejected) {
		a.enrollLimit.Fail(ip)
		log.Printf("enrollment rejected from %s (unknown or used token)", ip)
		http.Error(w, "enrollment token rejected", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	kind := live.HostAdded
	if boundHost != 0 {
		kind = live.HostUpdated
	}
	if h, err := a.st.Host(r.Context(), hostID); err == nil {
		if boundHost != 0 {
			log.Printf("credential of %s replaced, agent %s", h.Name, clip(req.AgentVersion))
		} else {
			log.Printf("server %s enrolled, agent %s", h.Name, clip(req.AgentVersion))
		}
	}
	a.bus.Publish(live.Event{Kind: kind, HostID: hostID})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: strconv.FormatInt(agentID, 10), AgentToken: agentToken})
}

func (a *API) report(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "cannot read request", http.StatusBadRequest)
		return
	}
	agent, ok := a.agentFor(w, r)
	if !ok {
		return
	}
	now := a.now()
	if since, ok := a.intervalOK(agent.ID, now); !ok {
		log.Printf("report from %s rejected (too often, %s since the last)", a.hostName(r, agent), since.Round(time.Second))
		http.Error(w, "reporting too often", http.StatusTooManyRequests)
		return
	}
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			http.Error(w, "malformed gzip body", http.StatusBadRequest)
			return
		}
		body, err = io.ReadAll(io.LimitReader(zr, MaxExpanded+1))
		if err != nil {
			http.Error(w, "malformed gzip body", http.StatusBadRequest)
			return
		}
		if len(body) > MaxExpanded {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	var rep protocol.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		http.Error(w, "malformed report", http.StatusBadRequest)
		return
	}
	if rep.ProtocolVersion != protocol.Version {
		http.Error(w, "unsupported protocol_version", http.StatusBadRequest)
		return
	}
	sanitize(&rep)
	err = a.st.AcceptReport(r.Context(), agent.ID, rep, now)
	var replay *store.ReplayError
	if errors.As(err, &replay) {
		log.Printf("report from %s rejected (timestamp %d already seen)", a.hostName(r, agent), rep.TS)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(protocol.ReplayResponse{LastTS: replay.LastTS})
		return
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	a.lastAccept[agent.ID] = now
	was := a.lastVersion[agent.ID]
	a.lastVersion[agent.ID] = rep.AgentVersion
	a.mu.Unlock()
	name := a.hostName(r, agent)
	if was != "" && rep.AgentVersion != "" && rep.AgentVersion != was {
		log.Printf("agent on %s now version %s, was %s", name, rep.AgentVersion, was)
	}
	point := store.PointFromReport(agent.HostID, rep, now)
	log.Printf("report from %s: agent %s, cpu %s, ram %s, disk %s", name, rep.AgentVersion, pct(point.CPU), pct(point.Mem), pct(point.Disk))
	a.st.QueueMetric(point)
	a.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: agent.HostID})
	w.WriteHeader(http.StatusNoContent)
}

// intervalOK reports whether enough time passed since the agent's last
// accepted report, and how much did.
func (a *API) intervalOK(agentID int64, now time.Time) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, seen := a.lastAccept[agentID]
	if !seen {
		return 0, true
	}
	since := now.Sub(last)
	return since, since >= MinInterval
}

func clip(s string) string {
	if utf8.RuneCountInString(s) <= maxString {
		return s
	}
	return string([]rune(s)[:maxString])
}

// sanitize bounds every agent-supplied string that the dashboard renders.
func sanitize(r *protocol.Report) {
	r.AgentVersion = clip(r.AgentVersion)
	for i := range r.Metrics.Disks {
		r.Metrics.Disks[i].Mount = clip(r.Metrics.Disks[i].Mount)
		r.Metrics.Disks[i].FS = clip(r.Metrics.Disks[i].FS)
	}
	for i := range r.Metrics.Net {
		r.Metrics.Net[i].Name = clip(r.Metrics.Net[i].Name)
		r.Metrics.Net[i].State = clip(r.Metrics.Net[i].State)
	}
	if len(r.Metrics.Services) > maxServices {
		r.Metrics.Services = r.Metrics.Services[:maxServices]
	}
	for i := range r.Metrics.Services {
		svc := &r.Metrics.Services[i]
		svc.Name = clip(svc.Name)
		if !serviceStatus[svc.Status] {
			svc.Status = "unknown"
		}
	}
	if p := r.Metrics.Proxmox; p != nil {
		p.Error, p.Version, p.Node, p.Cluster = clip(p.Error), clip(p.Version), clip(p.Node), clip(p.Cluster)
		if len(p.Guests) > maxGuests {
			p.Guests = p.Guests[:maxGuests]
		}
		kept := p.Guests[:0]
		for _, g := range p.Guests {
			if g.Type != "qemu" && g.Type != "lxc" {
				continue
			}
			g.Name, g.IPs = clip(g.Name), validAddrs(g.IPs)
			if !guestStatus[g.Status] {
				g.Status = "unknown"
			}
			kept = append(kept, g)
		}
		p.Guests = kept
		if len(p.Storage) > maxStorage {
			p.Storage = p.Storage[:maxStorage]
		}
		for i := range p.Storage {
			p.Storage[i].Name, p.Storage[i].Type = clip(p.Storage[i].Name), clip(p.Storage[i].Type)
		}
	}
	if inv := r.Inventory; inv != nil {
		inv.Hostname, inv.OS, inv.Kernel, inv.CPUModel = clip(strings.TrimSpace(inv.Hostname)), clip(inv.OS), clip(inv.Kernel), clip(inv.CPUModel)
		for i := range inv.Interfaces {
			inv.Interfaces[i].Name = clip(inv.Interfaces[i].Name)
			inv.Interfaces[i].IPv4 = validAddrs(inv.Interfaces[i].IPv4)
			inv.Interfaces[i].IPv6 = validAddrs(inv.Interfaces[i].IPv6)
		}
	}
}

// validAddrs keeps only strings that parse as IP addresses, without a zone:
// the dashboard shows these as the host's addresses.
func validAddrs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.WithZone("").String())
		}
	}
	return out
}
