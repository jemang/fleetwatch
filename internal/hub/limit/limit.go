// Package limit counts failed attempts per remote address.
package limit

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const sweepAbove = 10000

type Limiter struct {
	max    int
	window time.Duration
	now    func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
}

func New(max int, window time.Duration, now func() time.Time) *Limiter {
	return &Limiter{max: max, window: window, now: now, fails: map[string][]time.Time{}}
}

func (l *Limiter) recent(key string) []time.Time {
	cutoff := l.now().Add(-l.window)
	all := l.fails[key]
	i := 0
	for i < len(all) && !all[i].After(cutoff) {
		i++
	}
	if i == len(all) {
		delete(l.fails, key)
		return nil
	}
	l.fails[key] = all[i:]
	return l.fails[key]
}

// Allow reports whether the key has fewer than max failures inside the window.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key)) < l.max
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > sweepAbove {
		for k := range l.fails {
			l.recent(k)
		}
	}
	l.fails[key] = append(l.recent(key), l.now())
}

// trusted are the proxies whose X-Forwarded-For header is believed. Set once
// at start-up, before requests are served.
var trusted []netip.Prefix

func SetTrustedProxies(prefixes []netip.Prefix) { trusted = prefixes }

// ParsePrefixes reads a comma-separated list of addresses and networks, as
// the FLEETWATCH_TRUSTED_PROXIES setting holds it.
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network", item)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func isTrusted(a netip.Addr) bool {
	for _, p := range trusted {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// RemoteIP is the address limits are counted on. Behind a trusted proxy it
// is the last X-Forwarded-For entry that is not a trusted proxy itself; any
// other sender's header is ignored, so it cannot choose its own address.
func RemoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !isTrusted(peer) {
		return host
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return host
		}
		if !isTrusted(a) {
			return a.Unmap().String()
		}
	}
	return host
}
