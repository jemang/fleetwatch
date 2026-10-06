package checker

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/url"
	"sync"
	"time"

	"fleetwatch/internal/hub/alert"
	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
)

const (
	maxInFlight = 16
	maxSpread   = 10 * time.Second
)

type seenKey struct {
	url      string
	interval int
}

// Checker checks every enabled service on its interval. Tick starts the
// checks that are due and returns; Wait waits for them.
type Checker struct {
	St  *store.Store
	Bus *live.Bus
	Now func() time.Time
	// Do runs one check; nil is the real HTTP check.
	Do  func(ctx context.Context, sv store.Service) Result
	Log func(format string, args ...any)
	// Spread picks the first check after start in [0, max); nil is random.
	Spread func(max time.Duration) time.Duration

	mu      sync.Mutex
	started bool
	due     map[int64]time.Time
	seen    map[int64]seenKey
	running map[int64]bool
	// gen changes when a service is edited (URL, interval) or paused; a check
	// started under an older generation is stale and its result is dropped.
	gen map[int64]int
	wg  sync.WaitGroup
}

func (c *Checker) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(format, args...)
	}
}

func (c *Checker) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Wait()
			return
		case <-t.C:
			if err := c.Tick(ctx); err != nil && ctx.Err() == nil {
				c.logf("service checks: %v", err)
			}
		}
	}
}

func (c *Checker) Wait() { c.wg.Wait() }

func (c *Checker) spread(max time.Duration) time.Duration {
	if c.Spread != nil {
		return c.Spread(max)
	}
	return time.Duration(rand.Int64N(int64(max)))
}

// Tick starts every due check. A service is due when it is enabled, not
// being checked, and its interval has passed since its last check; a new,
// resumed or re-addressed service is due at once.
func (c *Checker) Tick(ctx context.Context) error {
	services, err := c.St.Services(ctx)
	if err != nil {
		return err
	}
	settings, err := c.St.Settings(ctx)
	if err != nil {
		return err
	}
	rules := RulesFrom(settings)
	now := c.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.due == nil {
		c.due, c.seen, c.running, c.gen = map[int64]time.Time{}, map[int64]seenKey{}, map[int64]bool{}, map[int64]int{}
	}
	// After a restart, services checked before start within 10 s instead of
	// all in the same second.
	first := !c.started
	c.started = true
	present := make(map[int64]bool, len(services))
	inFlight := len(c.running)
	for _, sv := range services {
		present[sv.ID] = true
		if !sv.Enabled {
			if _, known := c.due[sv.ID]; known {
				c.gen[sv.ID]++
			}
			delete(c.due, sv.ID)
			delete(c.seen, sv.ID)
			continue
		}
		key := seenKey{sv.URL, sv.IntervalS}
		if _, known := c.due[sv.ID]; !known {
			c.due[sv.ID] = now
			if first && sv.CheckedAt != 0 {
				c.due[sv.ID] = now.Add(c.spread(min(time.Duration(sv.IntervalS)*time.Second, maxSpread)))
			}
		} else if c.seen[sv.ID] != key {
			c.due[sv.ID] = now
			c.gen[sv.ID]++
		}
		c.seen[sv.ID] = key
		if c.running[sv.ID] || now.Before(c.due[sv.ID]) || inFlight >= maxInFlight {
			continue
		}
		c.running[sv.ID] = true
		inFlight++
		c.wg.Add(1)
		go c.run(ctx, sv, rules, c.gen[sv.ID])
	}
	for id := range c.due {
		if !present[id] {
			delete(c.due, id)
			delete(c.seen, id)
		}
	}
	for id := range c.gen {
		if !present[id] && !c.running[id] {
			delete(c.gen, id)
		}
	}
	return nil
}

// host is what log lines say about a URL: never its path or query, which can
// hold a token.
func host(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return "?"
}

// current reports whether a check started under generation gen still
// describes the service.
func (c *Checker) current(id int64, gen int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen[id] == gen
}

func (c *Checker) run(ctx context.Context, sv store.Service, rules Rules, gen int) {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		delete(c.running, sv.ID)
		// After an edit or a pause, Tick has already decided when it is due.
		if c.gen[sv.ID] == gen {
			c.due[sv.ID] = c.Now().Add(time.Duration(sv.IntervalS) * time.Second)
		}
		c.mu.Unlock()
	}()
	do := c.Do
	if do == nil {
		do = func(ctx context.Context, sv store.Service) Result { return Check(ctx, sv, c.Now) }
	}
	res := do(ctx, sv)
	cur := State{Name: sv.State, FailStreak: sv.FailStreak, OkStreak: sv.OkStreak, Reason: sv.LastError}
	if sv.StateSince != 0 {
		cur.Since = time.Unix(sv.StateSince, 0)
	}
	if cur.Name == Paused || cur.Name == "" {
		cur.Name = Unknown
	}
	next := Next(cur, res, rules)
	// The stored error is the latest failure, also while it is only suspected.
	cs := store.CheckState{State: next.Name, OK: res.OK, CheckedAt: res.At.Unix(), Ms: res.Ms, Code: res.Code,
		Error: next.Reason, FailStreak: next.FailStreak, OkStreak: next.OkStreak, CertExpiresAt: sv.CertExpiresAt}
	if !res.OK {
		cs.Error = res.Reason
		// A failure that only raises suspicion is not a response time.
		if next.Name != Down {
			cs.Ms, cs.Code = sv.LastMs, sv.LastCode
		}
	}
	if !next.Since.IsZero() {
		cs.Since = next.Since.Unix()
	}
	if !res.CertExpires.IsZero() {
		cs.CertExpiresAt = res.CertExpires.Unix()
	}
	if !c.current(sv.ID, gen) {
		return
	}
	if err := c.St.SaveCheck(ctx, sv.ID, sv.URL, cs); err != nil {
		// Removed, paused or re-addressed meanwhile: the result is stale.
		if !errors.Is(err, store.ErrNotFound) && ctx.Err() == nil {
			c.logf("service checks: %v", err)
		}
		return
	}
	c.Bus.Publish(live.Event{Kind: live.ServiceChecked, HostID: sv.ID})
	if next.Name == cur.Name {
		return
	}
	c.Bus.Publish(live.Event{Kind: live.ServicesChanged})
	name := "service " + sv.Name + " (" + host(sv.URL) + ")"
	switch {
	case next.Name == Down:
		c.logf("%s is down: %s", name, res.Reason)
	case cur.Name == Down:
		c.logf("%s recovered after %s", name, alert.Lasted(res.At.Sub(cur.Since)))
	case next.Name == Degraded && cur.Name == Online:
		c.logf("%s is slow: %d ms", name, res.Ms)
	case next.Name == Online && cur.Name == Degraded:
		c.logf("%s is fast again: %d ms", name, res.Ms)
	}
}
