package web

import (
	"context"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
)

// Watcher publishes an update when a host crosses the offline threshold, so
// the dashboard changes even though no report arrives.
type Watcher struct {
	st    *store.Store
	bus   *live.Bus
	now   func() time.Time
	state map[int64]bool
}

func NewWatcher(st *store.Store, bus *live.Bus, now func() time.Time) *Watcher {
	return &Watcher{st: st, bus: bus, now: now}
}

func (w *Watcher) Tick(ctx context.Context) error {
	hosts, err := w.st.Hosts(ctx)
	if err != nil {
		return err
	}
	now := w.now()
	next := make(map[int64]bool, len(hosts))
	for _, h := range hosts {
		on := Online(h.LastSeen, now)
		next[h.ID] = on
		if was, known := w.state[h.ID]; known && was != on {
			w.bus.Publish(live.Event{Kind: live.HostUpdated, HostID: h.ID})
		}
	}
	w.state = next
	return nil
}

func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}
