// Package live fans out host change events to dashboard connections.
package live

import "sync"

type Kind int

const (
	HostUpdated Kind = iota
	HostAdded
	// AlertsChanged carries no host: an alert was raised, fired or ended.
	AlertsChanged
	// HostRemoved names a host that no longer exists.
	HostRemoved
)

type Event struct {
	Kind   Kind
	HostID int64
}

type Bus struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

func New() *Bus { return &Bus{subs: map[chan Event]struct{}{}} }

func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			close(ch)
			b.mu.Unlock()
		})
	}
}

// Publish never blocks: a subscriber whose buffer is full loses the event.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}
