package live

import (
	"testing"
	"time"
)

func TestPublishReachesEverySubscriber(t *testing.T) {
	b := New()
	a, cancelA := b.Subscribe()
	c, cancelC := b.Subscribe()
	defer cancelA()
	defer cancelC()
	b.Publish(Event{Kind: HostAdded, HostID: 7})
	for _, ch := range []<-chan Event{a, c} {
		select {
		case e := <-ch:
			if e.Kind != HostAdded || e.HostID != 7 {
				t.Errorf("event = %+v", e)
			}
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive the event")
		}
	}
}

func TestSlowSubscriberNeverBlocksPublish(t *testing.T) {
	b := New()
	_, cancel := b.Subscribe() // never read
	defer cancel()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.Publish(Event{HostID: int64(i)})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a subscriber that does not read")
	}
}

func TestCancelStopsDeliveryAndIsIdempotent(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	cancel()
	cancel()
	b.Publish(Event{HostID: 1})
	if _, open := <-ch; open {
		t.Error("channel must be closed after cancel")
	}
}
