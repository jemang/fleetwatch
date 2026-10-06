package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPushSubscriptions(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	t0 := time.Unix(1_800_000_000, 0)
	if err := s.SavePushSubscription(ctx, PushSubscription{Endpoint: "https://push.example/a", P256dh: "k1", Auth: "a1", Label: "Chrome on Android"}, t0); err != nil {
		t.Fatal(err)
	}
	// The same browser again (keys renewed) updates its row.
	if err := s.SavePushSubscription(ctx, PushSubscription{Endpoint: "https://push.example/a", P256dh: "k2", Auth: "a2", Label: "Chrome on Android"}, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.SavePushSubscription(ctx, PushSubscription{Endpoint: "https://push.example/b", P256dh: "k3", Auth: "a3", Label: "Safari on iPhone"}, t0)
	subs, err := s.PushSubscriptions(ctx)
	if err != nil || len(subs) != 2 {
		t.Fatalf("subs = %+v, %v", subs, err)
	}
	a := subs[0]
	if a.P256dh != "k2" || a.Auth != "a2" || !a.CreatedAt.Equal(t0) || !a.LastOKAt.IsZero() {
		t.Errorf("updated row: %+v", a)
	}
	if err := s.MarkPushOK(ctx, a.ID, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PushSubscriptionByEndpoint(ctx, "https://push.example/a"); err != nil || !got.LastOKAt.Equal(t0.Add(2*time.Hour)) || got.Label != "Chrome on Android" {
		t.Errorf("by endpoint: %+v %v", got, err)
	}
	if _, err := s.PushSubscriptionByEndpoint(ctx, "https://push.example/zzz"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown endpoint: %v", err)
	}
	if err := s.DeletePushSubscription(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePushSubscription(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
	if err := s.DeletePushSubscriptionByEndpoint(ctx, "https://push.example/b"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePushSubscriptionByEndpoint(ctx, "https://push.example/b"); err != nil {
		t.Errorf("deleting an absent endpoint is fine: %v", err)
	}
	if subs, _ := s.PushSubscriptions(ctx); len(subs) != 0 {
		t.Errorf("left: %+v", subs)
	}
}

func TestPushKeyIsMadeOnce(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	n := 0
	create := func() (string, error) { n++; return "key-" + string(rune('0'+n)), nil }
	k1, err := s.PushKey(ctx, create)
	if err != nil || k1 != "key-1" {
		t.Fatalf("first: %q %v", k1, err)
	}
	k2, _ := s.PushKey(ctx, create)
	if k2 != "key-1" || n != 1 {
		t.Errorf("second: %q, made %d times", k2, n)
	}
	// A Settings save writes its own keys only.
	s.SetSettings(ctx, map[string]string{"webhook_url": "https://x"})
	if set, _ := s.Settings(ctx); set["push_vapid_key"] != "key-1" {
		t.Errorf("settings save dropped the key: %v", set)
	}
}
