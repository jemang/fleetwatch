package store

import (
	"errors"
	"testing"
	"time"
)

func TestPasskeys(t *testing.T) {
	s := open(t)
	if list, err := s.Passkeys(ctx); err != nil || len(list) != 0 {
		t.Fatalf("empty: %v %v", list, err)
	}
	id, err := s.AddPasskey(ctx, "MacBook", []byte("cred-1"), []byte(`{"id":"Y3JlZC0x"}`), t0)
	if err != nil || id == 0 {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(ctx, "again", []byte("cred-1"), []byte(`{}`), t0); err == nil {
		t.Error("the same credential cannot be stored twice")
	}
	s.AddPasskey(ctx, "YubiKey", []byte("cred-2"), []byte(`{}`), t0.Add(time.Minute))
	p, err := s.PasskeyByCredentialID(ctx, []byte("cred-1"))
	if err != nil || p.ID != id || p.Name != "MacBook" || string(p.Credential) != `{"id":"Y3JlZC0x"}` || !p.CreatedAt.Equal(t0) || !p.LastUsedAt.IsZero() {
		t.Errorf("passkey = %+v, %v", p, err)
	}
	if _, err := s.PasskeyByCredentialID(ctx, []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown credential: %v", err)
	}
	if err := s.UpdatePasskey(ctx, id, []byte(`{"signCount":7}`), t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Passkeys(ctx)
	if len(list) != 2 || list[0].Name != "MacBook" || string(list[0].Credential) != `{"signCount":7}` || !list[0].LastUsedAt.Equal(t0.Add(time.Hour)) || list[1].Name != "YubiKey" {
		t.Errorf("list = %+v", list)
	}
	if err := s.DeletePasskey(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePasskey(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
	if list, _ := s.Passkeys(ctx); len(list) != 1 {
		t.Errorf("after delete: %+v", list)
	}
}
