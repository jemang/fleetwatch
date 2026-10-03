package agent

import (
	"fmt"
	"strings"
	"context"
	"errors"
	"testing"
	"time"

	"fleetwatch/internal/agent/client"
	"fleetwatch/internal/protocol"
)

type fakeSampler struct {
	withInventory bool
	resends       int
}

func (f *fakeSampler) Sample() (protocol.Metrics, *protocol.Inventory) {
	if f.withInventory {
		return protocol.Metrics{}, &protocol.Inventory{Hostname: "web-01"}
	}
	return protocol.Metrics{}, nil
}
func (f *fakeSampler) ResendInventory() { f.resends++ }

type fakeSender struct {
	errs []error
	sent []protocol.Report
}

func (f *fakeSender) Send(_ context.Context, r protocol.Report) error {
	f.sent = append(f.sent, r)
	if len(f.errs) == 0 {
		return nil
	}
	err := f.errs[0]
	f.errs = f.errs[1:]
	return err
}

func newRunner(errs ...error) (*Runner, *fakeSampler, *fakeSender) {
	sa, se := &fakeSampler{}, &fakeSender{errs: errs}
	return &Runner{
		Sampler: sa, Sender: se, Interval: 15 * time.Second,
		Now:    func() time.Time { return time.Unix(1000, 0) },
		Jitter: func(d time.Duration) time.Duration { return d },
		Log:    func(string, ...any) {},
	}, sa, se
}

func TestStepSuccess(t *testing.T) {
	r, _, se := newRunner()
	if d := r.Step(context.Background()); d != 15*time.Second {
		t.Errorf("delay = %v, want 15s", d)
	}
	got := se.sent[0]
	if got.ProtocolVersion != protocol.Version || got.AgentVersion != Version || got.TS != 1000 {
		t.Errorf("report = %+v", got)
	}
}

func TestTimestampsStrictlyIncreaseWhenClockStandsStill(t *testing.T) {
	r, _, se := newRunner()
	r.Step(context.Background())
	r.Step(context.Background())
	if se.sent[1].TS != 1001 {
		t.Errorf("second ts = %d, want 1001", se.sent[1].TS)
	}
}

func TestReplayMovesTimestampPastHub(t *testing.T) {
	r, _, se := newRunner(&client.ReplayError{LastTS: 5000})
	if d := r.Step(context.Background()); d != 15*time.Second {
		t.Errorf("delay after 409 = %v, want the normal interval", d)
	}
	r.Step(context.Background())
	if se.sent[1].TS != 5001 {
		t.Errorf("ts after 409 = %d, want 5001 (clock behind the Hub's last ts)", se.sent[1].TS)
	}
}

func TestBackoffOnTransportErrorsAndReset(t *testing.T) {
	boom := errors.New("connection refused")
	r, _, _ := newRunner(boom, boom, &client.StatusError{Code: 503}, boom, nil, boom)
	var got []time.Duration
	for i := 0; i < 6; i++ {
		got = append(got, r.Step(context.Background()))
	}
	want := []time.Duration{15 * time.Second, 30 * time.Second, 60 * time.Second, 60 * time.Second, 15 * time.Second, 15 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delays = %v, want %v", got, want)
		}
	}
}

func TestUnauthorizedRetriesSlowerAndSlowerAndLogsOnce(t *testing.T) {
	r, _, _ := newRunner(client.ErrUnauthorized, client.ErrUnauthorized, client.ErrUnauthorized, client.ErrUnauthorized, client.ErrUnauthorized, client.ErrUnauthorized, nil, client.ErrUnauthorized)
	var logs []string
	r.Log = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if d := r.Step(context.Background()); d != w {
			t.Errorf("delay after 401 number %d = %v, want %v", i+1, d, w)
		}
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "does not accept") {
		t.Errorf("a rejected credential is logged once, got %q", logs)
	}
	if d := r.Step(context.Background()); d != 15*time.Second || len(logs) != 2 || !strings.Contains(logs[1], "accepts") {
		t.Errorf("after acceptance: delay %v, logs %q", d, logs)
	}
	if d := r.Step(context.Background()); d != 5*time.Minute || len(logs) != 3 {
		t.Errorf("a new rejection starts over: delay %v, logs %q", d, logs)
	}
}

func TestClientErrorsDoNotBackOff(t *testing.T) {
	r, _, _ := newRunner(&client.StatusError{Code: 429}, &client.StatusError{Code: 400})
	for i := 0; i < 2; i++ {
		if d := r.Step(context.Background()); d != 15*time.Second {
			t.Errorf("delay after 4xx = %v, want 15s", d)
		}
	}
}

func TestInventoryIsResentAfterFailedSend(t *testing.T) {
	r, sa, _ := newRunner(errors.New("down"), nil)
	sa.withInventory = true
	r.Step(context.Background())
	if sa.resends != 1 {
		t.Fatalf("a failed report that carried inventory must request a resend, got %d", sa.resends)
	}
	r.Step(context.Background())
	if sa.resends != 1 {
		t.Errorf("a delivered report must not request a resend, got %d", sa.resends)
	}
}

func TestDefaultJitterBounds(t *testing.T) {
	for i := 0; i < 200; i++ {
		if d := DefaultJitter(30 * time.Second); d < 24*time.Second || d > 36*time.Second {
			t.Fatalf("jitter(30s) = %v, want within 20%%", d)
		}
		if d := DefaultJitter(MaxBackoff); d > MaxBackoff {
			t.Fatalf("jitter must not exceed MaxBackoff, got %v", d)
		}
	}
}

func TestRunStopsWhenSleepReportsCancel(t *testing.T) {
	r, _, se := newRunner()
	steps := 0
	r.Sleep = func(context.Context, time.Duration) error {
		steps++
		if steps == 3 {
			return context.Canceled
		}
		return nil
	}
	if err := r.Run(context.Background()); !errors.Is(err, context.Canceled) {
		t.Errorf("Run = %v, want context.Canceled", err)
	}
	if len(se.sent) != 3 {
		t.Errorf("sent %d reports, want 3", len(se.sent))
	}
}
