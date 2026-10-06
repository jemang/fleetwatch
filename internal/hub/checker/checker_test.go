package checker

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
)

type rig struct {
	t     *testing.T
	st    *store.Store
	bus   *live.Bus
	c     *Checker
	mu    sync.Mutex
	now   time.Time
	calls atomic.Int32
	logs  []string
	res   atomic.Value // func(store.Service) Result
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r := &rig{t: t, st: st, bus: live.New(), now: t0}
	r.answer(func(store.Service) Result { return Result{OK: true, Ms: 80, Code: 200} })
	r.c = &Checker{St: st, Bus: r.bus, Now: r.clock,
		Do: func(ctx context.Context, sv store.Service) Result {
			r.calls.Add(1)
			res := r.res.Load().(func(store.Service) Result)(sv)
			res.At = r.clock()
			return res
		},
		Log: func(f string, a ...any) {
			r.mu.Lock()
			r.logs = append(r.logs, fmt.Sprintf(f, a...))
			r.mu.Unlock()
		},
		Spread: func(max time.Duration) time.Duration { return max - time.Second },
	}
	return r
}

func (r *rig) answer(f func(store.Service) Result) { r.res.Store(f) }
func (r *rig) clock() time.Time                    { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *rig) advance(d time.Duration)             { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

func (r *rig) tick() {
	r.t.Helper()
	if err := r.c.Tick(context.Background()); err != nil {
		r.t.Fatal(err)
	}
	r.c.Wait()
}

func (r *rig) add(name, url string) int64 {
	r.t.Helper()
	id, err := r.st.CreateService(context.Background(), store.Service{Name: name, URL: url, IntervalS: 60, TimeoutS: 10, Enabled: true}, t0)
	if err != nil {
		r.t.Fatal(err)
	}
	return id
}

func (r *rig) get(id int64) store.Service { sv, _ := r.st.Service(context.Background(), id); return sv }

func (r *rig) logText() string { r.mu.Lock(); defer r.mu.Unlock(); return strings.Join(r.logs, "\n") }

func TestNewServiceIsCheckedAtOnceThenOnItsInterval(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	r.tick()
	if got := r.get(id); r.calls.Load() != 1 || got.State != Online || got.LastMs != 80 || got.CheckedAt != t0.Unix() {
		t.Fatalf("first tick: calls %d, %+v", r.calls.Load(), got)
	}
	r.advance(59 * time.Second)
	r.tick()
	if r.calls.Load() != 1 {
		t.Errorf("checked again before its interval: %d", r.calls.Load())
	}
	r.advance(time.Second)
	r.tick()
	if r.calls.Load() != 2 {
		t.Errorf("not checked after its interval: %d", r.calls.Load())
	}
}

func TestPausedIsNotChecked(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	r.st.SetServiceEnabled(context.Background(), id, false)
	r.tick()
	if r.calls.Load() != 0 {
		t.Errorf("a paused service was checked")
	}
	r.st.SetServiceEnabled(context.Background(), id, true)
	r.tick()
	if r.calls.Load() != 1 {
		t.Errorf("a resumed service must be checked at once: %d", r.calls.Load())
	}
}

// After a restart, services that were checked before start within 10 s,
// not all in the same second.
func TestFirstCheckAfterStartIsSpread(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	r.st.SaveCheck(context.Background(), id, "http://a.example", store.CheckState{State: Online, CheckedAt: t0.Unix() - 30})
	r.tick()
	if r.calls.Load() != 0 {
		t.Fatalf("checked at once after start")
	}
	r.advance(9 * time.Second) // Spread returns max - 1 s
	r.tick()
	if r.calls.Load() != 1 {
		t.Errorf("not checked within the spread: %d", r.calls.Load())
	}
}

func TestURLChangeIsCheckedAtOnce(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	r.tick()
	sv := r.get(id)
	sv.URL = "http://b.example"
	r.st.UpdateService(context.Background(), sv)
	r.advance(time.Second)
	r.tick()
	if r.calls.Load() != 2 || r.get(id).State != Online {
		t.Errorf("a new URL must be checked on the next tick: %d", r.calls.Load())
	}
}

func TestGoesDownAfterThreeFailuresAndRecovers(t *testing.T) {
	r := newRig(t)
	id := r.add("Grafana", "http://grafana.lan/?token=s3cret")
	events, cancel := r.bus.Subscribe()
	defer cancel()
	r.tick() // online
	var failing atomic.Bool
	failing.Store(true)
	r.answer(func(store.Service) Result {
		if failing.Load() {
			return Result{Reason: "timeout"}
		}
		return Result{OK: true, Ms: 50, Code: 200}
	})
	for i := 0; i < 3; i++ {
		r.advance(time.Minute)
		r.tick()
	}
	if got := r.get(id); got.State != Down || got.LastError != "timeout" || got.FailStreak != 3 || got.StateSince != r.clock().Unix() {
		t.Fatalf("after 3 failures: %+v", got)
	}
	failing.Store(false)
	for i := 0; i < 2; i++ {
		r.advance(time.Minute)
		r.tick()
	}
	if got := r.get(id); got.State != Online {
		t.Fatalf("after 2 successes: %+v", got)
	}
	logs := r.logText()
	for _, want := range []string{"service Grafana (grafana.lan) is down: timeout", "service Grafana (grafana.lan) recovered after 2m"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log is missing %q in %q", want, logs)
		}
	}
	if strings.Contains(logs, "s3cret") || strings.Count(logs, "\n") != 1 {
		t.Errorf("log lines only on state change, without the query: %q", logs)
	}
	checked, changed := 0, 0
	for len(events) > 0 {
		switch (<-events).Kind {
		case live.ServiceChecked:
			checked++
		case live.ServicesChanged:
			changed++
		}
	}
	if checked != 6 || changed != 3 {
		t.Errorf("events: %d checked (want 6), %d changed (want 3: unknown→online, →down, →online)", checked, changed)
	}
}

func TestSlowAndFastAgainAreLogged(t *testing.T) {
	r := newRig(t)
	r.add("API", "http://api.lan")
	r.tick()
	r.answer(func(store.Service) Result { return Result{OK: true, Ms: 1842, Code: 200} })
	r.advance(time.Minute)
	r.tick()
	r.answer(func(store.Service) Result { return Result{OK: true, Ms: 84, Code: 200} })
	r.advance(time.Minute)
	r.tick()
	logs := r.logText()
	if !strings.Contains(logs, "service API (api.lan) is slow: 1842 ms") || !strings.Contains(logs, "service API (api.lan) is fast again: 84 ms") {
		t.Errorf("logs = %q", logs)
	}
}

func TestRulesComeFromSettings(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	r.st.SetSettings(context.Background(), map[string]string{"svc_fail_n": "1"})
	r.answer(func(store.Service) Result { return Result{Reason: "HTTP 500", Code: 500} })
	r.tick()
	if got := r.get(id); got.State != Down {
		t.Errorf("1 failure to down from settings: %+v", got)
	}
}

func TestNoSecondCheckWhileRunning(t *testing.T) {
	r := newRig(t)
	r.add("a", "http://a.example")
	release := make(chan struct{})
	r.answer(func(store.Service) Result { <-release; return Result{OK: true} })
	r.c.Tick(context.Background())
	r.advance(2 * time.Minute)
	r.c.Tick(context.Background())
	close(release)
	r.c.Wait()
	if r.calls.Load() != 1 {
		t.Errorf("a running service was started again: %d", r.calls.Load())
	}
}

func TestAtMost16InFlight(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 20; i++ {
		r.add(fmt.Sprint("s", i), fmt.Sprintf("http://s%d.example", i))
	}
	release := make(chan struct{})
	var running, peak atomic.Int32
	r.answer(func(store.Service) Result {
		n := running.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		<-release
		running.Add(-1)
		return Result{OK: true}
	})
	r.c.Tick(context.Background())
	time.Sleep(200 * time.Millisecond)
	close(release)
	r.c.Wait()
	if peak.Load() != 16 || r.calls.Load() != 16 {
		t.Errorf("peak %d, calls %d, want 16 and 16 (the rest on a later tick)", peak.Load(), r.calls.Load())
	}
	r.tick()
	if r.calls.Load() != 20 {
		t.Errorf("the rest must run on the next tick: %d", r.calls.Load())
	}
}

// A check that ends after its service was paused leaves it paused.
func TestResultAfterPauseIsDropped(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	started, release := make(chan struct{}), make(chan struct{})
	r.answer(func(store.Service) Result { close(started); <-release; return Result{Reason: "timeout"} })
	r.c.Tick(context.Background())
	<-started
	r.st.SetServiceEnabled(context.Background(), id, false)
	close(release)
	r.c.Wait()
	if got := r.get(id); got.State != Paused || got.CheckedAt != 0 {
		t.Errorf("after a late result: %+v", got)
	}
}

// A URL edited while its check runs is checked on the next tick after that
// check ends, not one old interval later.
func TestEditWhileRunningIsCheckedNext(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	sv := r.get(id)
	sv.IntervalS = 3600
	r.st.UpdateService(context.Background(), sv)
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.answer(func(store.Service) Result {
		once.Do(func() { close(started); <-release })
		return Result{OK: true, Ms: 5}
	})
	r.c.Tick(context.Background())
	<-started
	sv = r.get(id)
	sv.URL = "http://b.example"
	r.st.UpdateService(context.Background(), sv)
	r.c.Tick(context.Background())
	close(release)
	r.c.Wait()
	r.advance(time.Second)
	r.tick()
	if got := r.get(id); r.calls.Load() != 2 || got.State != Online || got.URL != "http://b.example" {
		t.Errorf("calls %d, %+v: the new URL must be checked on the next tick", r.calls.Load(), got)
	}
}

// Pause and resume while a check runs: the late result is dropped, the
// service starts over (unknown, no streaks) and is checked at once.
func TestPauseAndResumeDuringCheck(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	ctx := context.Background()
	r.st.SaveCheck(ctx, id, "http://a.example", store.CheckState{State: Online, Since: t0.Unix(), CheckedAt: t0.Unix(), FailStreak: 2})
	r.c.started = true // not the first tick after start: no spread
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.answer(func(store.Service) Result {
		first := false
		once.Do(func() { first = true; close(started); <-release })
		if first {
			return Result{Reason: "timeout"}
		}
		return Result{OK: true, Ms: 5}
	})
	r.c.Tick(ctx)
	<-started
	r.st.SetServiceEnabled(ctx, id, false)
	r.c.Tick(ctx)
	r.st.SetServiceEnabled(ctx, id, true)
	r.c.Tick(ctx)
	close(release)
	r.c.Wait()
	if got := r.get(id); got.State != Unknown || got.FailStreak != 0 {
		t.Fatalf("late result after pause and resume: %+v", got)
	}
	r.advance(time.Second)
	r.tick()
	if got := r.get(id); r.calls.Load() != 2 || got.State != Online {
		t.Errorf("calls %d, %+v: a resumed service is checked at once", r.calls.Load(), got)
	}
}

// While a failure is only suspected, the card keeps the last good response
// time: a 10 s timeout is not a response time.
func TestSuspectedFailureKeepsLastResponseTime(t *testing.T) {
	r := newRig(t)
	id := r.add("a", "http://a.example")
	r.tick() // online, 80 ms
	r.answer(func(store.Service) Result { return Result{Ms: 10000, Reason: "timeout"} })
	r.advance(time.Minute)
	r.tick()
	if got := r.get(id); got.State != Online || got.LastMs != 80 || got.LastCode != 200 || got.LastError != "timeout" {
		t.Errorf("suspected: %+v", got)
	}
}
