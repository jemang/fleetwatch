package checker

import (
	"testing"
	"time"
)

var (
	t0    = time.Unix(1_790_000_000, 0)
	t1    = t0.Add(time.Minute)
	rules = Rules{FailuresToDown: 3, SuccessesToRecover: 2, SlowMs: 1000}
	ok    = Result{OK: true, Ms: 80, Code: 200, At: t1}
	slow  = Result{OK: true, Ms: 1500, Code: 200, At: t1}
	fail  = Result{Reason: "timeout", At: t1}
)

func TestNext(t *testing.T) {
	cases := []struct {
		name string
		cur  State
		r    Result
		want State
	}{
		{"first success", State{Name: Unknown}, ok, State{Name: Online, Since: t1, OkStreak: 1}},
		{"first slow success", State{Name: Unknown}, slow, State{Name: Degraded, Since: t1, OkStreak: 1}},
		{"unknown, failure below limit", State{Name: Unknown}, fail, State{Name: Unknown, FailStreak: 1}},
		{"online, failure 1 is only suspected", State{Name: Online, Since: t0, OkStreak: 5}, fail, State{Name: Online, Since: t0, FailStreak: 1}},
		{"online, failure 3 is down", State{Name: Online, Since: t0, FailStreak: 2}, fail, State{Name: Down, Since: t1, FailStreak: 3, Reason: "timeout"}},
		{"degraded, failure 3 is down", State{Name: Degraded, Since: t0, FailStreak: 2}, fail, State{Name: Down, Since: t1, FailStreak: 3, Reason: "timeout"}},
		{"down stays down, reason updated", State{Name: Down, Since: t0, FailStreak: 3, Reason: "HTTP 503"}, fail, State{Name: Down, Since: t0, FailStreak: 4, Reason: "timeout"}},
		{"down, success 1 is not enough", State{Name: Down, Since: t0, FailStreak: 4, Reason: "timeout"}, ok, State{Name: Down, Since: t0, OkStreak: 1, Reason: "timeout"}},
		{"down, success 2 recovers", State{Name: Down, Since: t0, OkStreak: 1, Reason: "timeout"}, ok, State{Name: Online, Since: t1, OkStreak: 2}},
		{"down, slow success 2 recovers as degraded", State{Name: Down, Since: t0, OkStreak: 1}, slow, State{Name: Degraded, Since: t1, OkStreak: 2}},
		{"online turns slow", State{Name: Online, Since: t0, OkStreak: 3}, slow, State{Name: Degraded, Since: t1, OkStreak: 4}},
		{"degraded turns fast", State{Name: Degraded, Since: t0, OkStreak: 3}, ok, State{Name: Online, Since: t1, OkStreak: 4}},
		{"online stays online", State{Name: Online, Since: t0, OkStreak: 3}, ok, State{Name: Online, Since: t0, OkStreak: 4}},
		{"success resets failures (flapping never goes down)", State{Name: Online, Since: t0, FailStreak: 2}, ok, State{Name: Online, Since: t0, OkStreak: 1}},
		{"exactly the slow limit is fast", State{Name: Online, Since: t0}, Result{OK: true, Ms: 1000, At: t1}, State{Name: Online, Since: t0, OkStreak: 1}},
	}
	for _, c := range cases {
		if got := Next(c.cur, c.r, rules); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
	strict := Rules{FailuresToDown: 1, SuccessesToRecover: 3, SlowMs: 1000}
	if got := Next(State{Name: Online}, fail, strict); got.Name != Down {
		t.Errorf("1 failure to down: %+v", got)
	}
	if got := Next(State{Name: Down, OkStreak: 1}, ok, strict); got.Name != Down {
		t.Errorf("3 successes to recover, after 2: %+v", got)
	}
}

func TestRulesFrom(t *testing.T) {
	if got := RulesFrom(map[string]string{}); got != (Rules{3, 2, 1000}) {
		t.Errorf("defaults = %+v", got)
	}
	if got := RulesFrom(map[string]string{"svc_fail_n": "5", "svc_ok_n": "1", "svc_slow_ms": "250"}); got != (Rules{5, 1, 250}) {
		t.Errorf("set = %+v", got)
	}
	if got := RulesFrom(map[string]string{"svc_fail_n": "x", "svc_ok_n": "0", "svc_slow_ms": "-1"}); got != (Rules{3, 2, 1000}) {
		t.Errorf("unreadable values keep defaults: %+v", got)
	}
}
