// Package checker checks services over HTTP(S) and decides their state.
package checker

import (
	"strconv"
	"time"
)

const (
	Unknown  = "unknown"
	Online   = "online"
	Degraded = "degraded"
	Down     = "down"
	Paused   = "paused"
)

// Result is one check. At is when it finished.
type Result struct {
	OK              bool
	Ms, Code        int
	Reason          string
	CertExpires, At time.Time
}

// State is what is known about a service between checks.
type State struct {
	Name                 string
	Since                time.Time
	FailStreak, OkStreak int
	Reason               string
}

// Rules: how many failures in a row make a service down, how many successes
// bring it back, and above how many milliseconds an answer is slow.
type Rules struct{ FailuresToDown, SuccessesToRecover, SlowMs int }

// RulesFrom reads the rules from settings; a missing or unreadable value
// keeps its default.
func RulesFrom(settings map[string]string) Rules {
	get := func(key string, def int) int {
		n, err := strconv.Atoi(settings[key])
		if err != nil || n < 1 {
			return def
		}
		return n
	}
	return Rules{FailuresToDown: get("svc_fail_n", 3), SuccessesToRecover: get("svc_ok_n", 2), SlowMs: get("svc_slow_ms", 1000)}
}

// Next decides the state after a check. One failure is not an outage: a
// service is down only after FailuresToDown failures in a row, and comes
// back after SuccessesToRecover successes in a row.
func Next(cur State, r Result, rules Rules) State {
	n := cur
	if !r.OK {
		n.OkStreak = 0
		n.FailStreak++
		switch {
		case cur.Name == Down:
			n.Reason = r.Reason
		case n.FailStreak >= rules.FailuresToDown:
			n.Name, n.Since, n.Reason = Down, r.At, r.Reason
		}
		return n
	}
	n.FailStreak = 0
	n.OkStreak++
	if cur.Name == Down && n.OkStreak < rules.SuccessesToRecover {
		return n
	}
	up := Online
	if r.Ms > rules.SlowMs {
		up = Degraded
	}
	n.Reason = ""
	if cur.Name != up {
		n.Name, n.Since = up, r.At
	}
	return n
}
