// Package agent runs the collect-and-report loop.
package agent

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"fleetwatch/internal/agent/client"
	"fleetwatch/internal/protocol"
	"fleetwatch/internal/version"
)

var Version = version.Version

const (
	// A rejected credential is tried again after UnauthorizedRetry, then
	// twice as long each time up to MaxUnauthorizedRetry. The agent never
	// gives up: the Hub may enable it again, or come back from a backup.
	UnauthorizedRetry    = 5 * time.Minute
	MaxUnauthorizedRetry = time.Hour
	MaxBackoff           = 60 * time.Second
)

type Sampler interface {
	Sample() (protocol.Metrics, *protocol.Inventory)
	ResendInventory()
}

type Sender interface {
	Send(ctx context.Context, r protocol.Report) error
}

type Runner struct {
	Sampler  Sampler
	Sender   Sender
	Interval time.Duration
	Now      func() time.Time
	Sleep    func(ctx context.Context, d time.Duration) error
	Jitter   func(d time.Duration) time.Duration
	Log      func(format string, args ...any)

	lastTS   int64
	failures int
	rejected int // 401 answers in a row
}

func (r *Runner) Run(ctx context.Context) error {
	for {
		if err := r.Sleep(ctx, r.Step(ctx)); err != nil {
			return err
		}
	}
}

// Step samples once, sends once and returns the wait before the next step.
// A failed report is dropped: every report is a full snapshot, so the next
// one supersedes it.
func (r *Runner) Step(ctx context.Context) time.Duration {
	m, inv := r.Sampler.Sample()
	ts := r.Now().Unix()
	if ts <= r.lastTS {
		ts = r.lastTS + 1
	}
	r.lastTS = ts

	err := r.Sender.Send(ctx, protocol.Report{ProtocolVersion: protocol.Version, AgentVersion: Version, TS: ts, Metrics: m, Inventory: inv})
	if err != nil && inv != nil {
		r.Sampler.ResendInventory()
	}

	var replay *client.ReplayError
	var status *client.StatusError
	switch {
	case err == nil:
		r.failures = 0
		if r.rejected > 0 {
			r.Log("the Hub accepts the agent again")
			r.rejected = 0
		}
		return r.Interval
	case errors.Is(err, client.ErrUnauthorized):
		r.rejected++
		if r.rejected == 1 {
			r.Log("the Hub does not accept this agent (credential replaced, agent disabled or server removed); trying again every %s, then up to every %s", UnauthorizedRetry, MaxUnauthorizedRetry)
		}
		d := UnauthorizedRetry
		for i := 1; i < r.rejected && d < MaxUnauthorizedRetry; i++ {
			d *= 2
		}
		return min(d, MaxUnauthorizedRetry)
	case errors.As(err, &replay):
		if replay.LastTS > r.lastTS {
			r.lastTS = replay.LastTS
		}
		r.failures = 0
		return r.Interval
	case errors.As(err, &status) && status.Code < 500:
		r.Log("report dropped: %v", err)
		r.failures = 0
		return r.Interval
	}
	r.failures++
	d := backoff(r.Interval, r.failures)
	r.Log("report failed (%d in a row): %v; next attempt in about %s", r.failures, err, d)
	return r.Jitter(d)
}

func backoff(interval time.Duration, failures int) time.Duration {
	d := interval
	for i := 1; i < failures && d < MaxBackoff; i++ {
		d *= 2
	}
	return min(d, MaxBackoff)
}

func DefaultJitter(d time.Duration) time.Duration {
	j := d + time.Duration((rand.Float64()*0.4-0.2)*float64(d))
	return min(j, MaxBackoff)
}

func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
