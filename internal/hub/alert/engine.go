package alert

import (
	"context"
	"errors"
	"fmt"
	"time"

	"fleetwatch/internal/hub/live"
	"fleetwatch/internal/hub/store"
)

const (
	giveUpAfter = time.Hour           // an undelivered message older than this is dropped
	keepFor     = 90 * 24 * time.Hour // resolved alerts are deleted after this
)

type alertKey struct {
	host          int64
	kind, subject string
}

// Engine turns conditions into stored alerts and messages. Tick is called on
// a timer by Run; it is not safe for concurrent use.
type Engine struct {
	St  *store.Store
	Bus *live.Bus
	Now func() time.Time
	Hub string // name of this Hub in messages
	// Rules overrides the waiting times; nil reads them from the settings.
	Rules *Rules
	// Send delivers one message; nil sends to the targets in the settings.
	Send         func(ctx context.Context, settings map[string]string, m Message) error
	TelegramBase string
	Log          func(format string, args ...any)

	seenRunning map[GuestKey]bool
}

func (e *Engine) logf(format string, args ...any) {
	if e.Log != nil {
		e.Log(format, args...)
	}
}

func (e *Engine) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.Tick(ctx); err != nil && ctx.Err() == nil {
				e.logf("alerts: %v", err)
			}
		}
	}
}

func (e *Engine) deliver(ctx context.Context, settings map[string]string, m Message) error {
	if e.Send != nil {
		return e.Send(ctx, settings, m)
	}
	var errs []error
	for _, t := range Targets(settings, e.TelegramBase) {
		if err := t.Send(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) Tick(ctx context.Context) error {
	if e.seenRunning == nil {
		e.seenRunning = map[GuestKey]bool{}
	}
	now := e.Now()
	settings, err := e.St.Settings(ctx)
	if err != nil {
		return err
	}
	rules := RulesFrom(settings)
	if e.Rules != nil {
		rules = *e.Rules
	}
	hosts, err := e.St.Hosts(ctx)
	if err != nil {
		return err
	}
	conds, unknown := Evaluate(hosts, now, rules, e.seenRunning)
	open, err := e.St.OpenAlerts(ctx)
	if err != nil {
		return err
	}
	byKey := make(map[alertKey]store.Alert, len(open))
	for _, a := range open {
		byKey[alertKey{a.HostID, a.Kind, a.Subject}] = a
	}

	changed := false
	wrong := map[alertKey]bool{}
	for _, c := range conds {
		key := alertKey{c.HostID, c.Kind, c.Subject}
		wrong[key] = true
		a, exists := byKey[key]
		switch {
		case !exists:
			if _, err := e.St.CreateAlert(ctx, c.HostID, c.Kind, c.Subject, c.Detail, now, c.For == 0); err != nil {
				return err
			}
			changed = true
		case a.FiredAt.IsZero() && now.Sub(a.PendingSince) >= c.For:
			if err := e.St.SetAlertDetail(ctx, a.ID, c.Detail); err != nil {
				return err
			}
			if err := e.St.FireAlert(ctx, a.ID, now); err != nil {
				return err
			}
			changed = true
		}
	}
	for key, a := range byKey {
		if wrong[key] || (unknown[a.HostID] && a.Kind != KindOffline) {
			continue
		}
		if a.FiredAt.IsZero() {
			err = e.St.DeleteAlert(ctx, a.ID) // it cleared before it fired: leave no trace
		} else {
			err = e.St.ResolveAlert(ctx, a.ID, now)
		}
		if err != nil {
			return err
		}
		changed = true
	}

	e.notify(ctx, settings, now)
	if _, err := e.St.PruneAlerts(ctx, now.Add(-keepFor)); err != nil {
		return err
	}
	if changed {
		e.Bus.Publish(live.Event{Kind: live.AlertsChanged})
	}
	return nil
}

// notify sends the messages that are still owed. A failed delivery stays owed
// and is tried again on the next tick, for at most giveUpAfter.
func (e *Engine) notify(ctx context.Context, settings map[string]string, now time.Time) {
	owed, err := e.St.UnnotifiedAlerts(ctx)
	if err != nil {
		e.logf("alerts: %v", err)
		return
	}
	for _, a := range owed {
		resolved, dismissed := !a.ResolvedAt.IsZero(), !a.DismissedAt.IsZero()
		event, at := "firing", a.FiredAt
		if a.NotifiedFire {
			event, at = "resolved", a.ResolvedAt
		}
		switch {
		case event == "firing" && (resolved || dismissed):
			// It ended before anyone was told: say nothing about it at all.
			e.St.MarkNotified(ctx, a.ID, "firing")
			e.St.MarkNotified(ctx, a.ID, "resolved")
			continue
		case event == "resolved" && dismissed:
			e.St.MarkNotified(ctx, a.ID, "resolved")
			continue
		case now.Sub(at) > giveUpAfter:
			e.logf("alerts: giving up on the %q message for %s on %s", event, a.Kind, a.Host)
			e.St.MarkNotified(ctx, a.ID, event)
			continue
		}
		msg := Message{Event: event, Host: a.Host, Kind: a.Kind, Subject: a.Subject, Detail: a.Detail, Since: a.PendingSince, At: at, Hub: e.Hub}
		if err := e.deliver(ctx, settings, msg); err != nil {
			e.logf("alerts: %q message for %s on %s not delivered: %v", event, a.Kind, a.Host, err)
			continue
		}
		e.St.MarkNotified(ctx, a.ID, event)
	}
}
