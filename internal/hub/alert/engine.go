package alert

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
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
	PushSubject  string // the VAPID contact: push.Subject of the public URL
	Log          func(format string, args ...any)

	seenRunning map[GuestKey]bool
	outages     map[int64]outage // the latest silence of each host, while the Hub runs
	// delivered holds, per owed message, the targets that already took it, so
	// a retry goes only to the targets that failed. It is kept in memory: a
	// Hub restart can repeat a message once.
	delivered map[sentKey]map[string]bool
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
	targets := Targets(settings, e.TelegramBase)
	if pt, err := PushTarget(ctx, e.St, settings, e.PushSubject, e.Now(), e.logf); err != nil {
		errs = append(errs, fmt.Errorf("Push: %w", err))
	} else if pt != nil {
		targets = append(targets, *pt)
	}
	key := sentKey{m.AlertID, m.Event}
	done := e.delivered[key]
	for _, t := range targets {
		if done[t.Name] {
			continue
		}
		if err := t.Send(ctx, m); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Name, err))
			continue
		}
		if done == nil {
			if e.delivered == nil {
				e.delivered = map[sentKey]map[string]bool{}
			}
			done = map[string]bool{}
			e.delivered[key] = done
		}
		done[t.Name] = true
	}
	if len(errs) == 0 {
		delete(e.delivered, key)
	}
	return errors.Join(errs...)
}

type sentKey struct {
	alert int64
	event string
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
	var svcOpen []store.Alert
	byKey := make(map[alertKey]store.Alert, len(open))
	for _, a := range open {
		if a.ServiceID != 0 {
			svcOpen = append(svcOpen, a)
			continue
		}
		byKey[alertKey{a.HostID, a.Kind, a.Subject}] = a
	}
	names := make(map[int64]string, len(hosts))
	for _, h := range hosts {
		names[h.ID] = h.Name
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
			e.logf("alert fired: %s on %s (%s)", c.Kind, names[c.HostID], c.Detail)
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
			e.logf("alert resolved: %s on %s", a.Kind, a.Host)
		}
		if err != nil {
			return err
		}
		changed = true
	}

	e.trackOutages(hosts, unknown, now)
	svcChanged, err := e.tickServices(ctx, settings, svcOpen, now)
	if err != nil {
		return err
	}
	changed = changed || svcChanged

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
	var hostServices map[int64][]string // filled once, only when an offline message is owed
	stillOwed := map[sentKey]bool{}
	defer func() {
		for k := range e.delivered {
			if !stillOwed[k] {
				delete(e.delivered, k)
			}
		}
	}()
	for _, a := range owed {
		resolved, dismissed := !a.ResolvedAt.IsZero(), !a.DismissedAt.IsZero()
		event, at := "firing", a.FiredAt
		if a.NotifiedFire {
			event, at = "resolved", a.ResolvedAt
		}
		switch {
		case event == "firing" && (resolved || dismissed):
			// It ended before anyone was told: say nothing about it at all.
			e.St.MarkSkipped(ctx, a.ID)
			continue
		case event == "resolved" && dismissed:
			e.St.MarkNotified(ctx, a.ID, "resolved")
			continue
		case now.Sub(at) > giveUpAfter:
			e.logf("alerts: giving up on the %q message for %s on %s", event, a.Kind, who(a))
			e.St.MarkNotified(ctx, a.ID, event)
			continue
		}
		msg := Message{Event: event, Host: a.Host, Kind: a.Kind, Subject: a.Subject, Detail: a.Detail, Since: a.PendingSince, At: at, Hub: e.Hub,
			Service: a.Service, ServiceID: a.ServiceID, AlertID: a.ID, ServiceHost: domain(a.ServiceURL)}
		if a.Kind == KindOffline {
			if hostServices == nil {
				hostServices = e.servicesByHost(ctx)
			}
			msg.HostServices = hostServices[a.HostID]
		}
		if err := e.deliver(ctx, settings, msg); err != nil {
			stillOwed[sentKey{a.ID, event}] = true
			e.logf("alerts: %q message for %s on %s not delivered: %v", event, a.Kind, who(a), err)
			continue
		}
		e.logf("alerts: %q message for %s on %s delivered", event, a.Kind, who(a))
		e.St.MarkNotified(ctx, a.ID, event)
	}
}

type svcKey struct {
	service       int64
	kind, subject string
}

// tickServices raises, fires and ends the alerts of the services, as Tick does
// for hosts. An alert whose condition is gone ends with a message only when
// the service is fine again; otherwise the message would be false.
func (e *Engine) tickServices(ctx context.Context, settings map[string]string, open []store.Alert, now time.Time) (bool, error) {
	services, err := e.St.Services(ctx)
	if err != nil {
		return false, err
	}
	failN, err := strconv.Atoi(settings["svc_fail_n"])
	if err != nil || failN < 1 {
		failN = 3
	}
	byID := make(map[int64]store.Service, len(services))
	held := map[int64]bool{}
	for _, sv := range services {
		byID[sv.ID] = sv
		o, ok := e.outages[sv.HostID]
		if heldBy(sv, o, ok, failN) {
			held[sv.ID] = true
		}
	}
	byKey := make(map[svcKey]store.Alert, len(open))
	for _, a := range open {
		byKey[svcKey{a.ServiceID, a.Kind, a.Subject}] = a
	}
	changed := false
	wrong := map[svcKey]bool{}
	for _, c := range EvaluateServices(services, now, ServiceRulesFrom(settings), held) {
		key := svcKey{c.ServiceID, c.Kind, c.Subject}
		wrong[key] = true
		a, exists := byKey[key]
		switch {
		case !exists:
			if _, err := e.St.CreateServiceAlert(ctx, c.ServiceID, c.Kind, c.Subject, c.Detail, now, c.For == 0); err != nil {
				return changed, err
			}
			if c.For == 0 {
				e.logf("alert fired: %s on service %s (%s)", c.Kind, svcName(byID[c.ServiceID]), c.Detail)
			}
			changed = true
		case a.FiredAt.IsZero() && now.Sub(a.PendingSince) >= c.For:
			if err := e.St.SetAlertDetail(ctx, a.ID, c.Detail); err != nil {
				return changed, err
			}
			if err := e.St.FireAlert(ctx, a.ID, now); err != nil {
				return changed, err
			}
			e.logf("alert fired: %s on service %s (%s)", c.Kind, svcName(byID[c.ServiceID]), c.Detail)
			changed = true
		case !a.FiredAt.IsZero() && (c.Kind == KindSvcDown || c.Kind == KindSvcCert) && a.Detail != c.Detail:
			// The latest failure or day count, so the Alerts page says what is true now.
			if err := e.St.SetAlertDetail(ctx, a.ID, c.Detail); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	for key, a := range byKey {
		if wrong[key] {
			continue
		}
		sv, ok := byID[a.ServiceID]
		if ok && held[sv.ID] && (a.Kind == KindSvcDown || a.Kind == KindSvcSlow) {
			continue // its host's outage explains it; the alert stays as it is
		}
		switch {
		case a.FiredAt.IsZero():
			err = e.St.DeleteAlert(ctx, a.ID)
		case ok && fineAgain(a, sv):
			err = e.St.ResolveAlert(ctx, a.ID, now)
			e.logf("alert resolved: %s on service %s", a.Kind, svcName(sv))
		default:
			err = e.St.EndAlertQuietly(ctx, a.ID, now)
		}
		if err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// fineAgain: the condition of an ended alert is gone because the service
// works again, not because it was paused, re-addressed or its warning moved.
func fineAgain(a store.Alert, sv store.Service) bool {
	switch a.Kind {
	case KindSvcDown:
		return sv.State == "online" || sv.State == "degraded"
	case KindSvcSlow:
		return sv.State == "online"
	case KindSvcCert:
		return sv.Enabled && sv.CertExpiresAt != 0 && sv.CertExpiresAt != certExpiry(a.Subject)
	}
	return false
}

// domain is the host part of a service URL; its path and query can hold a
// token and never appear in messages or logs.
func domain(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host
	}
	return ""
}

func svcName(sv store.Service) string { return sv.Name + " (" + domain(sv.URL) + ")" }

// who names an alert's owner in log lines.
func who(a store.Alert) string {
	if a.ServiceID != 0 {
		return "service " + a.Service + " (" + domain(a.ServiceURL) + ")"
	}
	return a.Host
}

// servicesByHost names the enabled services of each host, sorted, for the
// host's offline message.
func (e *Engine) servicesByHost(ctx context.Context) map[int64][]string {
	out := map[int64][]string{}
	services, err := e.St.Services(ctx)
	if err != nil {
		e.logf("alerts: %v", err)
		return out
	}
	for _, sv := range services {
		if sv.Enabled && sv.HostID != 0 {
			out[sv.HostID] = append(out[sv.HostID], sv.Name)
		}
	}
	for _, names := range out {
		sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	}
	return out
}

// trackOutages remembers when each host went quiet and when it came back.
// A host that never reported has no outage: nothing it ran was ever seen.
func (e *Engine) trackOutages(hosts []store.Host, silent map[int64]bool, now time.Time) {
	if e.outages == nil {
		e.outages = map[int64]outage{}
	}
	for _, h := range hosts {
		o, known := e.outages[h.ID]
		switch {
		case silent[h.ID] && !h.LastSeen.IsZero():
			if !known || !o.to.IsZero() {
				e.outages[h.ID] = outage{from: h.LastSeen}
			}
		case known && o.to.IsZero():
			o.to = now
			e.outages[h.ID] = o
		}
	}
}
