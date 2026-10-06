package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"fleetwatch/internal/hub/store"
)

type IncidentRow struct {
	Start, End        int64 // End 0 while it lasts
	Duration          string
	Reason, EndReason string // EndReason "" when recovered
}

type serviceDetail struct {
	chrome
	C                      ServiceCard
	S                      store.Service
	ShownURL               string // scheme and host only
	Up24, Up7, Up30, Avg24 string
	Cert                   CertInfo
	HostOffline            bool // the related host is not reporting
	Bar                    []BarBlock
	Incidents              []IncidentRow
}

func (w *Web) serviceDetailData(r *http.Request, sv store.Service) (serviceDetail, error) {
	ctx, now := r.Context(), w.now()
	d := serviceDetail{C: serviceCard(sv), S: sv, ShownURL: shownURL(sv.URL), Cert: certInfo(sv, now)}
	for _, u := range []struct {
		dst  *string
		span time.Duration
	}{{&d.Up24, 24 * time.Hour}, {&d.Up7, 7 * 24 * time.Hour}, {&d.Up30, uptimeSpan}} {
		st, err := w.st.CheckStatsFor(ctx, sv.ID, store.HourStart(now.Add(-u.span)))
		if err != nil {
			return d, err
		}
		*u.dst = uptimeText(st)
		if u.span == 24*time.Hour {
			d.Avg24 = avgMsText(st)
		}
	}
	rows, err := w.st.RawChecks(ctx, sv.ID, now.Add(-24*time.Hour))
	if err != nil {
		return d, err
	}
	d.Bar = availabilityBar(rows, now)
	if sv.HostID != 0 {
		if h, err := w.st.Host(ctx, sv.HostID); err == nil {
			d.HostOffline = BuildRow(h, now).Status() == "offline"
		}
	}
	inc, err := w.st.Incidents(ctx, sv.ID, 10)
	if err != nil {
		return d, err
	}
	for _, in := range inc {
		row := IncidentRow{Start: in.Started.Unix(), Reason: in.Reason}
		if !in.Ended.IsZero() {
			row.End, row.Duration = in.Ended.Unix(), durationText(in.Ended.Sub(in.Started))
			if in.EndReason != "recovered" {
				row.EndReason = in.EndReason
			}
		}
		d.Incidents = append(d.Incidents, row)
	}
	return d, nil
}

// shownURL is the address as text on the page: scheme and host, never the
// path or query, which can hold a token.
func shownURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "?"
}

func (w *Web) servicePage(rw http.ResponseWriter, r *http.Request) {
	sv, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	d, err := w.serviceDetailData(r, sv)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	d.chrome = w.chrome(r, "services", rows)
	w.render(rw, http.StatusOK, "service", d)
}

// servicePanel is the live part of the detail page.
func (w *Web) servicePanel(rw http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	// Deleted in another tab: the page goes back to the list.
	if _, err := w.st.Service(r.Context(), id); errors.Is(err, store.ErrNotFound) && r.Header.Get("HX-Request") == "true" {
		rw.Header().Set("HX-Redirect", "/services")
		return
	}
	sv, ok := w.serviceFromPath(rw, r)
	if !ok {
		return
	}
	d, err := w.serviceDetailData(r, sv)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "svcpanel", d)
}
