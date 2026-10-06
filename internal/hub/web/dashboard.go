package web

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"fleetwatch/internal/hub/alert"
	"fleetwatch/internal/hub/store"
)

// recentShown is how many incidents the Dashboard lists.
const recentShown = 8

type DashTiles struct{ Total, Online, Down, Slow, Paused int }

type NameLink struct{ Name, Href string }

// AttentionItem is one line of the Dashboard's Attention list. Since, when
// set, is shown live as "for 8 minutes" after Text.
type AttentionItem struct {
	Tag, Title, Href, Text, After string
	Since                         int64
	Names                         []NameLink
}

type IncidentLine struct {
	ServiceID        int64
	Service          string
	Start, End       int64
	Duration, Reason string
}

type DashPanel struct {
	Tiles     DashTiles
	Attention []AttentionItem
	Incidents []IncidentLine
}

type dashboardData struct {
	chrome
	DashPanel
}

func plural1(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// buildDashboard puts what needs attention first: offline hosts with the
// services they take down, down services, other firing alerts, slow services.
func buildDashboard(services []store.Service, rows []HostRow, alerts []store.Alert, incidents []store.RecentIncident) DashPanel {
	var d DashPanel
	offline := map[int64]HostRow{}
	for _, r := range rows {
		if r.Status() == "offline" {
			offline[r.ID] = r
		}
	}
	under := map[int64][]NameLink{}
	var down, slow []AttentionItem
	for _, sv := range services {
		d.Tiles.Total++
		href := "/services/" + strconv.FormatInt(sv.ID, 10)
		switch {
		case !sv.Enabled:
			d.Tiles.Paused++
		case sv.State == "online":
			d.Tiles.Online++
		case sv.State == "degraded":
			d.Tiles.Online++
			d.Tiles.Slow++
			slow = append(slow, AttentionItem{Tag: "SLOW", Title: sv.Name, Href: href, Text: msText(sv.LastMs) + " response time"})
		case sv.State == "down":
			d.Tiles.Down++
			if _, ok := offline[sv.HostID]; ok && sv.HostID != 0 {
				under[sv.HostID] = append(under[sv.HostID], NameLink{sv.Name, href})
				continue
			}
			item := AttentionItem{Tag: "DOWN", Title: sv.Name, Href: href, Text: "unavailable", Since: sv.StateSince}
			if sv.LastError != "" {
				item.After = sv.LastError
			}
			down = append(down, item)
		}
	}
	hostIDs := make([]int64, 0, len(offline))
	for id := range offline {
		hostIDs = append(hostIDs, id)
	}
	sort.Slice(hostIDs, func(i, j int) bool {
		return strings.ToLower(offline[hostIDs[i]].Name) < strings.ToLower(offline[hostIDs[j]].Name)
	})
	for _, id := range hostIDs {
		r := offline[id]
		item := AttentionItem{Tag: "OFFLINE", Title: r.Name, Href: "/hosts/" + strconv.FormatInt(id, 10)}
		if names := under[id]; len(names) > 0 {
			item.Text = plural1(len(names), "service") + " unavailable because host " + r.Name + " is offline:"
			item.Names = names
		} else {
			item.Text, item.Since = "not reporting", r.LastSeenUnix
		}
		d.Attention = append(d.Attention, item)
	}
	d.Attention = append(d.Attention, down...)
	for _, a := range alerts {
		if a.FiredAt.IsZero() || !a.DismissedAt.IsZero() || !a.ResolvedAt.IsZero() {
			continue
		}
		switch a.Kind {
		case alert.KindOffline, alert.KindSvcDown, alert.KindSvcSlow:
			continue // shown above
		}
		title := alert.Title[a.Kind]
		if title == "" {
			title = a.Kind
		}
		who := a.Host
		if a.ServiceID != 0 {
			who = a.Service
		}
		text := who
		if a.Detail != "" {
			text += " · " + a.Detail
		}
		d.Attention = append(d.Attention, AttentionItem{Tag: "ALERT", Title: title, Href: "/alerts/" + strconv.FormatInt(a.ID, 10), Text: text})
	}
	d.Attention = append(d.Attention, slow...)
	for _, in := range incidents {
		line := IncidentLine{ServiceID: in.ServiceID, Service: in.ServiceName, Start: in.Started.Unix(), Reason: in.Reason}
		if !in.Ended.IsZero() {
			line.End, line.Duration = in.Ended.Unix(), durationText(in.Ended.Sub(in.Started))
		}
		d.Incidents = append(d.Incidents, line)
	}
	return d
}

func (w *Web) dashboardPanelData(r *http.Request, rows []HostRow) (DashPanel, error) {
	ctx := r.Context()
	services, err := w.st.Services(ctx)
	if err != nil {
		return DashPanel{}, err
	}
	alerts, err := w.st.OpenAlerts(ctx)
	if err != nil {
		return DashPanel{}, err
	}
	incidents, err := w.st.RecentIncidents(ctx, recentShown)
	if err != nil {
		return DashPanel{}, err
	}
	return buildDashboard(services, rows, alerts, incidents), nil
}

func (w *Web) dashboardPage(rw http.ResponseWriter, r *http.Request) {
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	p, err := w.dashboardPanelData(r, rows)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "dashboard", dashboardData{chrome: w.chrome(r, "dashboard", rows), DashPanel: p})
}

// dashboardPanel is the live part of the Dashboard.
func (w *Web) dashboardPanel(rw http.ResponseWriter, r *http.Request) {
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	p, err := w.dashboardPanelData(r, rows)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.render(rw, http.StatusOK, "dashpanel", p)
}

// searchShown is how many matches of each kind the search lists.
const searchShown = 8

type SearchHit struct{ Name, Note, Href string }

type searchData struct {
	Q               string
	Services, Hosts []SearchHit
}

// search finds services by name, domain, group and description, and hosts by
// name, hostname and address. A URL's path and query are never searched or shown.
func (w *Web) search(rw http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	d := searchData{Q: q}
	if q == "" {
		w.render(rw, http.StatusOK, "searchresults", d)
		return
	}
	services, err := w.st.Services(r.Context())
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	for _, sv := range services {
		c := serviceCard(sv)
		if len(d.Services) < searchShown && strings.Contains(c.Search, q) {
			note := shownURL(sv.URL)
			if sv.Group != "" {
				note += " · " + sv.Group
			}
			d.Services = append(d.Services, SearchHit{Name: sv.Name, Note: note, Href: "/services/" + strconv.FormatInt(sv.ID, 10)})
		}
	}
	rows, err := w.rows(r)
	if err != nil {
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	for _, h := range rows {
		hay := strings.ToLower(h.Name + " " + h.Hostname + " " + h.IP + " " + h.IPTitle)
		if len(d.Hosts) < searchShown && strings.Contains(hay, q) {
			d.Hosts = append(d.Hosts, SearchHit{Name: h.Name, Note: h.IP, Href: "/hosts/" + strconv.FormatInt(h.ID, 10)})
		}
	}
	w.render(rw, http.StatusOK, "searchresults", d)
}
