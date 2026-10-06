package web

import (
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"fleetwatch/internal/hub/store"
)

// ServiceCard is one service on the Services page.
type ServiceCard struct {
	ID                               int64
	Name, URL, Group, Letter, Search string
	IconURL                          string // "" shows the letter tile
	Paused                           bool
}

type ServiceGroup struct {
	Name  string
	Cards []ServiceCard
}

const ungrouped = "Ungrouped"

func serviceCard(sv store.Service) ServiceCard {
	c := ServiceCard{ID: sv.ID, Name: sv.Name, URL: sv.URL, Group: sv.Group, Paused: !sv.Enabled}
	if r, _ := utf8.DecodeRuneInString(sv.Name); r != utf8.RuneError {
		c.Letter = string(unicode.ToUpper(r))
	}
	if sv.IconAt != 0 {
		c.IconURL = "/services/" + strconv.FormatInt(sv.ID, 10) + "/icon?v=" + strconv.FormatInt(sv.IconAt, 10)
	}
	host := ""
	if u, err := url.Parse(sv.URL); err == nil {
		host = u.Host
	}
	c.Search = strings.ToLower(strings.Join(strings.Fields(sv.Name+" "+host+" "+sv.Group+" "+sv.Description), " "))
	return c
}

// BuildServiceGroups keeps the store's order: grouped services by group, the
// ungrouped ones last.
func BuildServiceGroups(list []store.Service) []ServiceGroup {
	var out []ServiceGroup
	for _, sv := range list {
		name := sv.Group
		if name == "" {
			name = ungrouped
		}
		if len(out) == 0 || out[len(out)-1].Name != name {
			out = append(out, ServiceGroup{Name: name})
		}
		out[len(out)-1].Cards = append(out[len(out)-1].Cards, serviceCard(sv))
	}
	return out
}
