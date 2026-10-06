package alert

import (
	"strconv"
	"strings"
	"time"

	"fleetwatch/internal/hub/store"
)

const (
	KindSvcDown = "svc_down"
	KindSvcSlow = "svc_slow"
	KindSvcCert = "svc_cert"
)

var defaultCertDays = []int{30, 14, 7, 1}

// ServiceRules: the certificate warning days, from large to small, and
// whether a slow service raises an alert after SlowFor.
type ServiceRules struct {
	CertDays  []int
	SlowAlert bool
	SlowFor   time.Duration
}

// ParseCertDays reads "30, 14, 7, 1": 1 to 6 whole numbers from 1 to 365,
// each smaller than the one before.
func ParseCertDays(s string) ([]int, bool) {
	parts := strings.Split(s, ",")
	if len(parts) > 6 {
		return nil, false
	}
	var out []int
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 365 || (len(out) > 0 && n >= out[len(out)-1]) {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// ServiceRulesFrom reads the rules from settings; an unreadable day list
// keeps the default.
func ServiceRulesFrom(settings map[string]string) ServiceRules {
	r := ServiceRules{CertDays: defaultCertDays, SlowAlert: settings["svc_slow_alert"] == "1", SlowFor: 5 * time.Minute}
	if days, ok := ParseCertDays(settings["svc_cert_days"]); ok {
		r.CertDays = days
	}
	return r
}

// ServiceCondition is something wrong with a service right now.
type ServiceCondition struct {
	ServiceID             int64
	Kind, Subject, Detail string
	For                   time.Duration
}

// certSubject keys a certificate alert by its warning and by the certificate,
// so a renewed certificate ends the alert with a message and a step to the
// next warning ends it without one.
func certSubject(threshold string, expires int64) string {
	return threshold + "@" + strconv.FormatInt(expires, 10)
}

func certExpiry(subject string) int64 {
	_, ts, ok := strings.Cut(subject, "@")
	if !ok {
		return 0
	}
	n, _ := strconv.ParseInt(ts, 10, 64)
	return n
}

// EvaluateServices lists what is wrong with the enabled services now. A held
// service (by id) raises no down or slow condition: its host's outage
// explains it, and the host's own alert speaks for it.
func EvaluateServices(services []store.Service, now time.Time, r ServiceRules, held map[int64]bool) []ServiceCondition {
	var conds []ServiceCondition
	for _, sv := range services {
		if !sv.Enabled {
			continue
		}
		switch {
		case held[sv.ID]:
		case sv.State == "down":
			conds = append(conds, ServiceCondition{ServiceID: sv.ID, Kind: KindSvcDown, Detail: sv.LastError})
		case sv.State == "degraded" && r.SlowAlert:
			conds = append(conds, ServiceCondition{ServiceID: sv.ID, Kind: KindSvcSlow, Detail: msText(sv.LastMs), For: r.SlowFor})
		}
		if c, ok := certCondition(sv, now, r.CertDays); ok {
			conds = append(conds, c)
		}
	}
	return conds
}

func certCondition(sv store.Service, now time.Time, days []int) (ServiceCondition, bool) {
	if sv.CertExpiresAt == 0 || !strings.HasPrefix(strings.ToLower(sv.URL), "https://") || len(days) == 0 {
		return ServiceCondition{}, false
	}
	date := time.Unix(sv.CertExpiresAt, 0).Format("2 Jan 2006") // the Hub's zone, as in Since and Ended
	left := sv.CertExpiresAt - now.Unix()
	if left <= 0 {
		return ServiceCondition{ServiceID: sv.ID, Kind: KindSvcCert, Subject: certSubject("expired", sv.CertExpiresAt), Detail: "expired " + date}, true
	}
	whole := int(left / 86400)
	threshold := 0
	for _, d := range days { // large to small: the last that holds is the smallest
		if whole <= d {
			threshold = d
		}
	}
	if threshold == 0 {
		return ServiceCondition{}, false
	}
	return ServiceCondition{ServiceID: sv.ID, Kind: KindSvcCert, Subject: certSubject(strconv.Itoa(threshold), sv.CertExpiresAt),
		Detail: daysText(whole) + ", " + date}, true
}

func daysText(n int) string {
	if n == 0 {
		return "less than a day"
	}
	if n == 1 {
		return "1 day"
	}
	return strconv.Itoa(n) + " days"
}

// msText prints a response time with thousands separators: "1,842 ms".
func msText(ms int) string {
	s := strconv.Itoa(ms)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s + " ms"
}

// outage is a host's silence: from its last report before it, to the tick
// that saw it report again (zero while it lasts).
type outage struct{ from, to time.Time }

// heldBy says whether a down or slow service is explained by its host's
// outage: it went down around the time the host went quiet. After the host
// returns the hold lasts until a check made since then has failed, so a
// rebooted host's services recover without a message. A failure long after
// the host went quiet (a dead agent on a running host) is not held.
func heldBy(sv store.Service, o outage, ok bool, failN int) bool {
	if !ok || sv.HostID == 0 || (sv.State != "down" && sv.State != "degraded") {
		return false
	}
	window := time.Duration(sv.IntervalS*(failN+1))*time.Second + 2*time.Minute
	since := time.Unix(sv.StateSince, 0)
	if since.Before(o.from.Add(-2*time.Minute)) || since.After(o.from.Add(window)) {
		return false
	}
	if o.to.IsZero() {
		return true
	}
	return !(sv.CheckedAt > o.to.Unix() && sv.OkStreak == 0)
}
