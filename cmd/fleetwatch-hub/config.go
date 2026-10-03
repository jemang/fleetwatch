package main

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/store"
)

type Config struct {
	AdminPassword string
	DataDir       string
	DLDir         string // the signed agent files the Hub hands out
	Listen        string
	PublicURL     string
	TLSCert       string
	TLSKey        string
	Retention     store.Retention
	// TrustedProxies may set X-Forwarded-For; limits then count on the
	// address it names.
	TrustedProxies []netip.Prefix
}

func (c Config) TLS() bool { return c.TLSCert != "" }

// SecureCookies is true when browsers reach the Hub over HTTPS, either
// directly or through a proxy.
func (c Config) SecureCookies() bool { return c.TLS() || strings.HasPrefix(c.PublicURL, "https://") }

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func LoadConfig(env func(string) string) (Config, error) {
	c := Config{
		AdminPassword: env("FLEETWATCH_ADMIN_PASSWORD"),
		DataDir:       orDefault(env("FLEETWATCH_DATA_DIR"), "/data"),
		DLDir:         orDefault(env("FLEETWATCH_DL_DIR"), "/usr/share/fleetwatch/dl"),
		Listen:        orDefault(env("FLEETWATCH_LISTEN"), ":8080"),
		PublicURL:     strings.TrimRight(env("FLEETWATCH_PUBLIC_URL"), "/"),
		TLSCert:       env("FLEETWATCH_TLS_CERT"),
		TLSKey:        env("FLEETWATCH_TLS_KEY"),
		Retention:     store.DefaultRetention,
	}
	for name, dst := range map[string]*time.Duration{
		"FLEETWATCH_RETENTION_RAW": &c.Retention.Raw, "FLEETWATCH_RETENTION_1M": &c.Retention.Min1,
		"FLEETWATCH_RETENTION_5M": &c.Retention.Min5, "FLEETWATCH_RETENTION_1H": &c.Retention.Hour1,
	} {
		v := env(name)
		if v == "" {
			continue
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return c, fmt.Errorf("%s must be a positive duration such as 24h, got %q", name, v)
		}
		*dst = d
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return c, errors.New("FLEETWATCH_PUBLIC_URL must be the http(s) URL that agents use to reach the Hub, for example https://monitor.example.com")
	}
	if c.TrustedProxies, err = limit.ParsePrefixes(env("FLEETWATCH_TRUSTED_PROXIES")); err != nil {
		return c, fmt.Errorf("FLEETWATCH_TRUSTED_PROXIES: %v", err)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return c, errors.New("set both FLEETWATCH_TLS_CERT and FLEETWATCH_TLS_KEY, or neither")
	}
	return c, nil
}
