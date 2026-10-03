// Package config loads and saves the agent configuration.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"fleetwatch/internal/agent/systemd"
)

const (
	DefaultPath     = "/etc/fleetwatch/agent.yaml"
	DefaultInterval = 15 * time.Second
	MinInterval     = 5 * time.Second
)

type Config struct {
	HubURL            string
	AgentID           string
	AgentToken        string
	Interval          time.Duration
	AllowInsecureHTTP bool
	Services          []string // systemd unit names, already completed with a suffix
	Proxmox           Proxmox
}

// Proxmox holds the read-only API token of the local node. Empty APIURL and
// CAFile mean the defaults of package pve.
type Proxmox struct {
	TokenID     string `yaml:"token_id,omitempty"`
	TokenSecret string `yaml:"token_secret,omitempty"`
	APIURL      string `yaml:"api_url,omitempty"`
	CAFile      string `yaml:"ca_file,omitempty"`
}

type file struct {
	HubURL            string   `yaml:"hub_url"`
	AgentID           string   `yaml:"agent_id"`
	AgentToken        string   `yaml:"agent_token"`
	Interval          string   `yaml:"interval"`
	AllowInsecureHTTP bool     `yaml:"allow_insecure_http"`
	Services          []string `yaml:"services,omitempty"`
	Proxmox           *Proxmox `yaml:"proxmox,omitempty"`
}

// UnitNames trims the names, drops empty ones and completes a bare name with
// ".service".
func UnitNames(names []string) []string {
	var out []string
	for _, n := range names {
		if n = systemd.UnitName(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func Load(path string, env func(string) string) (Config, error) {
	var f file
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(b, &f); err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", path, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return Config{}, err
	}
	if v := env("FLEETWATCH_HUB_URL"); v != "" {
		f.HubURL = v
	}
	if v := env("FLEETWATCH_AGENT_TOKEN"); v != "" {
		f.AgentToken = v
	}
	if v := env("FLEETWATCH_INTERVAL"); v != "" {
		f.Interval = v
	}
	if v := env("FLEETWATCH_SERVICES"); v != "" {
		f.Services = strings.Split(v, ",")
	}
	c := Config{HubURL: f.HubURL, AgentID: f.AgentID, AgentToken: f.AgentToken, Interval: DefaultInterval,
		AllowInsecureHTTP: f.AllowInsecureHTTP, Services: UnitNames(f.Services)}
	if f.Proxmox != nil {
		c.Proxmox = *f.Proxmox
	}
	for name, dst := range map[string]*string{
		"FLEETWATCH_PVE_TOKEN_ID": &c.Proxmox.TokenID, "FLEETWATCH_PVE_TOKEN_SECRET": &c.Proxmox.TokenSecret,
		"FLEETWATCH_PVE_API_URL": &c.Proxmox.APIURL, "FLEETWATCH_PVE_CA_FILE": &c.Proxmox.CAFile,
	} {
		if v := env(name); v != "" {
			*dst = v
		}
	}
	if v := env("FLEETWATCH_ALLOW_INSECURE_HTTP"); v != "" {
		if c.AllowInsecureHTTP, err = strconv.ParseBool(v); err != nil {
			return Config{}, fmt.Errorf("config: FLEETWATCH_ALLOW_INSECURE_HTTP: %w", err)
		}
	}
	if f.Interval != "" {
		if c.Interval, err = time.ParseDuration(f.Interval); err != nil {
			return Config{}, fmt.Errorf("config: interval: %w", err)
		}
	}
	return c, c.Validate()
}

func CheckHubURL(hubURL string, allowInsecure bool) error {
	u, err := url.Parse(hubURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("config: hub_url %q is not a valid URL", hubURL)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure {
			return nil
		}
		return errors.New("config: hub_url uses http://, which sends the agent token unencrypted; set allow_insecure_http: true to permit it")
	}
	return fmt.Errorf("config: hub_url scheme %q is not supported", u.Scheme)
}

func (c Config) Validate() error {
	if err := CheckHubURL(c.HubURL, c.AllowInsecureHTTP); err != nil {
		return err
	}
	if c.AgentToken == "" {
		return errors.New("config: agent_token is empty")
	}
	if c.Interval < MinInterval {
		return fmt.Errorf("config: interval %s is below the %s minimum", c.Interval, MinInterval)
	}
	return nil
}

// Save writes the config with mode 0600 because it holds the agent token.
func Save(path string, c Config) error {
	f := file{HubURL: c.HubURL, AgentID: c.AgentID, AgentToken: c.AgentToken, Interval: c.Interval.String(),
		AllowInsecureHTTP: c.AllowInsecureHTTP, Services: c.Services}
	if c.Proxmox != (Proxmox{}) {
		f.Proxmox = &c.Proxmox
	}
	b, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
