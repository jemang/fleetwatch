package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func noEnv(string) string { return "" }

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadFileAndDefaults(t *testing.T) {
	c, err := Load(write(t, "hub_url: https://hub.example.com\nagent_id: \"7\"\nagent_token: secret\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.HubURL != "https://hub.example.com" || c.AgentID != "7" || c.AgentToken != "secret" || c.Interval != 15*time.Second || c.AllowInsecureHTTP {
		t.Errorf("config = %+v", c)
	}
}

func TestEnvOverridesFileAndWorksWithoutFile(t *testing.T) {
	env := func(k string) string {
		return map[string]string{
			"FLEETWATCH_HUB_URL": "http://hub:8080", "FLEETWATCH_AGENT_TOKEN": "tok",
			"FLEETWATCH_INTERVAL": "20s", "FLEETWATCH_ALLOW_INSECURE_HTTP": "true",
		}[k]
	}
	c, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), env)
	if err != nil {
		t.Fatal(err)
	}
	if c.HubURL != "http://hub:8080" || c.AgentToken != "tok" || c.Interval != 20*time.Second || !c.AllowInsecureHTTP {
		t.Errorf("config = %+v", c)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]string{
		"hub_url: http://hub:8080\nagent_token: t\n":             "allow_insecure_http",
		"hub_url: ftp://hub\nagent_token: t\n":                   "scheme",
		"hub_url: https://hub\n":                                 "agent_token",
		"hub_url: https://hub\nagent_token: t\ninterval: 2s\n":   "minimum",
		"hub_url: https://hub\nagent_token: t\ninterval: soon\n": "interval",
		"agent_token: t\n":                                       "hub_url",
	}
	for content, want := range cases {
		_, err := Load(write(t, content), noEnv)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("config %q: error = %v, want it to mention %q", content, err, want)
		}
	}
	if _, err := Load(write(t, "hub_url: http://hub:8080\nagent_token: t\nallow_insecure_http: true\n"), noEnv); err != nil {
		t.Errorf("http with explicit opt-in must load: %v", err)
	}
}

func TestSaveWritesMode0600AndRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "agent.yaml")
	in := Config{HubURL: "https://hub.example.com", AgentID: "3", AgentToken: "secret", Interval: 15 * time.Second}
	if err := Save(p, in); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v; want 0600", st.Mode().Perm(), err)
	}
	out, err := Load(p, noEnv)
	if err != nil || !reflect.DeepEqual(out, in) {
		t.Errorf("round trip = %+v, %v; want %+v", out, err, in)
	}
}

func TestProxmoxTokenFromFileEnvAndRoundTrip(t *testing.T) {
	c, err := Load(write(t, "hub_url: https://hub\nagent_token: t\nproxmox:\n  token_id: fleetwatch@pve!agent\n  token_secret: s3cret\n"), noEnv)
	if err != nil || c.Proxmox != (Proxmox{TokenID: "fleetwatch@pve!agent", TokenSecret: "s3cret"}) {
		t.Fatalf("proxmox from file = %+v, %v", c.Proxmox, err)
	}
	env := func(k string) string {
		return map[string]string{"FLEETWATCH_HUB_URL": "https://hub", "FLEETWATCH_AGENT_TOKEN": "t",
			"FLEETWATCH_PVE_TOKEN_ID": "a@pve!b", "FLEETWATCH_PVE_TOKEN_SECRET": "x", "FLEETWATCH_PVE_API_URL": "https://10.0.0.1:8006", "FLEETWATCH_PVE_CA_FILE": "/tmp/ca.pem"}[k]
	}
	c, err = Load(filepath.Join(t.TempDir(), "missing.yaml"), env)
	want := Proxmox{TokenID: "a@pve!b", TokenSecret: "x", APIURL: "https://10.0.0.1:8006", CAFile: "/tmp/ca.pem"}
	if err != nil || c.Proxmox != want {
		t.Fatalf("proxmox from environment = %+v, %v", c.Proxmox, err)
	}
	p := filepath.Join(t.TempDir(), "agent.yaml")
	Save(p, c)
	if back, err := Load(p, noEnv); err != nil || back.Proxmox != want {
		t.Errorf("proxmox after save and load = %+v, %v", back.Proxmox, err)
	}
	plain := filepath.Join(t.TempDir(), "plain.yaml")
	Save(plain, Config{HubURL: "https://hub", AgentToken: "t", Interval: 15 * time.Second})
	if b, _ := os.ReadFile(plain); strings.Contains(string(b), "proxmox") {
		t.Errorf("no proxmox section without a token:\n%s", b)
	}
}

func TestServicesFromFileEnvAndRoundTrip(t *testing.T) {
	c, err := Load(write(t, "hub_url: https://hub\nagent_token: t\nservices:\n  - nginx\n  - backup.timer\n  - \" docker \"\n"), noEnv)
	if err != nil || !reflect.DeepEqual(c.Services, []string{"nginx.service", "backup.timer", "docker.service"}) {
		t.Fatalf("services from file = %q, %v; names without a suffix mean .service", c.Services, err)
	}
	env := func(k string) string {
		return map[string]string{"FLEETWATCH_HUB_URL": "https://hub", "FLEETWATCH_AGENT_TOKEN": "t", "FLEETWATCH_SERVICES": "ssh, cron,,docker.service"}[k]
	}
	c, err = Load(filepath.Join(t.TempDir(), "missing.yaml"), env)
	if err != nil || !reflect.DeepEqual(c.Services, []string{"ssh.service", "cron.service", "docker.service"}) {
		t.Fatalf("services from environment = %q, %v", c.Services, err)
	}
	p := filepath.Join(t.TempDir(), "agent.yaml")
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p, noEnv)
	if err != nil || !reflect.DeepEqual(back.Services, c.Services) {
		t.Errorf("services after save and load = %q, %v", back.Services, err)
	}
	plain, _ := Load(write(t, "hub_url: https://hub\nagent_token: t\n"), noEnv)
	if plain.Services != nil {
		t.Errorf("no services configured must stay nil, got %q", plain.Services)
	}
}
