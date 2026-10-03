package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fleetwatch/internal/protocol"
	"fleetwatch/internal/release"
)

func TestEnrollWritesConfig(t *testing.T) {
	var got protocol.EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "9", AgentToken: "permanent"})
	}))
	defer srv.Close()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "proc/sys/kernel"), 0o755)
	os.WriteFile(filepath.Join(root, "proc/sys/kernel/hostname"), []byte("web-01\n"), 0o644)
	cfg := filepath.Join(t.TempDir(), "agent.yaml")

	var out, errOut bytes.Buffer
	code := run([]string{"enroll", "--hub", srv.URL, "--token", "once", "--config", cfg, "--proc-root", root}, &out, &errOut)
	if code == 0 || !strings.Contains(errOut.String(), "allow_insecure_http") {
		t.Fatalf("http:// Hub without the flag must be refused: code %d, stderr %q", code, errOut.String())
	}
	if _, err := os.Stat(cfg); err == nil {
		t.Fatal("a refused enrollment must not write a config")
	}

	code = run([]string{"enroll", "--hub", srv.URL, "--token", "once", "--config", cfg, "--proc-root", root, "--allow-insecure-http", "--services", "nginx, docker", "--pve-token-id", "fleetwatch@pve!agent", "--pve-token-secret", "pvesecret"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("enroll failed: %s", errOut.String())
	}
	if got.Token != "once" || got.Hostname != "web-01" || got.ProtocolVersion != protocol.Version {
		t.Errorf("enroll request = %+v", got)
	}
	b, _ := os.ReadFile(cfg)
	for _, want := range []string{"agent_token: permanent", "agent_id: \"9\"", "allow_insecure_http: true", "interval: 15s", "- nginx.service", "- docker.service", "token_id: fleetwatch@pve!agent", "token_secret: pvesecret"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("config is missing %q:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "once") {
		t.Error("the enrollment token must not be stored")
	}
}

func TestUnknownCommandAndVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"reboot"}, &out, &errOut); code != 2 {
		t.Errorf("unknown command: code %d, want 2", code)
	}
	if code := run([]string{"version"}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "0.1.0") {
		t.Errorf("version: code %d, out %q", code, out.String())
	}
}

type fakeManager struct {
	calls []string
	fail  error
}

func (f *fakeManager) Stop(unit string) error { f.calls = append(f.calls, "stop "+unit); return f.fail }
func (f *fakeManager) Disable(unit string) error {
	f.calls = append(f.calls, "disable "+unit)
	return f.fail
}
func (f *fakeManager) Reload() error { f.calls = append(f.calls, "reload"); return f.fail }
func (f *fakeManager) TryRestart(unit string) error {
	f.calls = append(f.calls, "try-restart "+unit)
	return f.fail
}
func (f *fakeManager) Close() {}

// seams replaces what touches the real system and restores it after the test.
func seams(t *testing.T, mgr *fakeManager, root bool) {
	t.Helper()
	oldConnect, oldRoot, oldUnit, oldExe, oldKey := connectSystemd, isRoot, unitPath, executable, releaseKey
	t.Cleanup(func() {
		connectSystemd, isRoot, unitPath, executable, releaseKey = oldConnect, oldRoot, oldUnit, oldExe, oldKey
	})
	connectSystemd = func() (serviceManager, error) {
		if mgr == nil {
			return nil, errors.New("no system bus")
		}
		return mgr, nil
	}
	isRoot = func() bool { return root }
}

func writeConfig(t *testing.T, hub, extra string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "etc", "agent.yaml")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	os.WriteFile(cfg, []byte("hub_url: "+hub+"\nagent_id: \"9\"\nagent_token: old-token\ninterval: 30s\nallow_insecure_http: true\n"+extra), 0o600)
	return cfg
}

func TestStatus(t *testing.T) {
	self := protocol.SelfResponse{HostID: 4, Name: "web-01", Now: 1000}
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/self" || r.Header.Get("Authorization") != "Bearer old-token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(self)
	}))
	defer srv.Close()
	cfg := writeConfig(t, srv.URL, "")
	check := func(wantCode int, want string) {
		t.Helper()
		var out, errOut bytes.Buffer
		got := run([]string{"status", "--config", cfg}, &out, &errOut)
		if got != wantCode || !strings.Contains(out.String()+errOut.String(), want) {
			t.Errorf("status: code %d, output %q %q; want %d and %q", got, out.String(), errOut.String(), wantCode, want)
		}
	}
	check(1, "Waiting for the first report")
	self.LastSeen = 990
	check(0, "Server: web-01")
	check(0, "Status: Online (last report 10 seconds ago)")
	self.LastSeen = 400
	check(1, "Status: Offline (last report 10 minutes ago)")
	code = http.StatusUnauthorized
	check(1, "does not accept this agent")
	srv.Close()
	check(1, "cannot reach the Hub")
}

func TestEnrollKeepsSettingsAndRestartsTheService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "9", AgentToken: "new-token"})
	}))
	defer srv.Close()
	mgr := &fakeManager{}
	seams(t, mgr, true)
	cfg := writeConfig(t, srv.URL, "services:\n    - nginx.service\nproxmox:\n    token_id: fleetwatch@pve!agent\n    token_secret: kept-secret\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"enroll", "--hub", srv.URL, "--token", "once", "--config", cfg, "--allow-insecure-http"}, &out, &errOut); code != 0 {
		t.Fatalf("enroll: %s", errOut.String())
	}
	b, _ := os.ReadFile(cfg)
	for _, want := range []string{"agent_token: new-token", "interval: 30s", "- nginx.service", "token_secret: kept-secret"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("config is missing %q:\n%s", want, b)
		}
	}
	if strings.Contains(string(b), "old-token") {
		t.Error("the old credential must be gone")
	}
	if len(mgr.calls) != 1 || mgr.calls[0] != "try-restart fleetwatch-agent.service" {
		t.Errorf("service calls = %v", mgr.calls)
	}
}

func TestEnrollReadsOptionsFromTheEnvironment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(protocol.EnrollResponse{AgentID: "9", AgentToken: "permanent"})
	}))
	defer srv.Close()
	seams(t, nil, true)
	t.Setenv("FLEETWATCH_SERVICES", "nginx,docker")
	t.Setenv("FLEETWATCH_PVE_TOKEN_ID", "fleetwatch@pve!agent")
	t.Setenv("FLEETWATCH_PVE_TOKEN_SECRET", "from-env")
	cfg := filepath.Join(t.TempDir(), "agent.yaml")
	var out, errOut bytes.Buffer
	if code := run([]string{"enroll", "--hub", srv.URL, "--token", "once", "--config", cfg, "--allow-insecure-http", "--pve-ca-file", "/etc/fleetwatch/pve-root-ca.pem"}, &out, &errOut); code != 0 {
		t.Fatalf("enroll: %s", errOut.String())
	}
	b, _ := os.ReadFile(cfg)
	for _, want := range []string{"- nginx.service", "- docker.service", "token_secret: from-env", "ca_file: /etc/fleetwatch/pve-root-ca.pem"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("config is missing %q:\n%s", want, b)
		}
	}
}

func TestUninstall(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, "https://hub.example.com", "")
	exe := filepath.Join(dir, "bin", "fleetwatch-agent")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("agent"), 0o755)
	unit := filepath.Join(dir, "fleetwatch-agent.service")
	os.WriteFile(unit, []byte("[Unit]"), 0o644)

	mgr := &fakeManager{}
	seams(t, mgr, false)
	unitPath = unit
	executable = func() (string, error) { return exe, nil }
	var out, errOut bytes.Buffer
	if code := run([]string{"uninstall", "--config", cfg}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "root") {
		t.Fatalf("without root: code %d, %q", code, errOut.String())
	}
	if _, err := os.Stat(exe); err != nil || len(mgr.calls) != 0 {
		t.Fatal("without root nothing may be touched")
	}

	isRoot = func() bool { return true }
	if code := run([]string{"uninstall", "--config", cfg}, &out, &errOut); code != 0 {
		t.Fatalf("uninstall: code %d, %q", code, errOut.String())
	}
	want := "stop fleetwatch-agent.service, disable fleetwatch-agent.service, reload"
	if got := strings.Join(mgr.calls, ", "); got != want {
		t.Errorf("service calls = %q, want %q", got, want)
	}
	for _, gone := range []string{exe, unit, filepath.Dir(cfg)} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s must be removed", gone)
		}
	}
	if _, err := os.Stat(filepath.Dir(exe)); err != nil {
		t.Error("the directory of the program must stay")
	}
	if strings.Contains(out.String(), "pveum") {
		t.Errorf("without a Proxmox token there is nothing to remove: %q", out.String())
	}
}

// The agent starts no processes, so the Proxmox token stays; uninstall says
// how to remove it.
func TestUninstallNamesTheProxmoxToken(t *testing.T) {
	dir := t.TempDir()
	cfg := writeConfig(t, "https://hub.example.com", "proxmox:\n  token_id: fleetwatch@pve!agent-pve1\n  token_secret: s\n")
	exe := filepath.Join(dir, "fleetwatch-agent")
	os.WriteFile(exe, []byte("agent"), 0o755)
	seams(t, &fakeManager{}, false)
	unitPath = filepath.Join(dir, "fleetwatch-agent.service")
	executable = func() (string, error) { return exe, nil }
	isRoot = func() bool { return true }
	var out, errOut bytes.Buffer
	if code := run([]string{"uninstall", "--config", cfg}, &out, &errOut); code != 0 {
		t.Fatalf("uninstall: code %d, %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "pveum user token remove fleetwatch@pve agent-pve1") {
		t.Errorf("output must name the token to remove: %q", out.String())
	}
}

func TestUpgradeCommand(t *testing.T) {
	priv, pub, _ := release.GenerateKey()
	files := map[string][]byte{release.AgentFile("amd64"): []byte("new agent"), release.AgentFile("arm64"): []byte("new agent"), release.VersionFile: []byte("9.0.0\n")}
	sums := release.Sums(files)
	sig, _ := release.Sign(priv, sums)
	files[release.SumsFile], files[release.SigFile] = sums, sig
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[strings.TrimPrefix(r.URL.Path, "/dl/")]
		if !ok || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	cfg := writeConfig(t, srv.URL, "")
	exe := filepath.Join(t.TempDir(), "fleetwatch-agent")
	os.WriteFile(exe, []byte("old agent"), 0o755)
	mgr := &fakeManager{}
	seams(t, mgr, true)
	executable = func() (string, error) { return exe, nil }

	var out, errOut bytes.Buffer
	if code := run([]string{"upgrade", "--config", cfg}, &out, &errOut); code == 0 {
		t.Fatal("a release signed by another key than the built-in one must be refused")
	}
	if b, _ := os.ReadFile(exe); string(b) != "old agent" || len(mgr.calls) != 0 {
		t.Fatalf("a refused upgrade must change nothing: %q %v", b, mgr.calls)
	}

	releaseKey = pub
	if code := run([]string{"upgrade", "--config", cfg}, &out, &errOut); code != 0 {
		t.Fatalf("upgrade: %s", errOut.String())
	}
	if b, _ := os.ReadFile(exe); string(b) != "new agent" {
		t.Errorf("installed file = %q", b)
	}
	if !strings.Contains(out.String(), "9.0.0") || len(mgr.calls) != 1 || mgr.calls[0] != "try-restart fleetwatch-agent.service" {
		t.Errorf("output %q, service calls %v", out.String(), mgr.calls)
	}
}
